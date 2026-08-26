# This file is part of Umbilical.
#
# Umbilical is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, version 2.

import concurrent.futures
import sqlite3
import tempfile
import unittest
from pathlib import Path

from buildbot.umbilical_authority import AuthorityStore
from buildbot.umbilical_authority import AuthorityStoreExistsError
from buildbot.umbilical_authority import AuthorityStoreMalformedError
from buildbot.umbilical_authority import AuthorityStoreMissingError
from buildbot.umbilical_authority import AuthorityStoreVersionError
from buildbot.umbilical_authority import GenerationOverflowError
from buildbot.umbilical_authority import InvalidAuthorityScopeError


class AuthorityStoreTests(unittest.TestCase):
    def setUp(self):
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.path = Path(self._temporary_directory.name) / "authority.sqlite3"

    def _create_manual_store(self, version=1, generation=None, include_table=True):
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(f"PRAGMA user_version = {version}")
            if include_table:
                connection.execute(
                    """
                    CREATE TABLE controller_generations (
                        scope TEXT NOT NULL PRIMARY KEY,
                        generation INTEGER NOT NULL
                    ) WITHOUT ROWID
                    """
                )
                if generation is not None:
                    connection.execute(
                        "INSERT INTO controller_generations(scope, generation) "
                        "VALUES ('controller/default', ?)",
                        (generation,),
                    )
            connection.commit()
        finally:
            connection.close()

    def test_initialize_new_empty_store_succeeds(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertIsNone(store.read_generation("controller/default"))
            self.assertEqual(
                store._connection.execute("PRAGMA journal_mode").fetchone()[0].lower(),
                "wal",
            )
            self.assertEqual(
                store._connection.execute("PRAGMA synchronous").fetchone()[0],
                2,
            )

    def test_initialize_same_store_twice_fails_without_reset(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope"), 1)
        with self.assertRaises(AuthorityStoreExistsError):
            AuthorityStore.initialize_new(self.path)
        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(store.read_generation("scope"), 1)

    def test_open_existing_missing_path_fails(self):
        with self.assertRaises(AuthorityStoreMissingError):
            AuthorityStore.open_existing(self.path)
        self.assertFalse(self.path.exists())

    def test_first_acquisition_returns_one(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope"), 1)

    def test_repeated_acquisition_is_strictly_increasing(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(
                [store.acquire_generation("scope") for _ in range(3)],
                [1, 2, 3],
            )

    def test_close_reopen_preserves_generation(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope"), 1)
            self.assertEqual(store.acquire_generation("scope"), 2)
        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(store.read_generation("scope"), 2)
            self.assertEqual(store.acquire_generation("scope"), 3)

    def test_scopes_have_independent_sequences(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope/A"), 1)
            self.assertEqual(store.acquire_generation("scope/A"), 2)
            self.assertEqual(store.acquire_generation("opaque-B"), 1)
            self.assertEqual(store.read_generation("scope/A"), 2)
            self.assertEqual(store.read_generation("opaque-B"), 1)

    def test_is_current_generation_requires_exact_persisted_generation(self):
        with AuthorityStore.initialize_new(self.path) as store:
            current = store.acquire_generation("scope")
            self.assertTrue(store.is_current_generation("scope", current))
            self.assertFalse(store.is_current_generation("scope", 0))
            self.assertFalse(store.is_current_generation("scope", True))
            self.assertFalse(store.is_current_generation("scope", current + 1))
            self.assertFalse(store.is_current_generation("never-acquired", 1))

    def test_prior_generation_becomes_stale_after_next_acquisition(self):
        with AuthorityStore.initialize_new(self.path) as store:
            old_generation = store.acquire_generation("scope")
            new_generation = store.acquire_generation("scope")
            self.assertEqual(new_generation, old_generation + 1)
            self.assertFalse(store.is_current_generation("scope", old_generation))
            self.assertTrue(store.is_current_generation("scope", new_generation))

    def test_concurrent_independent_connections_acquire_unique_generations(self):
        AuthorityStore.initialize_new(self.path).close()
        acquisition_count = 24

        def acquire_once(_):
            with AuthorityStore.open_existing(self.path) as store:
                return store.acquire_generation("contended-scope")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            generations = list(executor.map(acquire_once, range(acquisition_count)))

        self.assertEqual(
            sorted(generations),
            list(range(1, acquisition_count + 1)),
        )
        self.assertEqual(len(set(generations)), acquisition_count)

    def test_non_database_state_fails_closed(self):
        self.path.write_bytes(b"not a sqlite database")
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_unsupported_schema_version_fails_closed(self):
        self._create_manual_store(version=999)
        with self.assertRaises(AuthorityStoreVersionError):
            AuthorityStore.open_existing(self.path)

    def test_missing_required_table_fails_closed(self):
        self._create_manual_store(version=1, include_table=False)
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_malformed_persisted_generation_fails_closed(self):
        self._create_manual_store(version=1, generation=0)
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_generation_overflow_fails_without_modifying_state(self):
        maximum = (1 << 63) - 1
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope"), 1)

        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                "UPDATE controller_generations SET generation = ? WHERE scope = 'scope'",
                (maximum,),
            )
            connection.commit()
        finally:
            connection.close()

        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(store.read_generation("scope"), maximum)
            with self.assertRaises(GenerationOverflowError):
                store.acquire_generation("scope")
            self.assertEqual(store.read_generation("scope"), maximum)

        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(store.read_generation("scope"), maximum)

    def test_empty_scope_is_rejected(self):
        with AuthorityStore.initialize_new(self.path) as store:
            with self.assertRaises(InvalidAuthorityScopeError):
                store.acquire_generation("")
            with self.assertRaises(InvalidAuthorityScopeError):
                store.read_generation("")


if __name__ == "__main__":
    unittest.main()
