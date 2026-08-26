# This file is part of Umbilical.
#
# Umbilical is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, version 2.

import concurrent.futures
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from buildbot.umbilical_authority import AuthorityStore
from buildbot.umbilical_authority import AuthorityStoreError
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

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_initialize_does_not_follow_existing_broken_symlink(self):
        link = Path(self._temporary_directory.name) / "authority-link.sqlite3"
        target = Path(self._temporary_directory.name) / "missing-target.sqlite3"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(AuthorityStoreExistsError):
            AuthorityStore.initialize_new(link)
        self.assertFalse(target.exists())

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
        AuthorityStore.initialize_new(self.path).close()
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("PRAGMA user_version = 999")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreVersionError):
            AuthorityStore.open_existing(self.path)

    def test_missing_required_table_fails_closed(self):
        AuthorityStore.initialize_new(self.path).close()
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("DROP TABLE controller_generations")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_schema_definition_drift_fails_closed(self):
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("PRAGMA user_version = 1")
            connection.execute(
                """
                CREATE TABLE controller_generations (
                    scope TEXT NOT NULL PRIMARY KEY,
                    generation INTEGER NOT NULL
                ) WITHOUT ROWID
                """
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_malformed_persisted_generation_fails_closed(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("controller/default"), 1)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("PRAGMA ignore_check_constraints = ON")
            connection.execute(
                "UPDATE controller_generations SET generation = 0 "
                "WHERE scope = 'controller/default'"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_unwritable_connection_acquisition_fails_closed(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store._connection.execute("PRAGMA query_only = ON")
            with self.assertRaises(AuthorityStoreError):
                store.acquire_generation("scope")
            store._connection.execute("PRAGMA query_only = OFF")
            self.assertIsNone(store.read_generation("scope"))

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

    def test_open_existing_rejects_persistent_after_update_trigger(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope"), 1)

        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                """
                CREATE TRIGGER rewind_generation
                AFTER UPDATE OF generation ON controller_generations
                BEGIN
                    UPDATE controller_generations
                    SET generation = OLD.generation
                    WHERE scope = NEW.scope;
                END
                """
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_open_existing_rejects_persistent_insert_trigger(self):
        AuthorityStore.initialize_new(self.path).close()

        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                """
                CREATE TRIGGER rewrite_insert_generation
                AFTER INSERT ON controller_generations
                BEGIN
                    UPDATE controller_generations
                    SET generation = NEW.generation + 100
                    WHERE scope = NEW.scope;
                END
                """
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_acquire_revalidates_schema_after_post_open_mutation(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope"), 1)

            connection = sqlite3.connect(self.path)
            try:
                connection.execute(
                    """
                    CREATE TRIGGER rewind_generation
                    AFTER UPDATE OF generation ON controller_generations
                    BEGIN
                        UPDATE controller_generations
                        SET generation = OLD.generation
                        WHERE scope = NEW.scope;
                    END
                    """
                )
                connection.commit()
            finally:
                connection.close()

            with self.assertRaises(AuthorityStoreMalformedError):
                store.acquire_generation("scope")

            connection = sqlite3.connect(self.path)
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT generation FROM controller_generations "
                        "WHERE scope = 'scope'"
                    ).fetchone(),
                    (1,),
                )
                connection.execute("DROP TRIGGER rewind_generation")
                connection.commit()
            finally:
                connection.close()

            # Rollback succeeded, so the same store remains mechanically usable
            # after malformed schema is repaired by an external administrator.
            self.assertEqual(store.acquire_generation("scope"), 2)

    def test_read_revalidates_schema_after_post_open_trigger(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope"), 1)

            connection = sqlite3.connect(self.path)
            try:
                connection.execute(
                    """
                    CREATE TRIGGER unexpected_trigger
                    AFTER UPDATE ON controller_generations
                    BEGIN
                        SELECT 1;
                    END
                    """
                )
                connection.commit()
            finally:
                connection.close()

            with self.assertRaises(AuthorityStoreMalformedError):
                store.read_generation("scope")

    def test_is_current_revalidates_schema_after_post_open_trigger(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope"), 1)

            connection = sqlite3.connect(self.path)
            try:
                connection.execute(
                    """
                    CREATE TRIGGER unexpected_trigger
                    AFTER UPDATE ON controller_generations
                    BEGIN
                        SELECT 1;
                    END
                    """
                )
                connection.commit()
            finally:
                connection.close()

            with self.assertRaises(AuthorityStoreMalformedError):
                store.is_current_generation("scope", 1)

    def test_read_failure_rollback_allows_reuse_after_external_repair(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope"), 1)

            connection = sqlite3.connect(self.path)
            try:
                connection.execute(
                    """
                    CREATE TRIGGER unexpected_trigger
                    AFTER UPDATE ON controller_generations
                    BEGIN
                        SELECT 1;
                    END
                    """
                )
                connection.commit()
            finally:
                connection.close()

            with self.assertRaises(AuthorityStoreMalformedError):
                store.read_generation("scope")
            self.assertFalse(store._poisoned)

            connection = sqlite3.connect(self.path)
            try:
                connection.execute("DROP TRIGGER unexpected_trigger")
                connection.commit()
            finally:
                connection.close()

            self.assertEqual(store.read_generation("scope"), 1)

    def test_read_rollback_failure_permanently_poisons_store(self):
        store = AuthorityStore.initialize_new(self.path)
        self.addCleanup(store.close)
        self.assertEqual(store.acquire_generation("scope"), 1)

        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                """
                CREATE TRIGGER unexpected_trigger
                AFTER UPDATE ON controller_generations
                BEGIN
                    SELECT 1;
                END
                """
            )
            connection.commit()
        finally:
            connection.close()

        original_connection = store._connection
        with mock.patch.object(
            AuthorityStore,
            "_rollback_transaction",
            side_effect=sqlite3.OperationalError("injected rollback failure"),
        ):
            with self.assertRaises(AuthorityStoreError):
                store.read_generation("scope")

        self.assertTrue(store._poisoned)
        self.assertIsNone(store._connection)
        with self.assertRaises(sqlite3.ProgrammingError):
            original_connection.execute("SELECT 1")
        with self.assertRaises(AuthorityStoreError):
            store.read_generation("scope")
        with self.assertRaises(AuthorityStoreError):
            store.is_current_generation("scope", 1)
        with self.assertRaises(AuthorityStoreError):
            store.acquire_generation("scope")

    def test_read_valid_store_without_scope_returns_none(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertIsNone(store.read_generation("never-acquired"))

    def test_malformed_store_without_scope_does_not_become_none(self):
        with AuthorityStore.initialize_new(self.path) as store:
            connection = sqlite3.connect(self.path)
            try:
                connection.execute(
                    """
                    CREATE TRIGGER unexpected_trigger
                    AFTER UPDATE ON controller_generations
                    BEGIN
                        SELECT 1;
                    END
                    """
                )
                connection.commit()
            finally:
                connection.close()

            with self.assertRaises(AuthorityStoreMalformedError):
                store.read_generation("never-acquired")

    def test_read_commit_failure_returns_no_observation_and_cleans_up(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope"), 1)

            def authorizer(action, argument1, _argument2, _database, _trigger):
                if action == sqlite3.SQLITE_TRANSACTION and argument1 == "COMMIT":
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            store._connection.set_authorizer(authorizer)
            try:
                with self.assertRaises(AuthorityStoreError):
                    store.read_generation("scope")
            finally:
                store._connection.set_authorizer(None)

            self.assertFalse(store._connection.in_transaction)
            self.assertFalse(store._poisoned)
            self.assertEqual(store.read_generation("scope"), 1)

    def test_read_validation_and_generation_lookup_share_snapshot(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope"), 1)

            validation_complete = threading.Event()
            writer_complete = threading.Event()
            original_validate_store = AuthorityStore._validate_store
            writer_errors = []

            def validate_then_pause(connection):
                original_validate_store(connection)
                validation_complete.set()
                if not writer_complete.wait(timeout=5):
                    self.fail("concurrent writer did not complete")

            def writer():
                if not validation_complete.wait(timeout=5):
                    writer_errors.append(RuntimeError("validation did not complete"))
                    writer_complete.set()
                    return
                connection = sqlite3.connect(self.path, timeout=5.0)
                try:
                    connection.execute(
                        "UPDATE controller_generations SET generation = 2 "
                        "WHERE scope = 'scope'"
                    )
                    connection.commit()
                except Exception as exc:
                    writer_errors.append(exc)
                finally:
                    connection.close()
                    writer_complete.set()

            thread = threading.Thread(target=writer)
            thread.start()
            try:
                with mock.patch.object(
                    AuthorityStore,
                    "_validate_store",
                    side_effect=validate_then_pause,
                ):
                    observed = store.read_generation("scope")
            finally:
                thread.join(timeout=5)

            self.assertFalse(thread.is_alive())
            self.assertEqual(writer_errors, [])
            # The writer committed after validation established the read
            # snapshot, so this observation may legitimately remain at 1.
            self.assertEqual(observed, 1)
            # A subsequent validated observation sees the newly committed state.
            self.assertEqual(store.read_generation("scope"), 2)

    def test_open_existing_rejects_unexpected_persisted_schema_objects(self):
        cases = {
            "table": "CREATE TABLE unexpected_table(value INTEGER)",
            "view": (
                "CREATE VIEW unexpected_view AS "
                "SELECT scope, generation FROM controller_generations"
            ),
            "index": (
                "CREATE INDEX unexpected_index "
                "ON controller_generations(generation)"
            ),
            "sqlite-lookalike-trigger": (
                "CREATE TRIGGER sqliteXrewind "
                "AFTER UPDATE OF generation ON controller_generations "
                "BEGIN "
                "UPDATE controller_generations "
                "SET generation = OLD.generation "
                "WHERE scope = NEW.scope; "
                "END"
            ),
        }

        for kind, ddl in cases.items():
            with self.subTest(kind=kind):
                path = (
                    Path(self._temporary_directory.name)
                    / f"unexpected-{kind}.sqlite3"
                )
                AuthorityStore.initialize_new(path).close()
                connection = sqlite3.connect(path)
                try:
                    connection.execute(ddl)
                    connection.commit()
                finally:
                    connection.close()
                with self.assertRaises(AuthorityStoreMalformedError):
                    AuthorityStore.open_existing(path)

    def test_rollback_failure_permanently_poisons_store(self):
        store = AuthorityStore.initialize_new(self.path)
        self.addCleanup(store.close)
        self.assertEqual(store.acquire_generation("scope"), 1)

        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                """
                CREATE TRIGGER unexpected_trigger
                AFTER UPDATE ON controller_generations
                BEGIN
                    SELECT 1;
                END
                """
            )
            connection.commit()
        finally:
            connection.close()

        original_connection = store._connection
        with mock.patch.object(
            AuthorityStore,
            "_rollback_transaction",
            side_effect=sqlite3.OperationalError("injected rollback failure"),
        ):
            with self.assertRaises(AuthorityStoreError):
                store.acquire_generation("scope")

        self.assertTrue(store._poisoned)
        self.assertIsNone(store._connection)
        with self.assertRaises(sqlite3.ProgrammingError):
            original_connection.execute("SELECT 1")

        with self.assertRaises(AuthorityStoreError):
            store.read_generation("scope")
        with self.assertRaises(AuthorityStoreError):
            store.is_current_generation("scope", 1)
        with self.assertRaises(AuthorityStoreError):
            store.acquire_generation("scope")

        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT generation FROM controller_generations WHERE scope = 'scope'"
                ).fetchone(),
                (1,),
            )
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
