# This file is part of Umbilical.
#
# Umbilical is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, version 2.

import concurrent.futures
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from buildbot.umbilical_authority import AuthorityStore
from buildbot.umbilical_authority import AuthorityStoreError
from buildbot.umbilical_authority import AuthorityStoreExistsError
from buildbot.umbilical_authority import AuthorityStoreMalformedError
from buildbot.umbilical_authority import AuthorityStoreMigrationRequiredError
from buildbot.umbilical_authority import AuthorityStoreMissingError
from buildbot.umbilical_authority import AuthorityStoreVersionError
from buildbot.umbilical_authority import CommandSpecBindingResult
from buildbot.umbilical_authority import CommandSpecConflictError
from buildbot.umbilical_authority import ExecutionKeyNotRegisteredError
from buildbot.umbilical_authority import ExecutionKeyRegistration
from buildbot.umbilical_authority import GenerationOverflowError
from buildbot.umbilical_authority import InvalidAuthorityScopeError
from buildbot.umbilical_authority import InvalidCommandSpecHashError
from buildbot.umbilical_authority import InvalidExecutionKeyError


_V1_GENERATIONS_SQL = """
CREATE TABLE controller_generations (
    scope TEXT NOT NULL PRIMARY KEY
        CHECK(typeof(scope) = 'text' AND scope <> ''),
    generation INTEGER NOT NULL
        CHECK(typeof(generation) = 'integer' AND generation > 0)
) WITHOUT ROWID
"""
_V2_EXECUTION_KEYS_SQL = """
CREATE TABLE execution_keys (
    execution_key TEXT NOT NULL PRIMARY KEY
        CHECK(typeof(execution_key) = 'text' AND execution_key <> '')
) WITHOUT ROWID
"""
_V3_BINDINGS_SQL = """
CREATE TABLE execution_command_bindings (
    execution_key TEXT NOT NULL PRIMARY KEY
        CHECK(typeof(execution_key) = 'text' AND execution_key <> ''),
    command_spec_hash TEXT NOT NULL
        CHECK(typeof(command_spec_hash) = 'text' AND command_spec_hash <> '')
) WITHOUT ROWID
"""


class AuthorityStoreTests(unittest.TestCase):
    def setUp(self):
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.path = Path(self._temporary_directory.name) / "authority.sqlite3"

    def _create_v1_store(self, path=None, rows=()):
        path = self.path if path is None else path
        connection = sqlite3.connect(path, isolation_level=None)
        try:
            self.assertEqual(
                connection.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower(),
                "wal",
            )
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(_V1_GENERATIONS_SQL)
            for scope, generation in rows:
                connection.execute(
                    "INSERT INTO controller_generations(scope, generation) VALUES (?, ?)",
                    (scope, generation),
                )
            connection.execute("PRAGMA user_version = 1")
            connection.execute("COMMIT")
        finally:
            connection.close()
        return path

    def _create_v2_store(self, path=None, generation_rows=(), execution_keys=()):
        path = self.path if path is None else path
        connection = sqlite3.connect(path, isolation_level=None)
        try:
            self.assertEqual(
                connection.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower(),
                "wal",
            )
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(_V1_GENERATIONS_SQL)
            connection.execute(_V2_EXECUTION_KEYS_SQL)
            for scope, generation in generation_rows:
                connection.execute(
                    "INSERT INTO controller_generations(scope, generation) VALUES (?, ?)",
                    (scope, generation),
                )
            for execution_key in execution_keys:
                connection.execute(
                    "INSERT INTO execution_keys(execution_key) VALUES (?)",
                    (execution_key,),
                )
            connection.execute("PRAGMA user_version = 2")
            connection.execute("COMMIT")
        finally:
            connection.close()
        return path

    def _replace_table_definition_literal(
        self, table_name, old_literal, new_literal, path=None
    ):
        path = self.path if path is None else path
        connection = sqlite3.connect(path)
        try:
            row = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
                (table_name,),
            ).fetchone()
            self.assertIsNotNone(row)
            table_sql = row[0]
            self.assertIsInstance(table_sql, str)
            self.assertEqual(table_sql.count(old_literal), 1)
            connection.execute(f"DROP TABLE {table_name}")
            connection.execute(table_sql.replace(old_literal, new_literal, 1))
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
                store._connection.execute("PRAGMA synchronous").fetchone()[0], 2
            )

    def test_initialize_new_creates_exact_v3_schema_directly(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(
                store._connection.execute("PRAGMA user_version").fetchone(), (3,)
            )
            objects = store._connection.execute(
                "SELECT type, name FROM sqlite_schema "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            ).fetchall()
            self.assertEqual(
                objects,
                [
                    ("table", "controller_generations"),
                    ("table", "execution_command_bindings"),
                    ("table", "execution_keys"),
                ],
            )
            self.assertEqual(
                store._connection.execute(
                    "SELECT execution_key, command_spec_hash "
                    "FROM execution_command_bindings"
                ).fetchall(),
                [],
            )

    def test_canonical_persisted_schema_literals_are_exact(self):
        with AuthorityStore.initialize_new(self.path) as store:
            rows = dict(
                store._connection.execute(
                    "SELECT name, sql FROM sqlite_schema WHERE type = 'table'"
                ).fetchall()
            )
            self.assertEqual(
                rows["controller_generations"], _V1_GENERATIONS_SQL.lstrip("\n")
            )
            self.assertEqual(
                rows["execution_keys"], _V2_EXECUTION_KEYS_SQL.lstrip("\n")
            )
            self.assertEqual(
                rows["execution_command_bindings"], _V3_BINDINGS_SQL.lstrip("\n")
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

    def test_valid_v1_requires_explicit_migration(self):
        self._create_v1_store(rows=(("scope", 7),))
        with self.assertRaises(AuthorityStoreMigrationRequiredError):
            AuthorityStore.open_existing(self.path)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (1,))
            self.assertEqual(
                connection.execute(
                    "SELECT scope, generation FROM controller_generations"
                ).fetchall(),
                [("scope", 7)],
            )
        finally:
            connection.close()

    def test_valid_v2_requires_explicit_migration_without_mutation(self):
        self._create_v2_store(
            generation_rows=(("scope", 7),), execution_keys=("K",)
        )
        with self.assertRaises(AuthorityStoreMigrationRequiredError):
            AuthorityStore.open_existing(self.path)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (2,))
            self.assertEqual(
                connection.execute(
                    "SELECT name FROM sqlite_schema "
                    "WHERE name NOT LIKE 'sqlite_%' ORDER BY name"
                ).fetchall(),
                [("controller_generations",), ("execution_keys",)],
            )
            self.assertEqual(
                connection.execute("SELECT execution_key FROM execution_keys").fetchall(),
                [("K",)],
            )
        finally:
            connection.close()

    def test_migrate_v1_to_v2_still_produces_exact_v2(self):
        self._create_v1_store(rows=(("scope", 5),))
        AuthorityStore.migrate_v1_to_v2(self.path)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (2,))
            self.assertEqual(
                connection.execute(
                    "SELECT type, name FROM sqlite_schema "
                    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
                ).fetchall(),
                [
                    ("table", "controller_generations"),
                    ("table", "execution_keys"),
                ],
            )
            self.assertEqual(
                connection.execute(
                    "SELECT scope, generation FROM controller_generations"
                ).fetchall(),
                [("scope", 5)],
            )
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreMigrationRequiredError):
            AuthorityStore.open_existing(self.path)

    def test_explicit_v1_to_v2_to_v3_chain_succeeds(self):
        self._create_v1_store(rows=(("scope", 5),))
        AuthorityStore.migrate_v1_to_v2(self.path)
        AuthorityStore.migrate_v2_to_v3(self.path)
        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(store.read_generation("scope"), 5)
            self.assertFalse(store.execution_key_exists("missing"))

    def test_v2_to_v3_preserves_generation_rows_exactly(self):
        rows = [("scope/A", 3), ("scope/B", 9)]
        self._create_v2_store(generation_rows=rows, execution_keys=("K",))
        AuthorityStore.migrate_v2_to_v3(self.path)
        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(
                store._connection.execute(
                    "SELECT scope, generation FROM controller_generations ORDER BY scope"
                ).fetchall(),
                rows,
            )

    def test_v2_to_v3_preserves_execution_keys_exactly(self):
        keys = [" K ", "K", "k", "é", "é"]
        self._create_v2_store(execution_keys=keys)
        before = sqlite3.connect(self.path)
        try:
            before_rows = before.execute(
                "SELECT execution_key FROM execution_keys ORDER BY execution_key"
            ).fetchall()
        finally:
            before.close()
        AuthorityStore.migrate_v2_to_v3(self.path)
        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(
                store._connection.execute(
                    "SELECT execution_key FROM execution_keys ORDER BY execution_key"
                ).fetchall(),
                before_rows,
            )

    def test_v2_to_v3_invents_zero_bindings(self):
        self._create_v2_store(execution_keys=("K1", "K2"))
        AuthorityStore.migrate_v2_to_v3(self.path)
        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(
                store._connection.execute(
                    "SELECT execution_key, command_spec_hash "
                    "FROM execution_command_bindings"
                ).fetchall(),
                [],
            )

    def test_malformed_v2_migration_fails_closed(self):
        self._create_v2_store(execution_keys=("K",))
        self._replace_table_definition_literal("execution_keys", "'text'", "'TEXT'")
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.migrate_v2_to_v3(self.path)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (2,))
            self.assertEqual(
                connection.execute(
                    "SELECT name FROM sqlite_schema "
                    "WHERE name = 'execution_command_bindings'"
                ).fetchall(),
                [],
            )
        finally:
            connection.close()

    def test_unexpected_v2_persisted_object_blocks_migration(self):
        self._create_v2_store(generation_rows=(("scope", 2),))
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("CREATE TABLE unexpected(value INTEGER)")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.migrate_v2_to_v3(self.path)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (2,))
            self.assertEqual(
                connection.execute(
                    "SELECT generation FROM controller_generations WHERE scope='scope'"
                ).fetchone(),
                (2,),
            )
        finally:
            connection.close()

    def test_v2_to_v3_called_on_v1_v3_or_unsupported_version_fails(self):
        paths = []
        v1 = Path(self._temporary_directory.name) / "v1.sqlite3"
        self._create_v1_store(v1)
        paths.append((v1, 1))
        v3 = Path(self._temporary_directory.name) / "v3.sqlite3"
        AuthorityStore.initialize_new(v3).close()
        paths.append((v3, 3))
        unsupported = Path(self._temporary_directory.name) / "unsupported.sqlite3"
        self._create_v2_store(unsupported)
        connection = sqlite3.connect(unsupported)
        try:
            connection.execute("PRAGMA user_version = 999")
            connection.commit()
        finally:
            connection.close()
        paths.append((unsupported, 999))
        for path, version in paths:
            with self.subTest(version=version):
                with self.assertRaises(AuthorityStoreVersionError):
                    AuthorityStore.migrate_v2_to_v3(path)
                connection = sqlite3.connect(path)
                try:
                    self.assertEqual(
                        connection.execute("PRAGMA user_version").fetchone(),
                        (version,),
                    )
                finally:
                    connection.close()

    def test_v1_to_v2_called_on_v2_fails_and_v2_remains_exact(self):
        self._create_v2_store(execution_keys=("K",))
        with self.assertRaises(AuthorityStoreVersionError):
            AuthorityStore.migrate_v1_to_v2(self.path)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (2,))
            self.assertEqual(
                connection.execute(
                    "SELECT name FROM sqlite_schema "
                    "WHERE name NOT LIKE 'sqlite_%' ORDER BY name"
                ).fetchall(),
                [("controller_generations",), ("execution_keys",)],
            )
        finally:
            connection.close()

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

    def test_concurrent_generation_acquisition_is_unique(self):
        AuthorityStore.initialize_new(self.path).close()
        acquisition_count = 24

        def acquire_once(_):
            with AuthorityStore.open_existing(self.path) as store:
                return store.acquire_generation("contended-scope")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            generations = list(executor.map(acquire_once, range(acquisition_count)))

        self.assertEqual(sorted(generations), list(range(1, acquisition_count + 1)))

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

    def test_empty_scope_is_rejected(self):
        with AuthorityStore.initialize_new(self.path) as store:
            with self.assertRaises(InvalidAuthorityScopeError):
                store.acquire_generation("")
            with self.assertRaises(InvalidAuthorityScopeError):
                store.read_generation("")

    def test_first_execution_key_registration_is_new_and_durable(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(
                store.register_execution_key("opaque/key"),
                ExecutionKeyRegistration.NEW,
            )
            self.assertTrue(store.execution_key_exists("opaque/key"))
        with AuthorityStore.open_existing(self.path) as store:
            self.assertTrue(store.execution_key_exists("opaque/key"))

    def test_duplicate_execution_key_registration_is_duplicate_and_single_row(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(
                store.register_execution_key("K"), ExecutionKeyRegistration.NEW
            )
            self.assertEqual(
                store.register_execution_key("K"), ExecutionKeyRegistration.DUPLICATE
            )
            self.assertEqual(
                store._connection.execute(
                    "SELECT count(*) FROM execution_keys WHERE execution_key = 'K'"
                ).fetchone(),
                (1,),
            )

    def test_concurrent_execution_key_registration_has_one_new(self):
        AuthorityStore.initialize_new(self.path).close()
        caller_count = 24

        def register_once(_):
            with AuthorityStore.open_existing(self.path) as store:
                return store.register_execution_key("contended-key")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(register_once, range(caller_count)))

        self.assertEqual(results.count(ExecutionKeyRegistration.NEW), 1)
        self.assertEqual(
            results.count(ExecutionKeyRegistration.DUPLICATE), caller_count - 1
        )

    def test_invalid_execution_key_arguments_are_rejected(self):
        class StringSubclass(str):
            pass

        invalid = ["", None, 0, True, b"K", StringSubclass("K")]
        with AuthorityStore.initialize_new(self.path) as store:
            for key in invalid:
                with self.subTest(key=repr(key)):
                    with self.assertRaises(InvalidExecutionKeyError):
                        store.register_execution_key(key)
                    with self.assertRaises(InvalidExecutionKeyError):
                        store.execution_key_exists(key)

    def test_execution_key_commit_failure_returns_no_registration_result(self):
        with AuthorityStore.initialize_new(self.path) as store:
            def authorizer(action, argument1, _argument2, _database, _trigger):
                if action == sqlite3.SQLITE_TRANSACTION and argument1 == "COMMIT":
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            store._connection.set_authorizer(authorizer)
            try:
                with self.assertRaises(AuthorityStoreError):
                    store.register_execution_key("K")
            finally:
                store._connection.set_authorizer(None)
            self.assertFalse(store.execution_key_exists("K"))

    def test_registered_key_can_be_bound(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K")
            self.assertEqual(
                store.bind_command_spec_hash("K", "H"),
                CommandSpecBindingResult.BOUND,
            )
            self.assertEqual(store.read_command_spec_hash("K"), "H")

    def test_same_key_same_hash_is_already_bound(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K")
            self.assertEqual(
                store.bind_command_spec_hash("K", "H"),
                CommandSpecBindingResult.BOUND,
            )
            self.assertEqual(
                store.bind_command_spec_hash("K", "H"),
                CommandSpecBindingResult.ALREADY_BOUND,
            )
            self.assertEqual(
                store._connection.execute(
                    "SELECT count(*) FROM execution_command_bindings "
                    "WHERE execution_key='K'"
                ).fetchone(),
                (1,),
            )

    def test_close_reopen_same_binding_is_already_bound(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K")
            self.assertEqual(
                store.bind_command_spec_hash("K", "H"),
                CommandSpecBindingResult.BOUND,
            )
        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(store.read_command_spec_hash("K"), "H")
            self.assertEqual(
                store.bind_command_spec_hash("K", "H"),
                CommandSpecBindingResult.ALREADY_BOUND,
            )

    def test_different_hash_conflicts_and_original_remains(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K")
            store.bind_command_spec_hash("K", "H1")
            with self.assertRaises(CommandSpecConflictError):
                store.bind_command_spec_hash("K", "H2")
            self.assertEqual(store.read_command_spec_hash("K"), "H1")
            self.assertEqual(
                store._connection.execute(
                    "SELECT command_spec_hash FROM execution_command_bindings "
                    "WHERE execution_key='K'"
                ).fetchone(),
                ("H1",),
            )

    def test_unregistered_key_cannot_bind_and_creates_no_rows(self):
        with AuthorityStore.initialize_new(self.path) as store:
            with self.assertRaises(ExecutionKeyNotRegisteredError):
                store.bind_command_spec_hash("missing", "H")
            self.assertFalse(store.execution_key_exists("missing"))
            self.assertEqual(
                store._connection.execute(
                    "SELECT count(*) FROM execution_command_bindings"
                ).fetchone(),
                (0,),
            )

    def test_unregistered_key_cannot_be_read(self):
        with AuthorityStore.initialize_new(self.path) as store:
            with self.assertRaises(ExecutionKeyNotRegisteredError):
                store.read_command_spec_hash("missing")

    def test_registered_unbound_key_reads_none(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K")
            self.assertIsNone(store.read_command_spec_hash("K"))

    def test_independent_keys_bind_independently(self):
        with AuthorityStore.initialize_new(self.path) as store:
            for key in ("K1", "K2"):
                store.register_execution_key(key)
            self.assertEqual(
                store.bind_command_spec_hash("K1", "H1"),
                CommandSpecBindingResult.BOUND,
            )
            self.assertEqual(
                store.bind_command_spec_hash("K2", "H2"),
                CommandSpecBindingResult.BOUND,
            )
            self.assertEqual(store.read_command_spec_hash("K1"), "H1")
            self.assertEqual(store.read_command_spec_hash("K2"), "H2")

    def test_concurrent_same_key_same_hash_has_one_bound(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K")
        caller_count = 16

        def bind_once(_):
            with AuthorityStore.open_existing(self.path) as store:
                return store.bind_command_spec_hash("K", "H")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(bind_once, range(caller_count)))

        self.assertEqual(results.count(CommandSpecBindingResult.BOUND), 1)
        self.assertEqual(
            results.count(CommandSpecBindingResult.ALREADY_BOUND), caller_count - 1
        )
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT execution_key, command_spec_hash "
                    "FROM execution_command_bindings"
                ).fetchall(),
                [("K", "H")],
            )
        finally:
            connection.close()

    def test_concurrent_competing_hashes_have_one_winner_and_one_conflict(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K")

        def bind(hash_value):
            try:
                with AuthorityStore.open_existing(self.path) as store:
                    return store.bind_command_spec_hash("K", hash_value)
            except CommandSpecConflictError:
                return "conflict"

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(bind, ("H1", "H2")))

        self.assertEqual(results.count(CommandSpecBindingResult.BOUND), 1)
        self.assertEqual(results.count("conflict"), 1)
        connection = sqlite3.connect(self.path)
        try:
            durable = connection.execute(
                "SELECT command_spec_hash FROM execution_command_bindings "
                "WHERE execution_key='K'"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertIn(durable, ("H1", "H2"))

    def test_command_spec_hash_exact_value_semantics(self):
        values = ["H", "h", " H ", " ", "é", "é"]
        with AuthorityStore.initialize_new(self.path) as store:
            for index, value in enumerate(values):
                key = f"K{index}"
                store.register_execution_key(key)
                self.assertEqual(
                    store.bind_command_spec_hash(key, value),
                    CommandSpecBindingResult.BOUND,
                )
                self.assertEqual(store.read_command_spec_hash(key), value)
            self.assertEqual(
                store._connection.execute(
                    "SELECT command_spec_hash FROM execution_command_bindings "
                    "ORDER BY execution_key"
                ).fetchall(),
                [(value,) for value in values],
            )

    def test_invalid_command_spec_hash_is_rejected(self):
        class StringSubclass(str):
            pass

        invalid = ["", None, 0, True, b"H", StringSubclass("H"), chr(0xD800)]
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K")
            for value in invalid:
                with self.subTest(value=repr(value)):
                    with self.assertRaises(InvalidCommandSpecHashError):
                        store.bind_command_spec_hash("K", value)
            self.assertIsNone(store.read_command_spec_hash("K"))

    def test_malformed_persisted_hash_fails_full_validation(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K")
            store.bind_command_spec_hash("K", "H")
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("PRAGMA ignore_check_constraints = ON")
            connection.execute(
                "UPDATE execution_command_bindings SET command_spec_hash='' "
                "WHERE execution_key='K'"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_orphan_binding_fails_full_validation(self):
        AuthorityStore.initialize_new(self.path).close()
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                "INSERT INTO execution_command_bindings"
                "(execution_key, command_spec_hash) VALUES ('orphan', 'H')"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_malformed_binding_blocks_generation_observation(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope"), 1)
            store.register_execution_key("K")
            store.bind_command_spec_hash("K", "H")
            connection = sqlite3.connect(self.path)
            try:
                connection.execute("PRAGMA ignore_check_constraints = ON")
                connection.execute(
                    "UPDATE execution_command_bindings SET command_spec_hash='' "
                    "WHERE execution_key='K'"
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(AuthorityStoreMalformedError):
                store.read_generation("scope")
            with self.assertRaises(AuthorityStoreMalformedError):
                store.is_current_generation("scope", 1)

    def test_malformed_binding_blocks_execution_key_observation_and_registration(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K")
            store.bind_command_spec_hash("K", "H")
            connection = sqlite3.connect(self.path)
            try:
                connection.execute("PRAGMA ignore_check_constraints = ON")
                connection.execute(
                    "UPDATE execution_command_bindings SET command_spec_hash='' "
                    "WHERE execution_key='K'"
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(AuthorityStoreMalformedError):
                store.execution_key_exists("K")
            with self.assertRaises(AuthorityStoreMalformedError):
                store.register_execution_key("K2")

    def test_malformed_binding_blocks_command_binding_observation_and_mutation(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K")
            store.bind_command_spec_hash("K", "H")
            connection = sqlite3.connect(self.path)
            try:
                connection.execute("PRAGMA ignore_check_constraints = ON")
                connection.execute(
                    "UPDATE execution_command_bindings SET command_spec_hash='' "
                    "WHERE execution_key='K'"
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(AuthorityStoreMalformedError):
                store.read_command_spec_hash("K")
            with self.assertRaises(AuthorityStoreMalformedError):
                store.bind_command_spec_hash("K", "H")

    def test_binding_commit_failure_returns_no_success_result(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K")

            def authorizer(action, argument1, _argument2, _database, _trigger):
                if action == sqlite3.SQLITE_TRANSACTION and argument1 == "COMMIT":
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            store._connection.set_authorizer(authorizer)
            try:
                with self.assertRaises(AuthorityStoreError):
                    store.bind_command_spec_hash("K", "H")
            finally:
                store._connection.set_authorizer(None)

            self.assertFalse(store._connection.in_transaction)
            self.assertIsNone(store.read_command_spec_hash("K"))

    def test_binding_rollback_failure_permanently_poisons_store(self):
        store = AuthorityStore.initialize_new(self.path)
        self.addCleanup(store.close)
        store.register_execution_key("K")
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("CREATE TABLE unexpected(value INTEGER)")
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
                store.bind_command_spec_hash("K", "H")

        self.assertTrue(store._poisoned)
        self.assertIsNone(store._connection)
        with self.assertRaises(sqlite3.ProgrammingError):
            original_connection.execute("SELECT 1")
        for operation in (
            lambda: store.bind_command_spec_hash("K", "H"),
            lambda: store.read_command_spec_hash("K"),
            lambda: store.execution_key_exists("K"),
            lambda: store.read_generation("scope"),
        ):
            with self.assertRaises(AuthorityStoreError):
                operation()

    def test_read_command_spec_hash_commit_failure_returns_no_observation(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K")
            store.bind_command_spec_hash("K", "H")

            def authorizer(action, argument1, _argument2, _database, _trigger):
                if action == sqlite3.SQLITE_TRANSACTION and argument1 == "COMMIT":
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            store._connection.set_authorizer(authorizer)
            try:
                with self.assertRaises(AuthorityStoreError):
                    store.read_command_spec_hash("K")
            finally:
                store._connection.set_authorizer(None)
            self.assertFalse(store._connection.in_transaction)
            self.assertEqual(store.read_command_spec_hash("K"), "H")

    def test_binding_schema_literal_case_drift_fails_closed(self):
        AuthorityStore.initialize_new(self.path).close()
        self._replace_table_definition_literal(
            "execution_command_bindings",
            "'text' AND command_spec_hash",
            "'TEXT' AND command_spec_hash",
        )
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_unexpected_persisted_schema_object_fails_closed(self):
        AuthorityStore.initialize_new(self.path).close()
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("CREATE VIEW unexpected AS SELECT execution_key FROM execution_keys")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

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


if __name__ == "__main__":
    unittest.main()
