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
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest import mock

import buildbot.umbilical_authority as authority
from buildbot.umbilical_authority import AuthorityStore
from buildbot.umbilical_authority import AuthorityStoreError
from buildbot.umbilical_authority import AuthorityStoreExistsError
from buildbot.umbilical_authority import AuthorityStoreMalformedError
from buildbot.umbilical_authority import AuthorityStoreMigrationRequiredError
from buildbot.umbilical_authority import AuthorityStoreMissingError
from buildbot.umbilical_authority import AuthorityStoreVersionError
from buildbot.umbilical_authority import CommandSpecBindingResult
from buildbot.umbilical_authority import CommandSpecConflictError
from buildbot.umbilical_authority import ControllerGenerationNotCurrentError
from buildbot.umbilical_authority import ExecutionAdmission
from buildbot.umbilical_authority import ExecutionAdmissionConflictError
from buildbot.umbilical_authority import ExecutionAdmissionResult
from buildbot.umbilical_authority import ExecutionKeyNotCommandBoundError
from buildbot.umbilical_authority import ExecutionKeyNotRegisteredError
from buildbot.umbilical_authority import ExecutionKeyRegistration
from buildbot.umbilical_authority import GenerationOverflowError
from buildbot.umbilical_authority import InvalidAuthorityScopeError
from buildbot.umbilical_authority import InvalidCommandSpecHashError
from buildbot.umbilical_authority import InvalidControllerGenerationError
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
_V4_ADMISSIONS_SQL = """
CREATE TABLE execution_admissions (
    execution_key TEXT NOT NULL PRIMARY KEY
        CHECK(typeof(execution_key) = 'text' AND execution_key <> ''),
    authority_scope TEXT NOT NULL
        CHECK(typeof(authority_scope) = 'text' AND authority_scope <> ''),
    controller_generation INTEGER NOT NULL
        CHECK(
            typeof(controller_generation) = 'integer'
            AND controller_generation > 0
        )
) WITHOUT ROWID
"""


class AuthorityStoreTests(unittest.TestCase):
    def setUp(self):
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.path = Path(self._temporary_directory.name) / "authority.sqlite3"

    def _new_path(self, name):
        return Path(self._temporary_directory.name) / name

    @staticmethod
    def _read_rows(path, query):
        connection = sqlite3.connect(path)
        try:
            return connection.execute(query).fetchall()
        finally:
            connection.close()

    def _create_v1_store(self, path=None, rows=()):
        path = self.path if path is None else path
        connection = sqlite3.connect(path, isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
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
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(_V1_GENERATIONS_SQL)
            connection.execute(_V2_EXECUTION_KEYS_SQL)
            for row in generation_rows:
                connection.execute(
                    "INSERT INTO controller_generations(scope, generation) VALUES (?, ?)",
                    row,
                )
            for key in execution_keys:
                connection.execute("INSERT INTO execution_keys VALUES (?)", (key,))
            connection.execute("PRAGMA user_version = 2")
            connection.execute("COMMIT")
        finally:
            connection.close()
        return path

    def _create_v3_store(
        self,
        path=None,
        generation_rows=(),
        execution_keys=(),
        bindings=(),
    ):
        path = self._create_v2_store(path, generation_rows, execution_keys)
        AuthorityStore.migrate_v2_to_v3(path)
        connection = sqlite3.connect(path)
        try:
            for key, command_hash in bindings:
                connection.execute(
                    "INSERT INTO execution_command_bindings VALUES (?, ?)",
                    (key, command_hash),
                )
            connection.commit()
        finally:
            connection.close()
        return path

    def _prepare_bound(self, *, key="K", scope="S", command_hash="H", path=None):
        path = self.path if path is None else path
        store = AuthorityStore.initialize_new(path)
        generation = store.acquire_generation(scope)
        store.register_execution_key(key)
        store.bind_command_spec_hash(key, command_hash)
        return store, generation

    def _replace_table_definition_literal(self, table, old, new, path=None):
        path = self.path if path is None else path
        connection = sqlite3.connect(path)
        try:
            sql = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?", (table,)
            ).fetchone()[0]
            self.assertEqual(sql.count(old), 1)
            connection.execute(f"DROP TABLE {table}")
            connection.execute(sql.replace(old, new, 1))
            connection.commit()
        finally:
            connection.close()

    def _deny_commit(self, store):
        def authorizer(action, argument1, _argument2, _database, _trigger):
            if action == sqlite3.SQLITE_TRANSACTION and argument1 == "COMMIT":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        store._connection.set_authorizer(authorizer)

    # U1A/U1B/U1D regression preservation, mechanically adapted to current v5.
    def test_initialize_new_empty_store_succeeds(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertIsNone(store.read_generation("controller/default"))
            self.assertEqual(store._connection.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
            self.assertEqual(store._connection.execute("PRAGMA synchronous").fetchone(), (2,))

    def test_initialize_new_rejects_non_windows_without_creating_a_store(self):
        with mock.patch.object(authority.os, "name", "posix"):
            with self.assertRaisesRegex(AuthorityStoreError, "supported only on Windows"):
                AuthorityStore.initialize_new(self.path)
        self.assertFalse(self.path.exists())

    def test_initialize_new_creates_exact_v5_schema_directly(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store._connection.execute("PRAGMA user_version").fetchone(), (5,))
            self.assertEqual(
                store._connection.execute(
                    "SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
                ).fetchall(),
                [("table", "controller_generations"), ("table", "execution_admissions"), ("table", "execution_command_bindings"), ("table", "execution_keys"), ("table", "execution_launches")],
            )
            self.assertEqual(store._connection.execute("SELECT * FROM execution_admissions").fetchall(), [])
            self.assertEqual(store._connection.execute("SELECT * FROM execution_launches").fetchall(), [])

    def test_canonical_persisted_schema_literals_are_exact(self):
        with AuthorityStore.initialize_new(self.path) as store:
            rows = dict(store._connection.execute("SELECT name, sql FROM sqlite_schema WHERE type='table'").fetchall())
            self.assertEqual(rows["controller_generations"], _V1_GENERATIONS_SQL.lstrip("\n"))
            self.assertEqual(rows["execution_keys"], _V2_EXECUTION_KEYS_SQL.lstrip("\n"))
            self.assertEqual(rows["execution_command_bindings"], _V3_BINDINGS_SQL.lstrip("\n"))
            self.assertEqual(rows["execution_admissions"], _V4_ADMISSIONS_SQL.lstrip("\n"))
            self.assertEqual(rows["execution_launches"], authority._CREATE_EXECUTION_LAUNCHES_SQL.lstrip("\n"))

    def test_initialize_same_store_twice_fails_without_reset(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope"), 1)
        with self.assertRaises(AuthorityStoreExistsError):
            AuthorityStore.initialize_new(self.path)
        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(store.read_generation("scope"), 1)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_initialize_does_not_follow_existing_broken_symlink(self):
        link = self._new_path("link.sqlite3")
        target = self._new_path("missing.sqlite3")
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(AuthorityStoreExistsError):
            AuthorityStore.initialize_new(link)
        self.assertFalse(target.exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_initialize_rejects_symlink_interposed_at_reservation(self):
        target = self._new_path("interposed-target.sqlite3")
        real_reserve = AuthorityStore._reserve_new_windows_path

        def interpose(path):
            try:
                os.symlink(target, path)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            return real_reserve(path)

        with mock.patch.object(AuthorityStore, "_reserve_new_windows_path", side_effect=interpose):
            with self.assertRaises(AuthorityStoreExistsError):
                AuthorityStore.initialize_new(self.path)
        self.assertTrue(os.path.lexists(self.path))
        self.assertFalse(target.exists())

    @unittest.skipUnless(os.name == "nt", "Windows reservation semantics required")
    def test_windows_reservation_prevents_replacement_before_sqlite_open(self):
        replacement = self._new_path("replacement.sqlite3")
        replacement.write_bytes(b"not an authority store")
        real_connect = AuthorityStore._connect_rw

        def connect(path):
            with self.assertRaises(PermissionError):
                os.replace(replacement, path)
            self.assertTrue(path.exists())
            return real_connect(path)

        with mock.patch.object(AuthorityStore, "_connect_rw", side_effect=connect):
            with AuthorityStore.initialize_new(self.path) as store:
                self.assertIsNone(store.read_generation("controller/default"))
        self.assertTrue(replacement.exists())

    def test_open_existing_missing_path_fails(self):
        with self.assertRaises(AuthorityStoreMissingError):
            AuthorityStore.open_existing(self.path)
        self.assertFalse(self.path.exists())

    def test_valid_v1_requires_explicit_migration(self):
        self._create_v1_store(rows=(("scope", 7),))
        with self.assertRaises(AuthorityStoreMigrationRequiredError):
            AuthorityStore.open_existing(self.path)
        self.assertEqual(self._read_rows(self.path, "PRAGMA user_version"), [(1,)])

    def test_valid_v2_requires_explicit_migration_without_mutation(self):
        self._create_v2_store(generation_rows=(("scope", 7),), execution_keys=("K",))
        with self.assertRaises(AuthorityStoreMigrationRequiredError):
            AuthorityStore.open_existing(self.path)
        c = sqlite3.connect(self.path); self.addCleanup(c.close)
        self.assertEqual(c.execute("PRAGMA user_version").fetchone(), (2,))
        self.assertEqual(c.execute("SELECT execution_key FROM execution_keys").fetchall(), [("K",)])

    def test_valid_v3_requires_explicit_migration_without_mutation(self):
        self._create_v3_store(generation_rows=(("scope", 7),), execution_keys=("K",), bindings=(("K", "H"),))
        with self.assertRaises(AuthorityStoreMigrationRequiredError):
            AuthorityStore.open_existing(self.path)
        c = sqlite3.connect(self.path); self.addCleanup(c.close)
        self.assertEqual(c.execute("PRAGMA user_version").fetchone(), (3,))
        self.assertEqual(c.execute("SELECT * FROM execution_command_bindings").fetchall(), [("K", "H")])
        self.assertEqual(c.execute("SELECT name FROM sqlite_schema WHERE name='execution_admissions'").fetchall(), [])

    def test_migrate_v1_to_v2_still_produces_exact_v2(self):
        self._create_v1_store(rows=(("scope", 5),))
        AuthorityStore.migrate_v1_to_v2(self.path)
        c = sqlite3.connect(self.path); self.addCleanup(c.close)
        self.assertEqual(c.execute("PRAGMA user_version").fetchone(), (2,))
        self.assertEqual(c.execute("SELECT name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall(), [("controller_generations",), ("execution_keys",)])

    def test_migrate_v2_to_v3_still_produces_exact_v3(self):
        self._create_v2_store(generation_rows=(("scope", 5),), execution_keys=("K",))
        AuthorityStore.migrate_v2_to_v3(self.path)
        c = sqlite3.connect(self.path); self.addCleanup(c.close)
        self.assertEqual(c.execute("PRAGMA user_version").fetchone(), (3,))
        self.assertEqual(c.execute("SELECT name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall(), [("controller_generations",), ("execution_command_bindings",), ("execution_keys",)])

    def test_explicit_v1_to_v2_to_v3_to_v4_to_v5_chain_succeeds(self):
        self._create_v1_store(rows=(("scope", 5),))
        AuthorityStore.migrate_v1_to_v2(self.path)
        AuthorityStore.migrate_v2_to_v3(self.path)
        AuthorityStore.migrate_v3_to_v4(self.path)
        AuthorityStore.migrate_v4_to_v5(self.path)
        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(store.read_generation("scope"), 5)
            self.assertFalse(store.execution_key_exists("missing"))

    def test_v2_to_v3_preserves_generation_rows_exactly(self):
        rows = [("scope/A", 3), ("scope/B", 9)]
        self._create_v2_store(generation_rows=rows, execution_keys=("K",))
        AuthorityStore.migrate_v2_to_v3(self.path)
        c = sqlite3.connect(self.path); self.addCleanup(c.close)
        self.assertEqual(c.execute("SELECT scope, generation FROM controller_generations ORDER BY scope").fetchall(), rows)

    def test_v2_to_v3_preserves_execution_keys_exactly(self):
        keys = [" K ", "K", "k", "é", "é"]
        self._create_v2_store(execution_keys=keys)
        before = self._read_rows(self.path, "SELECT execution_key FROM execution_keys ORDER BY execution_key")
        AuthorityStore.migrate_v2_to_v3(self.path)
        after = self._read_rows(self.path, "SELECT execution_key FROM execution_keys ORDER BY execution_key")
        self.assertEqual(after, before)

    def test_v2_to_v3_invents_zero_bindings(self):
        self._create_v2_store(execution_keys=("K1", "K2"))
        AuthorityStore.migrate_v2_to_v3(self.path)
        self.assertEqual(self._read_rows(self.path, "SELECT * FROM execution_command_bindings"), [])

    def test_malformed_v2_migration_fails_closed(self):
        self._create_v2_store(execution_keys=("K",))
        self._replace_table_definition_literal("execution_keys", "'text'", "'TEXT'")
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.migrate_v2_to_v3(self.path)

    def test_unexpected_v2_persisted_object_blocks_migration(self):
        self._create_v2_store()
        c = sqlite3.connect(self.path); c.execute("CREATE TABLE unexpected(value INTEGER)"); c.commit(); c.close()
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.migrate_v2_to_v3(self.path)

    def test_v2_to_v3_called_on_v1_v3_or_unsupported_version_fails(self):
        v1 = self._new_path("v1.db"); self._create_v1_store(v1)
        v3 = self._new_path("v3.db"); self._create_v3_store(v3)
        bad = self._new_path("bad.db"); self._create_v2_store(bad); c=sqlite3.connect(bad); c.execute("PRAGMA user_version=999"); c.commit(); c.close()
        for path in (v1, v3, bad):
            with self.assertRaises(AuthorityStoreVersionError):
                AuthorityStore.migrate_v2_to_v3(path)

    def test_v1_to_v2_called_on_v2_fails_and_v2_remains_exact(self):
        self._create_v2_store(execution_keys=("K",))
        with self.assertRaises(AuthorityStoreVersionError):
            AuthorityStore.migrate_v1_to_v2(self.path)
        self.assertEqual(self._read_rows(self.path, "PRAGMA user_version"), [(2,)])

    def test_first_acquisition_returns_one(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope"), 1)

    def test_repeated_acquisition_is_strictly_increasing(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual([store.acquire_generation("scope") for _ in range(3)], [1, 2, 3])

    def test_close_reopen_preserves_generation(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.acquire_generation("scope"); store.acquire_generation("scope")
        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(store.read_generation("scope"), 2)
            self.assertEqual(store.acquire_generation("scope"), 3)

    def test_scopes_have_independent_sequences(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("A"), 1)
            self.assertEqual(store.acquire_generation("A"), 2)
            self.assertEqual(store.acquire_generation("B"), 1)

    def test_concurrent_generation_acquisition_is_unique(self):
        AuthorityStore.initialize_new(self.path).close()
        def acquire(_):
            with AuthorityStore.open_existing(self.path) as store:
                return store.acquire_generation("scope")
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            values = list(pool.map(acquire, range(16)))
        self.assertEqual(sorted(values), list(range(1, 17)))

    def test_generation_overflow_fails_without_modifying_state(self):
        maximum = (1 << 63) - 1
        with AuthorityStore.initialize_new(self.path) as store:
            store.acquire_generation("scope")
        c=sqlite3.connect(self.path); c.execute("UPDATE controller_generations SET generation=?", (maximum,)); c.commit(); c.close()
        with AuthorityStore.open_existing(self.path) as store:
            with self.assertRaises(GenerationOverflowError):
                store.acquire_generation("scope")
            self.assertEqual(store.read_generation("scope"), maximum)

    def test_empty_scope_is_rejected(self):
        with AuthorityStore.initialize_new(self.path) as store:
            for operation in (store.acquire_generation, store.read_generation):
                with self.assertRaises(InvalidAuthorityScopeError): operation("")

    def test_first_execution_key_registration_is_new_and_durable(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.register_execution_key("K"), ExecutionKeyRegistration.NEW)
        with AuthorityStore.open_existing(self.path) as store:
            self.assertTrue(store.execution_key_exists("K"))

    def test_duplicate_execution_key_registration_is_duplicate_and_single_row(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.register_execution_key("K"), ExecutionKeyRegistration.NEW)
            self.assertEqual(store.register_execution_key("K"), ExecutionKeyRegistration.DUPLICATE)
            self.assertEqual(store._connection.execute("SELECT count(*) FROM execution_keys").fetchone(), (1,))

    def test_concurrent_execution_key_registration_has_one_new(self):
        AuthorityStore.initialize_new(self.path).close()
        def register(_):
            with AuthorityStore.open_existing(self.path) as store: return store.register_execution_key("K")
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(register, range(16)))
        self.assertEqual(results.count(ExecutionKeyRegistration.NEW), 1)
        self.assertEqual(results.count(ExecutionKeyRegistration.DUPLICATE), 15)

    def test_invalid_execution_key_arguments_are_rejected(self):
        class S(str): pass
        with AuthorityStore.initialize_new(self.path) as store:
            for key in ("", None, 0, True, b"K", S("K")):
                with self.assertRaises(InvalidExecutionKeyError): store.register_execution_key(key)
                with self.assertRaises(InvalidExecutionKeyError): store.execution_key_exists(key)

    def test_execution_key_commit_failure_returns_no_registration_result(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self._deny_commit(store)
            try:
                with self.assertRaises(AuthorityStoreError): store.register_execution_key("K")
            finally: store._connection.set_authorizer(None)
            self.assertFalse(store.execution_key_exists("K"))

    def test_registered_key_can_be_bound(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K")
            self.assertEqual(store.bind_command_spec_hash("K", "H"), CommandSpecBindingResult.BOUND)
            self.assertEqual(store.read_command_spec_hash("K"), "H")

    def test_same_key_same_hash_is_already_bound(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K"); store.bind_command_spec_hash("K", "H")
            self.assertEqual(store.bind_command_spec_hash("K", "H"), CommandSpecBindingResult.ALREADY_BOUND)

    def test_close_reopen_same_binding_is_already_bound(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K"); store.bind_command_spec_hash("K", "H")
        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(store.bind_command_spec_hash("K", "H"), CommandSpecBindingResult.ALREADY_BOUND)

    def test_different_hash_conflicts_and_original_remains(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K"); store.bind_command_spec_hash("K", "H1")
            with self.assertRaises(CommandSpecConflictError): store.bind_command_spec_hash("K", "H2")
            self.assertEqual(store.read_command_spec_hash("K"), "H1")

    def test_unregistered_key_cannot_bind_and_creates_no_rows(self):
        with AuthorityStore.initialize_new(self.path) as store:
            with self.assertRaises(ExecutionKeyNotRegisteredError): store.bind_command_spec_hash("K", "H")
            self.assertEqual(store._connection.execute("SELECT count(*) FROM execution_command_bindings").fetchone(), (0,))

    def test_unregistered_key_cannot_be_read(self):
        with AuthorityStore.initialize_new(self.path) as store:
            with self.assertRaises(ExecutionKeyNotRegisteredError): store.read_command_spec_hash("K")

    def test_registered_unbound_key_reads_none(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K"); self.assertIsNone(store.read_command_spec_hash("K"))

    def test_independent_keys_bind_independently(self):
        with AuthorityStore.initialize_new(self.path) as store:
            for k,h in (("K1","H1"),("K2","H2")):
                store.register_execution_key(k); store.bind_command_spec_hash(k,h)
            self.assertEqual(store.read_command_spec_hash("K1"), "H1")
            self.assertEqual(store.read_command_spec_hash("K2"), "H2")

    def test_concurrent_same_key_same_hash_has_one_bound(self):
        with AuthorityStore.initialize_new(self.path) as store: store.register_execution_key("K")
        def bind(_):
            with AuthorityStore.open_existing(self.path) as store: return store.bind_command_spec_hash("K","H")
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(bind, range(12)))
        self.assertEqual(results.count(CommandSpecBindingResult.BOUND),1)
        self.assertEqual(results.count(CommandSpecBindingResult.ALREADY_BOUND),11)

    def test_concurrent_competing_hashes_have_one_winner_and_one_conflict(self):
        with AuthorityStore.initialize_new(self.path) as store: store.register_execution_key("K")
        def bind(h):
            try:
                with AuthorityStore.open_existing(self.path) as store: return store.bind_command_spec_hash("K",h)
            except CommandSpecConflictError: return "conflict"
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(bind,("H1","H2")))
        self.assertEqual(results.count(CommandSpecBindingResult.BOUND),1); self.assertEqual(results.count("conflict"),1)

    def test_command_spec_hash_exact_value_semantics(self):
        values=["H","h"," H "," ","é","é"]
        with AuthorityStore.initialize_new(self.path) as store:
            for i,h in enumerate(values):
                k=f"K{i}"; store.register_execution_key(k); store.bind_command_spec_hash(k,h); self.assertEqual(store.read_command_spec_hash(k),h)

    def test_invalid_command_spec_hash_is_rejected(self):
        class S(str): pass
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K")
            for h in ("",None,0,True,b"H",S("H"),chr(0xD800)):
                with self.assertRaises(InvalidCommandSpecHashError): store.bind_command_spec_hash("K",h)

    def test_malformed_persisted_hash_fails_full_validation(self):
        with AuthorityStore.initialize_new(self.path) as store: store.register_execution_key("K"); store.bind_command_spec_hash("K","H")
        c=sqlite3.connect(self.path); c.execute("PRAGMA ignore_check_constraints=ON"); c.execute("UPDATE execution_command_bindings SET command_spec_hash='' WHERE execution_key='K'"); c.commit(); c.close()
        with self.assertRaises(AuthorityStoreMalformedError): AuthorityStore.open_existing(self.path)

    def test_orphan_binding_fails_full_validation(self):
        AuthorityStore.initialize_new(self.path).close(); c=sqlite3.connect(self.path); c.execute("INSERT INTO execution_command_bindings VALUES ('K','H')"); c.commit(); c.close()
        with self.assertRaises(AuthorityStoreMalformedError): AuthorityStore.open_existing(self.path)

    def test_binding_commit_failure_returns_no_success_result(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K"); self._deny_commit(store)
            try:
                with self.assertRaises(AuthorityStoreError): store.bind_command_spec_hash("K","H")
            finally: store._connection.set_authorizer(None)
            self.assertIsNone(store.read_command_spec_hash("K"))

    def test_binding_schema_literal_case_drift_fails_closed(self):
        AuthorityStore.initialize_new(self.path).close(); self._replace_table_definition_literal("execution_command_bindings", "'text' AND command_spec_hash", "'TEXT' AND command_spec_hash")
        with self.assertRaises(AuthorityStoreMalformedError): AuthorityStore.open_existing(self.path)

    def test_unexpected_persisted_schema_object_fails_closed(self):
        AuthorityStore.initialize_new(self.path).close(); c=sqlite3.connect(self.path); c.execute("CREATE VIEW unexpected AS SELECT * FROM execution_keys"); c.commit(); c.close()
        with self.assertRaises(AuthorityStoreMalformedError): AuthorityStore.open_existing(self.path)

    def test_non_database_state_fails_closed(self):
        self.path.write_bytes(b"not sqlite")
        with self.assertRaises(AuthorityStoreMalformedError): AuthorityStore.open_existing(self.path)

    def test_unsupported_schema_version_fails_closed(self):
        AuthorityStore.initialize_new(self.path).close(); c=sqlite3.connect(self.path); c.execute("PRAGMA user_version=999"); c.commit(); c.close()
        with self.assertRaises(AuthorityStoreVersionError): AuthorityStore.open_existing(self.path)

    def test_is_current_generation_requires_exact_persisted_generation(self):
        with AuthorityStore.initialize_new(self.path) as store:
            g=store.acquire_generation("S"); self.assertTrue(store.is_current_generation("S",g))
            for x in (0, True, g+1, (1<<63)):
                self.assertFalse(store.is_current_generation("S",x))

    def test_prior_generation_becomes_stale_after_next_acquisition(self):
        with AuthorityStore.initialize_new(self.path) as store:
            old=store.acquire_generation("S"); new=store.acquire_generation("S"); self.assertFalse(store.is_current_generation("S",old)); self.assertTrue(store.is_current_generation("S",new))

    def test_read_commit_failure_returns_no_observation_and_cleans_up(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.acquire_generation("S"); self._deny_commit(store)
            try:
                with self.assertRaises(AuthorityStoreError): store.read_generation("S")
            finally: store._connection.set_authorizer(None)
            self.assertFalse(store._poisoned); self.assertEqual(store.read_generation("S"),1)

    def test_rollback_failure_permanently_poisons_store(self):
        store=AuthorityStore.initialize_new(self.path); self.addCleanup(store.close); c=sqlite3.connect(self.path); c.execute("CREATE TABLE unexpected(x)"); c.commit(); c.close()
        with mock.patch.object(AuthorityStore,"_rollback_transaction",side_effect=sqlite3.OperationalError("boom")):
            with self.assertRaises(AuthorityStoreError): store.acquire_generation("S")
        self.assertTrue(store._poisoned); self.assertIsNone(store._connection)

    # Retained U1A/U1B/U1D fail-closed and cleanup regressions.
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
            self._deny_commit(store)
            try:
                with self.assertRaises(AuthorityStoreError):
                    store.read_command_spec_hash("K")
            finally:
                store._connection.set_authorizer(None)
            self.assertFalse(store._connection.in_transaction)
            self.assertEqual(store.read_command_spec_hash("K"), "H")

    def test_canonical_v2_schema_round_trip_succeeds(self):
        # Historical name retained; this exercises the same generation/key round trip
        # against the current schema rather than silently treating v2 as current.
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope"), 1)
            self.assertEqual(
                store.register_execution_key("K"), ExecutionKeyRegistration.NEW
            )
        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(store.read_generation("scope"), 1)
            self.assertTrue(store.execution_key_exists("K"))

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
            connection.execute("PRAGMA user_version = 4")
            connection.execute(
                """
                CREATE TABLE controller_generations (
                    scope TEXT NOT NULL PRIMARY KEY,
                    generation INTEGER NOT NULL
                ) WITHOUT ROWID
                """
            )
            connection.execute(_V2_EXECUTION_KEYS_SQL)
            connection.execute(_V3_BINDINGS_SQL)
            connection.execute(_V4_ADMISSIONS_SQL)
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_execution_key_literal_case_schema_drift_fails_closed(self):
        AuthorityStore.initialize_new(self.path).close()
        self._replace_table_definition_literal("execution_keys", "'text'", "'TEXT'")
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_generation_literal_case_schema_drift_fails_closed(self):
        AuthorityStore.initialize_new(self.path).close()
        self._replace_table_definition_literal(
            "controller_generations", "'text'", "'TEXT'"
        )
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_noncanonical_v2_schema_blocks_validated_observations(self):
        # Historical test name retained; current v5 observations still fail closed
        # on the same noncanonical execution_keys definition.
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store.acquire_generation("scope"), 1)
            self._replace_table_definition_literal(
                "execution_keys", "'text'", "'TEXT'"
            )
            with self.assertRaises(AuthorityStoreMalformedError):
                store.execution_key_exists("missing")
            with self.assertRaises(AuthorityStoreMalformedError):
                store.read_generation("scope")

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
        for operation in (
            lambda: store.read_generation("scope"),
            lambda: store.is_current_generation("scope", 1),
            lambda: store.acquire_generation("scope"),
        ):
            with self.assertRaises(AuthorityStoreError):
                operation()

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
                    AuthorityStore, "_validate_store", side_effect=validate_then_pause
                ):
                    observed = store.read_generation("scope")
            finally:
                thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(writer_errors, [])
            self.assertEqual(observed, 1)
            self.assertEqual(store.read_generation("scope"), 2)

    def test_open_existing_rejects_unexpected_persisted_schema_objects(self):
        cases = {
            "table": "CREATE TABLE unexpected_table(value INTEGER)",
            "view": (
                "CREATE VIEW unexpected_view AS "
                "SELECT scope, generation FROM controller_generations"
            ),
            "index": "CREATE INDEX unexpected_index ON controller_generations(generation)",
            "sqlite-lookalike-trigger": (
                "CREATE TRIGGER sqliteXrewind "
                "AFTER UPDATE OF generation ON controller_generations "
                "BEGIN UPDATE controller_generations "
                "SET generation = OLD.generation WHERE scope = NEW.scope; END"
            ),
        }
        for kind, ddl in cases.items():
            with self.subTest(kind=kind):
                path = self._new_path(f"unexpected-{kind}.sqlite3")
                AuthorityStore.initialize_new(path).close()
                connection = sqlite3.connect(path)
                try:
                    connection.execute(ddl)
                    connection.commit()
                finally:
                    connection.close()
                with self.assertRaises(AuthorityStoreMalformedError):
                    AuthorityStore.open_existing(path)

    def test_independent_execution_keys_register_independently(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(
                store.register_execution_key("K1"), ExecutionKeyRegistration.NEW
            )
            self.assertEqual(
                store.register_execution_key("K2"), ExecutionKeyRegistration.NEW
            )
            self.assertTrue(store.execution_key_exists("K1"))
            self.assertTrue(store.execution_key_exists("K2"))

    def test_execution_key_is_exact_and_not_normalized(self):
        keys = ["K", "k", " K ", " "]
        with AuthorityStore.initialize_new(self.path) as store:
            for key in keys:
                self.assertEqual(
                    store.register_execution_key(key), ExecutionKeyRegistration.NEW
                )
            self.assertEqual(
                store._connection.execute(
                    "SELECT execution_key FROM execution_keys ORDER BY execution_key"
                ).fetchall(),
                [(" ",), (" K ",), ("K",), ("k",)],
            )

    def test_execution_key_restart_preserves_registration(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(
                store.register_execution_key("K"), ExecutionKeyRegistration.NEW
            )
        with AuthorityStore.open_existing(self.path) as store:
            self.assertTrue(store.execution_key_exists("K"))
            self.assertEqual(
                store.register_execution_key("K"), ExecutionKeyRegistration.DUPLICATE
            )

    def test_malformed_persisted_execution_key_fails_closed(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(
                store.register_execution_key("K"), ExecutionKeyRegistration.NEW
            )
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("PRAGMA ignore_check_constraints = ON")
            connection.execute(
                "UPDATE execution_keys SET execution_key = '' "
                "WHERE execution_key = 'K'"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_registration_revalidates_schema_after_post_open_mutation(self):
        with AuthorityStore.initialize_new(self.path) as store:
            connection = sqlite3.connect(self.path)
            try:
                connection.execute("CREATE TABLE unexpected_table(value INTEGER)")
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(AuthorityStoreMalformedError):
                store.register_execution_key("K")
            connection = sqlite3.connect(self.path)
            try:
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM execution_keys").fetchone(),
                    (0,),
                )
            finally:
                connection.close()

    def test_execution_key_exists_revalidates_schema_after_post_open_mutation(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(
                store.register_execution_key("K"), ExecutionKeyRegistration.NEW
            )
            connection = sqlite3.connect(self.path)
            try:
                connection.execute(
                    "CREATE VIEW unexpected_view AS SELECT execution_key FROM execution_keys"
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(AuthorityStoreMalformedError):
                store.execution_key_exists("missing")

    def test_registration_rollback_failure_permanently_poisons_store(self):
        store = AuthorityStore.initialize_new(self.path)
        self.addCleanup(store.close)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("CREATE TABLE unexpected_table(value INTEGER)")
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
                store.register_execution_key("K")
        self.assertTrue(store._poisoned)
        self.assertIsNone(store._connection)
        with self.assertRaises(sqlite3.ProgrammingError):
            original_connection.execute("SELECT 1")
        for operation in (
            lambda: store.register_execution_key("K"),
            lambda: store.execution_key_exists("K"),
            lambda: store.acquire_generation("scope"),
            lambda: store.read_generation("scope"),
        ):
            with self.assertRaises(AuthorityStoreError):
                operation()

    def test_exact_v1_store_does_not_silently_open_as_v2(self):
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

    def test_canonical_v1_schema_migration_succeeds(self):
        self._create_v1_store(rows=(("scope", 5),))
        AuthorityStore.migrate_v1_to_v2(self.path)
        AuthorityStore.migrate_v2_to_v3(self.path)
        AuthorityStore.migrate_v3_to_v4(self.path)
        AuthorityStore.migrate_v4_to_v5(self.path)
        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(store.read_generation("scope"), 5)
            self.assertFalse(store.execution_key_exists("missing"))

    def test_explicit_v1_to_v2_migration_preserves_generation_rows(self):
        rows = [("scope/A", 3), ("scope/B", 9)]
        self._create_v1_store(rows=rows)
        before = sqlite3.connect(self.path)
        try:
            before_rows = before.execute(
                "SELECT scope, generation FROM controller_generations ORDER BY scope"
            ).fetchall()
        finally:
            before.close()
        AuthorityStore.migrate_v1_to_v2(self.path)
        connection = sqlite3.connect(self.path)
        try:
            after_rows = connection.execute(
                "SELECT scope, generation FROM controller_generations ORDER BY scope"
            ).fetchall()
            self.assertEqual(after_rows, before_rows)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (2,))
        finally:
            connection.close()
        AuthorityStore.migrate_v2_to_v3(self.path)
        AuthorityStore.migrate_v3_to_v4(self.path)
        AuthorityStore.migrate_v4_to_v5(self.path)
        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(store.read_generation("scope/A"), 3)
            self.assertEqual(store.acquire_generation("scope/A"), 4)
            self.assertEqual(
                store.register_execution_key("K"), ExecutionKeyRegistration.NEW
            )
            self.assertTrue(store.execution_key_exists("K"))

    def test_v1_literal_case_schema_drift_rejects_migration(self):
        self._create_v1_store()
        self._replace_table_definition_literal(
            "controller_generations", "'text'", "'TEXT'"
        )
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.migrate_v1_to_v2(self.path)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (1,))
            self.assertEqual(
                connection.execute(
                    "SELECT name FROM sqlite_schema WHERE name = 'execution_keys'"
                ).fetchall(),
                [],
            )
        finally:
            connection.close()

    def test_malformed_v1_migration_fails_without_resetting_state(self):
        self._create_v1_store(rows=(("scope", 7),))
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("CREATE TABLE unexpected_table(value INTEGER)")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.migrate_v1_to_v2(self.path)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (1,))
            self.assertEqual(
                connection.execute(
                    "SELECT scope, generation FROM controller_generations"
                ).fetchall(),
                [("scope", 7)],
            )
            self.assertEqual(
                connection.execute(
                    "SELECT name FROM sqlite_schema WHERE name = 'execution_keys'"
                ).fetchall(),
                [],
            )
        finally:
            connection.close()

    def test_v1_to_v2_migration_called_on_v2_fails(self):
        self._create_v2_store(execution_keys=("K",))
        with self.assertRaises(AuthorityStoreVersionError):
            AuthorityStore.migrate_v1_to_v2(self.path)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (2,))
            self.assertEqual(
                connection.execute("SELECT execution_key FROM execution_keys").fetchall(),
                [("K",)],
            )
        finally:
            connection.close()

    def test_v1_to_v2_migration_rejects_unsupported_version(self):
        self._create_v1_store()
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("PRAGMA user_version = 999")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreVersionError):
            AuthorityStore.migrate_v1_to_v2(self.path)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (999,))
        finally:
            connection.close()

    def test_v1_to_v2_migration_rejects_unexpected_v1_schema_object(self):
        self._create_v1_store(rows=(("scope", 2),))
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
            AuthorityStore.migrate_v1_to_v2(self.path)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (1,))
            self.assertEqual(
                connection.execute(
                    "SELECT generation FROM controller_generations WHERE scope = 'scope'"
                ).fetchone(),
                (2,),
            )
        finally:
            connection.close()

    # U1E migration tests.
    def test_migrate_v3_to_v4_ends_at_exact_historical_v4(self):
        self._create_v3_store(generation_rows=(("S",2),),execution_keys=("K",),bindings=(("K","H"),))
        AuthorityStore.migrate_v3_to_v4(self.path)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (4,))
            self.assertEqual(
                connection.execute("SELECT name FROM sqlite_schema WHERE name='execution_launches'").fetchall(),
                [],
            )
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreMigrationRequiredError):
            AuthorityStore.open_existing(self.path)

    def test_v3_to_v4_preserves_generation_rows_exactly(self):
        rows=[("A",3),("B",9)]; self._create_v3_store(generation_rows=rows)
        before = self._read_rows(self.path, "SELECT * FROM controller_generations ORDER BY scope")
        AuthorityStore.migrate_v3_to_v4(self.path)
        after = self._read_rows(self.path, "SELECT * FROM controller_generations ORDER BY scope")
        self.assertEqual(after, before)

    def test_v3_to_v4_preserves_execution_keys_exactly(self):
        keys=(" K ","K","k","é","é"); self._create_v3_store(execution_keys=keys)
        before = self._read_rows(self.path, "SELECT * FROM execution_keys ORDER BY execution_key")
        AuthorityStore.migrate_v3_to_v4(self.path)
        after = self._read_rows(self.path, "SELECT * FROM execution_keys ORDER BY execution_key")
        self.assertEqual(after, before)

    def test_v3_to_v4_preserves_command_bindings_exactly(self):
        self._create_v3_store(execution_keys=("K1","K2"),bindings=(("K1","H1"),("K2","H2")))
        before = self._read_rows(
            self.path, "SELECT * FROM execution_command_bindings ORDER BY execution_key"
        )
        AuthorityStore.migrate_v3_to_v4(self.path)
        after = self._read_rows(
            self.path, "SELECT * FROM execution_command_bindings ORDER BY execution_key"
        )
        self.assertEqual(after, before)

    def test_v3_to_v4_invents_zero_admissions(self):
        self._create_v3_store(execution_keys=("K",),bindings=(("K","H"),)); AuthorityStore.migrate_v3_to_v4(self.path)
        self.assertEqual(self._read_rows(self.path, "SELECT * FROM execution_admissions"), [])

    def test_malformed_v3_rejects_migration(self):
        self._create_v3_store(execution_keys=("K",),bindings=(("K","H"),)); self._replace_table_definition_literal("execution_command_bindings","'text' AND command_spec_hash","'TEXT' AND command_spec_hash")
        with self.assertRaises(AuthorityStoreMalformedError): AuthorityStore.migrate_v3_to_v4(self.path)

    def test_unexpected_v3_object_rejects_migration(self):
        self._create_v3_store(); c=sqlite3.connect(self.path); c.execute("CREATE TABLE unexpected(x)"); c.commit(); c.close()
        with self.assertRaises(AuthorityStoreMalformedError): AuthorityStore.migrate_v3_to_v4(self.path)

    def test_v3_to_v4_wrong_versions_reject(self):
        v1=self._new_path("v1.db"); self._create_v1_store(v1)
        v2=self._new_path("v2.db"); self._create_v2_store(v2)
        v4=self._new_path("v4.db"); self._create_v3_store(v4); AuthorityStore.migrate_v3_to_v4(v4)
        bad=self._new_path("bad.db"); self._create_v3_store(bad); c=sqlite3.connect(bad); c.execute("PRAGMA user_version=999"); c.commit(); c.close()
        for path in (v1,v2,v4,bad):
            with self.assertRaises(AuthorityStoreVersionError): AuthorityStore.migrate_v3_to_v4(path)

    def test_v3_to_v4_commit_uncertainty_uses_existing_policy(self):
        self._create_v3_store()
        real_connect=AuthorityStore._connect_rw
        holder={}
        class Proxy:
            def __init__(self,c): self._c=c
            def __getattr__(self,n): return getattr(self._c,n)
            @property
            def in_transaction(self): return self._c.in_transaction
            def execute(self,sql,*a,**kw):
                if sql=="COMMIT": raise sqlite3.OperationalError("injected commit failure")
                return self._c.execute(sql,*a,**kw)
            def close(self): self._c.close()
        def connect(path): holder['p']=Proxy(real_connect(path)); return holder['p']
        with mock.patch.object(AuthorityStore,"_connect_rw",side_effect=connect):
            with self.assertRaisesRegex(AuthorityStoreError,"outcome is uncertain"): AuthorityStore.migrate_v3_to_v4(self.path)

    # U1E admission functional semantics.
    def test_registered_bound_current_admit_is_admitted(self):
        store,g=self._prepare_bound(); self.addCleanup(store.close); self.assertEqual(store.admit_execution("K","S",g),ExecutionAdmissionResult.ADMITTED)

    def test_exact_second_admission_while_current_is_already_admitted(self):
        store,g=self._prepare_bound(); self.addCleanup(store.close); store.admit_execution("K","S",g); self.assertEqual(store.admit_execution("K","S",g),ExecutionAdmissionResult.ALREADY_ADMITTED)

    def test_close_reopen_exact_admission_is_already_admitted(self):
        store,g=self._prepare_bound(); store.admit_execution("K","S",g); store.close()
        with AuthorityStore.open_existing(self.path) as reopened: self.assertEqual(reopened.admit_execution("K","S",g),ExecutionAdmissionResult.ALREADY_ADMITTED)

    def test_unregistered_key_cannot_be_admitted(self):
        with AuthorityStore.initialize_new(self.path) as store:
            g=store.acquire_generation("S")
            with self.assertRaises(ExecutionKeyNotRegisteredError): store.admit_execution("K","S",g)
            self.assertFalse(store.execution_key_exists("K")); self.assertEqual(store._connection.execute("SELECT count(*) FROM execution_admissions").fetchone(),(0,))

    def test_registered_unbound_key_cannot_be_admitted(self):
        with AuthorityStore.initialize_new(self.path) as store:
            g=store.acquire_generation("S"); store.register_execution_key("K")
            with self.assertRaises(ExecutionKeyNotCommandBoundError): store.admit_execution("K","S",g)
            self.assertIsNone(store.read_execution_admission("K"))

    def test_missing_generation_scope_is_not_current(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K"); store.bind_command_spec_hash("K","H")
            with self.assertRaises(ControllerGenerationNotCurrentError): store.admit_execution("K","S",1)

    def test_stale_expected_generation_is_not_current(self):
        store,g=self._prepare_bound(); self.addCleanup(store.close); store.acquire_generation("S")
        with self.assertRaises(ControllerGenerationNotCurrentError): store.admit_execution("K","S",g)

    def test_future_expected_generation_is_not_current(self):
        store,g=self._prepare_bound(); self.addCleanup(store.close)
        with self.assertRaises(ControllerGenerationNotCurrentError): store.admit_execution("K","S",g+1)

    def test_invalid_expected_generation_rejected_before_transaction(self):
        store,_=self._prepare_bound(); self.addCleanup(store.close)
        for value in (None,True,False,0,-1,1.0,"1",(1<<63)):
            with self.subTest(value=value):
                with self.assertRaises(InvalidControllerGenerationError): store.admit_execution("K","S",value)
                self.assertFalse(store._connection.in_transaction)

    def test_same_key_different_current_scope_conflicts(self):
        store,g=self._prepare_bound(); self.addCleanup(store.close); store.admit_execution("K","S",g); other=store.acquire_generation("T")
        with self.assertRaises(ExecutionAdmissionConflictError): store.admit_execution("K","T",other)

    def test_same_key_after_generation_advances_cannot_be_readmitted(self):
        store,g=self._prepare_bound(); self.addCleanup(store.close); store.admit_execution("K","S",g); new=store.acquire_generation("S")
        with self.assertRaises(ExecutionAdmissionConflictError): store.admit_execution("K","S",new)
        self.assertEqual(store.read_execution_admission("K").controller_generation,g)

    def test_stale_caller_matching_original_admission_not_already_admitted(self):
        store,g=self._prepare_bound(); self.addCleanup(store.close); store.admit_execution("K","S",g); store.acquire_generation("S")
        with self.assertRaises(ControllerGenerationNotCurrentError): store.admit_execution("K","S",g)

    def test_admission_persists_across_restart(self):
        store,g=self._prepare_bound(); store.admit_execution("K","S",g); store.close()
        with AuthorityStore.open_existing(self.path) as reopened: self.assertEqual(reopened.read_execution_admission("K"),ExecutionAdmission("K","S",g))

    def test_two_distinct_keys_admit_independently(self):
        with AuthorityStore.initialize_new(self.path) as store:
            g=store.acquire_generation("S")
            for k,h in (("K1","H1"),("K2","H2")): store.register_execution_key(k); store.bind_command_spec_hash(k,h); self.assertEqual(store.admit_execution(k,"S",g),ExecutionAdmissionResult.ADMITTED)
            self.assertEqual(store._connection.execute("SELECT count(*) FROM execution_admissions").fetchone(),(2,))

    def test_read_unregistered_admission_is_explicit_failure(self):
        with AuthorityStore.initialize_new(self.path) as store:
            with self.assertRaises(ExecutionKeyNotRegisteredError): store.read_execution_admission("K")

    def test_read_registered_no_admission_returns_none(self):
        with AuthorityStore.initialize_new(self.path) as store:
            store.register_execution_key("K"); self.assertIsNone(store.read_execution_admission("K"))

    def test_execution_admission_value_is_frozen(self):
        value=ExecutionAdmission("K","S",1)
        with self.assertRaises(FrozenInstanceError): value.controller_generation=2

    def test_read_stale_admission_does_not_imply_current_authority(self):
        store,g=self._prepare_bound(); self.addCleanup(store.close); store.admit_execution("K","S",g); store.acquire_generation("S"); admission=store.read_execution_admission("K"); self.assertEqual(admission.controller_generation,g); self.assertFalse(store.is_current_generation("S",g))

    # Concurrency.
    def test_same_admission_concurrency_one_admitted_rest_already(self):
        store,g=self._prepare_bound(); store.close()
        def admit(_):
            with AuthorityStore.open_existing(self.path) as s: return s.admit_execution("K","S",g)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(admit,range(16)))
        self.assertEqual(results.count(ExecutionAdmissionResult.ADMITTED),1); self.assertEqual(results.count(ExecutionAdmissionResult.ALREADY_ADMITTED),15)

    def test_competing_admission_identities_have_one_durable_winner(self):
        with AuthorityStore.initialize_new(self.path) as store:
            g1=store.acquire_generation("S1"); g2=store.acquire_generation("S2"); store.register_execution_key("K"); store.bind_command_spec_hash("K","H")
        def admit(args):
            scope,g=args
            try:
                with AuthorityStore.open_existing(self.path) as s: return s.admit_execution("K",scope,g)
            except ExecutionAdmissionConflictError: return "conflict"
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(admit,(("S1",g1),("S2",g2))))
        self.assertEqual(results.count(ExecutionAdmissionResult.ADMITTED),1); self.assertEqual(results.count("conflict"),1)
        self.assertEqual(
            self._read_rows(self.path, "SELECT count(*) FROM execution_admissions"), [(1,)]
        )

    def test_generation_advance_admission_race_only_serialized_outcomes(self):
        for index in range(8):
            path=self._new_path(f"race-{index}.db")
            with AuthorityStore.initialize_new(path) as store:
                g=store.acquire_generation("S"); store.register_execution_key("K"); store.bind_command_spec_hash("K","H")
            barrier=threading.Barrier(2)
            def admit():
                barrier.wait()
                try:
                    with AuthorityStore.open_existing(path) as s: return s.admit_execution("K","S",g)
                except ControllerGenerationNotCurrentError: return "stale"
            def advance():
                barrier.wait()
                with AuthorityStore.open_existing(path) as s: return s.acquire_generation("S")
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                fa=pool.submit(admit); fg=pool.submit(advance); ar=fa.result(); ng=fg.result()
            self.assertEqual(ng,g+1)
            with AuthorityStore.open_existing(path) as final:
                admission=final.read_execution_admission("K")
                if ar==ExecutionAdmissionResult.ADMITTED: self.assertEqual(admission,ExecutionAdmission("K","S",g))
                else: self.assertEqual(ar,"stale"); self.assertIsNone(admission)

    # Relationship and malformed-state validation.
    def _make_valid_admission(self):
        store,g=self._prepare_bound(); store.admit_execution("K","S",g); store.close(); return g

    def test_admission_orphan_execution_key_fails_closed(self):
        self._make_valid_admission(); c=sqlite3.connect(self.path); c.execute("PRAGMA foreign_keys=OFF"); c.execute("DELETE FROM execution_command_bindings"); c.execute("DELETE FROM execution_keys"); c.commit(); c.close()
        with self.assertRaises(AuthorityStoreMalformedError): AuthorityStore.open_existing(self.path)

    def test_admission_registered_but_unbound_fails_closed(self):
        self._make_valid_admission(); c=sqlite3.connect(self.path); c.execute("DELETE FROM execution_command_bindings"); c.commit(); c.close()
        with self.assertRaises(AuthorityStoreMalformedError): AuthorityStore.open_existing(self.path)

    def test_admission_missing_scope_fails_closed(self):
        self._make_valid_admission(); c=sqlite3.connect(self.path); c.execute("DELETE FROM controller_generations"); c.commit(); c.close()
        with self.assertRaises(AuthorityStoreMalformedError): AuthorityStore.open_existing(self.path)

    def test_admission_malformed_execution_key_fails_closed(self):
        self._make_valid_admission(); c=sqlite3.connect(self.path); c.execute("PRAGMA ignore_check_constraints=ON"); c.execute("UPDATE execution_admissions SET execution_key='' WHERE execution_key='K'"); c.commit(); c.close()
        with self.assertRaises(AuthorityStoreMalformedError): AuthorityStore.open_existing(self.path)

    def test_admission_malformed_scope_fails_closed(self):
        self._make_valid_admission(); c=sqlite3.connect(self.path); c.execute("PRAGMA ignore_check_constraints=ON"); c.execute("UPDATE execution_admissions SET authority_scope='' WHERE execution_key='K'"); c.commit(); c.close()
        with self.assertRaises(AuthorityStoreMalformedError): AuthorityStore.open_existing(self.path)

    def test_admission_generation_zero_fails_closed(self):
        self._make_valid_admission(); c=sqlite3.connect(self.path); c.execute("PRAGMA ignore_check_constraints=ON"); c.execute("UPDATE execution_admissions SET controller_generation=0 WHERE execution_key='K'"); c.commit(); c.close()
        with self.assertRaises(AuthorityStoreMalformedError): AuthorityStore.open_existing(self.path)

    def test_admission_generation_non_integer_fails_closed(self):
        self._make_valid_admission(); c=sqlite3.connect(self.path); c.execute("PRAGMA ignore_check_constraints=ON"); c.execute("UPDATE execution_admissions SET controller_generation='x' WHERE execution_key='K'"); c.commit(); c.close()
        with self.assertRaises(AuthorityStoreMalformedError): AuthorityStore.open_existing(self.path)

    def test_admission_generation_greater_than_current_fails_closed(self):
        g=self._make_valid_admission(); c=sqlite3.connect(self.path); c.execute("PRAGMA ignore_check_constraints=ON"); c.execute("UPDATE execution_admissions SET controller_generation=? WHERE execution_key='K'",(g+1,)); c.commit(); c.close()
        with self.assertRaises(AuthorityStoreMalformedError): AuthorityStore.open_existing(self.path)

    def test_admission_schema_literal_drift_fails_closed(self):
        AuthorityStore.initialize_new(self.path).close(); self._replace_table_definition_literal("execution_admissions","'text' AND authority_scope","'TEXT' AND authority_scope")
        with self.assertRaises(AuthorityStoreMalformedError): AuthorityStore.open_existing(self.path)

    def test_generation_advance_keeps_prior_admission_structurally_valid(self):
        store,g=self._prepare_bound(); self.addCleanup(store.close); store.admit_execution("K","S",g); self.assertEqual(store.acquire_generation("S"),g+1); self.assertEqual(store.read_execution_admission("K"),ExecutionAdmission("K","S",g))

    # Post-open revalidation of malformed admission state.
    def test_post_open_malformed_admission_blocks_read_generation(self): self._post_open_malformed(lambda s:s.read_generation("S"))
    def test_post_open_malformed_admission_blocks_execution_key_exists(self): self._post_open_malformed(lambda s:s.execution_key_exists("K"))
    def test_post_open_malformed_admission_blocks_read_command_hash(self): self._post_open_malformed(lambda s:s.read_command_spec_hash("K"))
    def test_post_open_malformed_admission_blocks_read_admission(self): self._post_open_malformed(lambda s:s.read_execution_admission("K"))
    def test_post_open_malformed_admission_blocks_admit(self): self._post_open_malformed(lambda s:s.admit_execution("K","S",1))
    def test_post_open_malformed_admission_blocks_acquire_generation(self): self._post_open_malformed(lambda s:s.acquire_generation("S"))
    def test_post_open_malformed_admission_blocks_register_key(self): self._post_open_malformed(lambda s:s.register_execution_key("K2"))
    def test_post_open_malformed_admission_blocks_bind_hash(self): self._post_open_malformed(lambda s:s.bind_command_spec_hash("K","H"))

    def _post_open_malformed(self, operation):
        store,g=self._prepare_bound(); self.addCleanup(store.close); store.admit_execution("K","S",g)
        c=sqlite3.connect(self.path); c.execute("PRAGMA ignore_check_constraints=ON"); c.execute("UPDATE execution_admissions SET authority_scope='' WHERE execution_key='K'"); c.commit(); c.close()
        with self.assertRaises(AuthorityStoreMalformedError): operation(store)

    # Commit / rollback cleanup contracts for U1E.
    def test_admission_preserves_authority_scope_runtime_semantics(self):
        class Scope(str):
            pass
        with AuthorityStore.initialize_new(self.path) as store:
            scope = Scope("S")
            generation = store.acquire_generation(scope)
            store.register_execution_key("K")
            store.bind_command_spec_hash("K", "H")
            self.assertEqual(
                store.admit_execution("K", scope, generation),
                ExecutionAdmissionResult.ADMITTED,
            )
            self.assertEqual(
                store.read_execution_admission("K"),
                ExecutionAdmission("K", "S", generation),
            )

    def test_v3_to_v4_rollback_failure_requires_explicit_inspection(self):
        self._create_v3_store()
        connection_holder = {}
        real_connect = AuthorityStore._connect_rw

        def connect(path):
            connection = real_connect(path)
            connection_holder["connection"] = connection
            return connection

        with mock.patch.object(AuthorityStore, "_connect_rw", side_effect=connect):
            with mock.patch.object(
                AuthorityStore,
                "_validate_v4_store",
                side_effect=AuthorityStoreMalformedError("injected validation failure"),
            ):
                with mock.patch.object(
                    AuthorityStore,
                    "_rollback_migration_if_needed",
                    side_effect=AuthorityStoreError(
                        "v3-to-v4 migration rollback failed; durable outcome requires inspection"
                    ),
                ):
                    with self.assertRaisesRegex(AuthorityStoreError, "requires inspection"):
                        AuthorityStore.migrate_v3_to_v4(self.path)

    def test_admission_idempotency_commit_failure_returns_no_success_result(self):
        store, generation = self._prepare_bound()
        self.addCleanup(store.close)
        self.assertEqual(
            store.admit_execution("K", "S", generation),
            ExecutionAdmissionResult.ADMITTED,
        )
        self._deny_commit(store)
        try:
            with self.assertRaises(AuthorityStoreError):
                store.admit_execution("K", "S", generation)
        finally:
            store._connection.set_authorizer(None)
        self.assertEqual(
            store.read_execution_admission("K"),
            ExecutionAdmission("K", "S", generation),
        )

    def test_admission_commit_failure_returns_no_success_result(self):
        store,g=self._prepare_bound(); self.addCleanup(store.close); self._deny_commit(store)
        try:
            with self.assertRaises(AuthorityStoreError): store.admit_execution("K","S",g)
        finally: store._connection.set_authorizer(None)
        self.assertIsNone(store.read_execution_admission("K"))

    def test_admission_rollback_failure_poisons_store(self):
        store,g=self._prepare_bound(); self.addCleanup(store.close); c=sqlite3.connect(self.path); c.execute("CREATE TABLE unexpected(x)"); c.commit(); c.close()
        with mock.patch.object(AuthorityStore,"_rollback_transaction",side_effect=sqlite3.OperationalError("boom")):
            with self.assertRaises(AuthorityStoreError): store.admit_execution("K","S",g)
        self.assertTrue(store._poisoned); self.assertIsNone(store._connection)

    def test_admission_read_commit_failure_returns_no_observation(self):
        store,g=self._prepare_bound(); self.addCleanup(store.close); store.admit_execution("K","S",g); self._deny_commit(store)
        try:
            with self.assertRaises(AuthorityStoreError): store.read_execution_admission("K")
        finally: store._connection.set_authorizer(None)
        self.assertEqual(store.read_execution_admission("K"),ExecutionAdmission("K","S",g))

    def test_admission_read_rollback_failure_poisons_store(self):
        store,g=self._prepare_bound(); self.addCleanup(store.close); store.admit_execution("K","S",g); c=sqlite3.connect(self.path); c.execute("CREATE TABLE unexpected(x)"); c.commit(); c.close()
        with mock.patch.object(AuthorityStore,"_rollback_transaction",side_effect=sqlite3.OperationalError("boom")):
            with self.assertRaises(AuthorityStoreError): store.read_execution_admission("K")
        self.assertTrue(store._poisoned); self.assertIsNone(store._connection)


if __name__ == "__main__":
    unittest.main()
