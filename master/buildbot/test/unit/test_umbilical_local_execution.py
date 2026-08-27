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
from unittest import mock

import buildbot.umbilical_authority as authority
import buildbot.umbilical_local_execution as local_execution
from buildbot.umbilical_authority import AuthorityStore
from buildbot.umbilical_authority import AuthorityStoreError
from buildbot.umbilical_authority import AuthorityStoreMalformedError
from buildbot.umbilical_authority import AuthorityStoreMigrationRequiredError
from buildbot.umbilical_authority import CommandSpecHashMismatchError
from buildbot.umbilical_authority import ControllerGenerationNotCurrentError
from buildbot.umbilical_authority import ExecutionAdmissionMismatchError
from buildbot.umbilical_authority import ExecutionAdmissionMissingError
from buildbot.umbilical_authority import ExecutionKeyNotCommandBoundError
from buildbot.umbilical_authority import ExecutionKeyNotRegisteredError
from buildbot.umbilical_authority import ExecutionLaunchAlreadyClaimedError
from buildbot.umbilical_authority import ExecutionLaunchState
from buildbot.umbilical_authority import ExecutionLaunchStateError
from buildbot.umbilical_local_execution import InvalidLocalCommandSpecError
from buildbot.umbilical_local_execution import LocalCommandSpec
from buildbot.umbilical_local_execution import SubprocessLocalProcessLauncher
from buildbot.umbilical_local_execution import canonical_command_spec_bytes
from buildbot.umbilical_local_execution import command_spec_hash
from buildbot.umbilical_local_execution import execute_local_command


class RecordingLauncher:
    def __init__(self, store, execution_key="K", result=0, error=None):
        self.store = store
        self.execution_key = execution_key
        self.result = result
        self.error = error
        self.calls = []

    def launch(self, command_spec):
        launch = self.store.read_execution_launch(self.execution_key)
        if launch is None or launch.state is not ExecutionLaunchState.UNKNOWN:
            raise AssertionError("physical launcher entered before durable UNKNOWN")
        self.calls.append(command_spec)
        if self.error is not None:
            raise self.error
        return self.result


class U1FLocalExecutionTests(unittest.TestCase):
    def setUp(self):
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self.root = Path(self._temporary_directory.name)
        self.path = self.root / "authority.sqlite3"

    def _spec(
        self,
        *,
        executable=None,
        argv=None,
        working_directory=None,
        environment=None,
        timeout_seconds=30,
    ):
        executable = str(self.root / "tool.exe") if executable is None else executable
        argv = (executable, "alpha", "beta") if argv is None else argv
        working_directory = str(self.root) if working_directory is None else working_directory
        environment = {"A": "1", "B": "2"} if environment is None else environment
        return LocalCommandSpec.snapshot(
            executable=executable,
            argv=argv,
            working_directory=working_directory,
            environment=environment,
            timeout_seconds=timeout_seconds,
        )

    def _prepare(self, *, key="K", scope="S", spec=None):
        spec = self._spec() if spec is None else spec
        store = AuthorityStore.initialize_new(self.path)
        generation = store.acquire_generation(scope)
        store.register_execution_key(key)
        command_hash = command_spec_hash(spec)
        store.bind_command_spec_hash(key, command_hash)
        store.admit_execution(key, scope, generation)
        return store, generation, spec, command_hash

    def _patched_launcher(self, recorder):
        def launch(_launcher, command_spec):
            return recorder.launch(command_spec)

        return mock.patch.object(
            SubprocessLocalProcessLauncher,
            "launch",
            autospec=True,
            side_effect=launch,
        )

    def _create_v4_store(self, *, with_authority=False):
        connection = sqlite3.connect(self.path, isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(authority._CREATE_GENERATIONS_SQL)
            connection.execute(authority._CREATE_EXECUTION_KEYS_SQL)
            connection.execute(authority._CREATE_EXECUTION_COMMAND_BINDINGS_SQL)
            connection.execute(authority._CREATE_EXECUTION_ADMISSIONS_SQL)
            if with_authority:
                connection.execute("INSERT INTO controller_generations VALUES ('S', 1)")
                connection.execute("INSERT INTO execution_keys VALUES ('K')")
                connection.execute(
                    "INSERT INTO execution_command_bindings VALUES ('K', 'H')"
                )
                connection.execute(
                    "INSERT INTO execution_admissions VALUES ('K', 'S', 1)"
                )
            connection.execute("PRAGMA user_version = 4")
            connection.execute("COMMIT")
        finally:
            connection.close()

    # Command identity and immutable caller snapshot.
    def test_command_spec_hash_is_deterministic(self):
        spec = self._spec()
        self.assertEqual(command_spec_hash(spec), command_spec_hash(spec))
        self.assertTrue(command_spec_hash(spec).startswith("ucsh1:sha256:"))

    def test_changed_executable_and_argv_change_hash(self):
        baseline = self._spec()
        other_executable = str(self.root / "other.exe")
        variants = (
            self._spec(
                executable=other_executable,
                argv=(other_executable, "alpha", "beta"),
            ),
            self._spec(argv=(baseline.executable, "alpha", "gamma")),
        )
        for variant in variants:
            self.assertNotEqual(command_spec_hash(baseline), command_spec_hash(variant))

    def test_cwd_environment_and_timeout_are_command_identity(self):
        baseline = self._spec()
        other_directory = self.root / "other"
        other_directory.mkdir()
        variants = (
            self._spec(working_directory=str(other_directory)),
            self._spec(environment={"A": "1", "B": "3"}),
            self._spec(timeout_seconds=31),
        )
        for variant in variants:
            self.assertNotEqual(command_spec_hash(baseline), command_spec_hash(variant))

    def test_environment_mapping_order_is_canonical(self):
        first = self._spec(environment={"A": "1", "B": "2"})
        second = self._spec(environment={"B": "2", "A": "1"})
        self.assertEqual(first.environment, second.environment)
        self.assertEqual(command_spec_hash(first), command_spec_hash(second))

    def test_length_framing_prevents_ambiguous_argv_collision(self):
        executable = str(self.root / "tool.exe")
        first = self._spec(argv=(executable, "ab", "c"))
        second = self._spec(argv=(executable, "a", "bc"))
        self.assertNotEqual(canonical_command_spec_bytes(first), canonical_command_spec_bytes(second))
        self.assertNotEqual(command_spec_hash(first), command_spec_hash(second))

    def test_strict_utf8_rejects_surrogate(self):
        executable = str(self.root / "tool.exe")
        with self.assertRaises(InvalidLocalCommandSpecError):
            self._spec(argv=(executable, chr(0xD800)))
        with self.assertRaises(InvalidLocalCommandSpecError):
            self._spec(environment={"BAD": chr(0xD800)})

    def test_caller_mutation_after_snapshot_cannot_change_command(self):
        executable = str(self.root / "tool.exe")
        argv = [executable, "before"]
        environment = {"A": "before"}
        spec = self._spec(argv=argv, environment=environment)
        argv[1] = "after"
        argv.append("new")
        environment["A"] = "after"
        environment["B"] = "new"
        self.assertEqual(spec.argv, (executable, "before"))
        self.assertEqual(spec.environment, (("A", "before"),))

    def test_subprocess_adapter_uses_exact_fields_without_shell(self):
        spec = self._spec()
        completed = mock.Mock(returncode=7)
        with mock.patch.object(local_execution.subprocess, "run", return_value=completed) as run:
            self.assertEqual(SubprocessLocalProcessLauncher().launch(spec), 7)
        run.assert_called_once_with(
            spec.argv,
            executable=spec.executable,
            cwd=spec.working_directory,
            env=dict(spec.environment),
            timeout=spec.timeout_seconds,
            stdin=local_execution.subprocess.DEVNULL,
            check=False,
            shell=False,
            close_fds=True,
        )

    # Durable authority prerequisites and at-most-once claiming.
    def test_unregistered_execution_key_cannot_launch(self):
        with AuthorityStore.initialize_new(self.path) as store:
            generation = store.acquire_generation("S")
            with self.assertRaises(ExecutionKeyNotRegisteredError):
                store.claim_execution_launch("K", "S", generation, "H")
            self.assertEqual(
                store._connection.execute("SELECT count(*) FROM execution_launches").fetchone(),
                (0,),
            )

    def test_unbound_execution_key_cannot_launch(self):
        with AuthorityStore.initialize_new(self.path) as store:
            generation = store.acquire_generation("S")
            store.register_execution_key("K")
            with self.assertRaises(ExecutionKeyNotCommandBoundError):
                store.claim_execution_launch("K", "S", generation, "H")

    def test_missing_admission_cannot_launch(self):
        with AuthorityStore.initialize_new(self.path) as store:
            generation = store.acquire_generation("S")
            store.register_execution_key("K")
            store.bind_command_spec_hash("K", "H")
            with self.assertRaises(ExecutionAdmissionMissingError):
                store.claim_execution_launch("K", "S", generation, "H")

    def test_wrong_scope_cannot_launch(self):
        store, generation, _spec, command_hash = self._prepare()
        self.addCleanup(store.close)
        other_generation = store.acquire_generation("T")
        self.assertEqual(other_generation, generation)
        with self.assertRaises(ExecutionAdmissionMismatchError):
            store.claim_execution_launch("K", "T", other_generation, command_hash)
        self.assertIsNone(store.read_execution_launch("K"))

    def test_stale_generation_cannot_launch(self):
        store, generation, _spec, command_hash = self._prepare()
        self.addCleanup(store.close)
        store.acquire_generation("S")
        with self.assertRaises(ControllerGenerationNotCurrentError):
            store.claim_execution_launch("K", "S", generation, command_hash)
        self.assertIsNone(store.read_execution_launch("K"))

    def test_concrete_command_must_match_u1d_binding(self):
        original = self._spec()
        store, generation, _spec, _hash = self._prepare(spec=original)
        self.addCleanup(store.close)
        changed = self._spec(argv=(original.executable, "different"))
        recorder = RecordingLauncher(store)
        with self._patched_launcher(recorder):
            with self.assertRaises(CommandSpecHashMismatchError):
                execute_local_command(
                    store,
                    execution_key="K",
                    authority_scope="S",
                    controller_generation=generation,
                    command_spec=changed,
                )
        self.assertEqual(recorder.calls, [])
        self.assertIsNone(store.read_execution_launch("K"))

    def test_first_claim_succeeds_and_duplicate_is_rejected(self):
        store, generation, _spec, command_hash = self._prepare()
        self.addCleanup(store.close)
        launch = store.claim_execution_launch("K", "S", generation, command_hash)
        self.assertEqual(launch.state, ExecutionLaunchState.INTENT)
        with self.assertRaises(ExecutionLaunchAlreadyClaimedError):
            store.claim_execution_launch("K", "S", generation, command_hash)

    def test_concurrent_claims_have_exactly_one_winner(self):
        store, generation, _spec, command_hash = self._prepare()
        store.close()

        def claim(_):
            try:
                with AuthorityStore.open_existing(self.path) as contender:
                    contender.claim_execution_launch("K", "S", generation, command_hash)
                return "claimed"
            except ExecutionLaunchAlreadyClaimedError:
                return "duplicate"

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, range(2)))
        self.assertEqual(results.count("claimed"), 1)
        self.assertEqual(results.count("duplicate"), 1)

    def test_duplicate_after_unknown_and_terminal_is_rejected(self):
        for exit_code in (None, 0, 17):
            self.path = self.root / f"state-{exit_code}.sqlite3"
            store, generation, _spec, command_hash = self._prepare()
            store.claim_execution_launch("K", "S", generation, command_hash)
            store.mark_execution_launch_unknown("K", command_hash)
            if exit_code is not None:
                store.record_execution_terminal_result("K", command_hash, exit_code)
            with self.assertRaises(ExecutionLaunchAlreadyClaimedError):
                store.claim_execution_launch("K", "S", generation, command_hash)
            store.close()

    def test_terminal_result_is_durable_exactly_once(self):
        store, generation, _spec, command_hash = self._prepare()
        self.addCleanup(store.close)
        store.claim_execution_launch("K", "S", generation, command_hash)
        store.mark_execution_launch_unknown("K", command_hash)
        terminal = store.record_execution_terminal_result("K", command_hash, 0)
        self.assertEqual(terminal.state, ExecutionLaunchState.TERMINAL)
        self.assertEqual(terminal.exit_code, 0)
        with self.assertRaises(ExecutionLaunchStateError):
            store.record_execution_terminal_result("K", command_hash, 0)

    # Ordering and conservative UNKNOWN semantics.
    def test_launcher_enters_only_after_durable_unknown(self):
        store, generation, spec, _hash = self._prepare()
        self.addCleanup(store.close)
        recorder = RecordingLauncher(store, result=0)
        with self._patched_launcher(recorder):
            result = execute_local_command(
                store,
                execution_key="K",
                authority_scope="S",
                controller_generation=generation,
                command_spec=spec,
            )
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(recorder.calls, [spec])
        self.assertEqual(store.read_execution_launch("K").state, ExecutionLaunchState.TERMINAL)

    def test_failure_before_claim_does_not_consume_authority(self):
        original = self._spec()
        store, generation, _spec, _hash = self._prepare(spec=original)
        self.addCleanup(store.close)
        changed = self._spec(argv=(original.executable, "wrong"))
        recorder = RecordingLauncher(store)
        with self._patched_launcher(recorder):
            with self.assertRaises(CommandSpecHashMismatchError):
                execute_local_command(
                    store,
                    execution_key="K",
                    authority_scope="S",
                    controller_generation=generation,
                    command_spec=changed,
                )
        self.assertEqual(recorder.calls, [])
        self.assertIsNone(store.read_execution_launch("K"))

    def test_failure_after_intent_never_launches_or_grants_retry(self):
        store, generation, spec, _hash = self._prepare()
        self.addCleanup(store.close)
        recorder = RecordingLauncher(store)
        with mock.patch.object(
            store,
            "mark_execution_launch_unknown",
            side_effect=AuthorityStoreError("injected post-intent failure"),
        ):
            with self._patched_launcher(recorder):
                with self.assertRaises(AuthorityStoreError):
                    execute_local_command(
                        store,
                        execution_key="K",
                        authority_scope="S",
                        controller_generation=generation,
                        command_spec=spec,
                    )
        self.assertEqual(recorder.calls, [])
        self.assertEqual(store.read_execution_launch("K").state, ExecutionLaunchState.INTENT)
        with self.assertRaises(ExecutionLaunchAlreadyClaimedError):
            store.claim_execution_launch("K", "S", generation, command_spec_hash(spec))

    def test_process_launch_exception_remains_unknown_and_no_retry(self):
        store, generation, spec, command_hash = self._prepare()
        self.addCleanup(store.close)
        recorder = RecordingLauncher(store, error=OSError("uncertain process creation"))
        with self._patched_launcher(recorder):
            with self.assertRaises(OSError):
                execute_local_command(
                    store,
                    execution_key="K",
                    authority_scope="S",
                    controller_generation=generation,
                    command_spec=spec,
                )
        self.assertEqual(len(recorder.calls), 1)
        self.assertEqual(store.read_execution_launch("K").state, ExecutionLaunchState.UNKNOWN)
        with self.assertRaises(ExecutionLaunchAlreadyClaimedError):
            store.claim_execution_launch("K", "S", generation, command_hash)

    def test_post_launch_durable_failure_remains_unknown_and_no_retry(self):
        store, generation, spec, command_hash = self._prepare()
        self.addCleanup(store.close)
        recorder = RecordingLauncher(store, result=0)
        with mock.patch.object(
            store,
            "record_execution_terminal_result",
            side_effect=AuthorityStoreError("injected terminal write failure"),
        ):
            with self._patched_launcher(recorder):
                with self.assertRaises(AuthorityStoreError):
                    execute_local_command(
                        store,
                        execution_key="K",
                        authority_scope="S",
                        controller_generation=generation,
                        command_spec=spec,
                    )
        self.assertEqual(len(recorder.calls), 1)
        self.assertEqual(store.read_execution_launch("K").state, ExecutionLaunchState.UNKNOWN)
        with self.assertRaises(ExecutionLaunchAlreadyClaimedError):
            store.claim_execution_launch("K", "S", generation, command_hash)

    def test_generation_rollover_before_claim_blocks_side_effect(self):
        store, generation, spec, _hash = self._prepare()
        self.addCleanup(store.close)
        store.acquire_generation("S")
        recorder = RecordingLauncher(store)
        with self._patched_launcher(recorder):
            with self.assertRaises(ControllerGenerationNotCurrentError):
                execute_local_command(
                    store,
                    execution_key="K",
                    authority_scope="S",
                    controller_generation=generation,
                    command_spec=spec,
                )
        self.assertEqual(recorder.calls, [])
        self.assertIsNone(store.read_execution_launch("K"))

    def test_consequential_path_never_uses_observation_generation_api(self):
        store, generation, spec, _hash = self._prepare()
        self.addCleanup(store.close)
        recorder = RecordingLauncher(store)
        with mock.patch.object(
            store,
            "is_current_generation",
            side_effect=AssertionError("observation API must not fence launch"),
        ):
            with self._patched_launcher(recorder):
                execute_local_command(
                    store,
                    execution_key="K",
                    authority_scope="S",
                    controller_generation=generation,
                    command_spec=spec,
                )
        self.assertEqual(len(recorder.calls), 1)

    def test_mutating_original_containers_after_binding_does_not_change_launch(self):
        executable = str(self.root / "tool.exe")
        argv = [executable, "stable"]
        environment = {"A": "stable"}
        spec = self._spec(argv=argv, environment=environment)
        store, generation, _spec, _hash = self._prepare(spec=spec)
        self.addCleanup(store.close)
        argv[1] = "mutated"
        environment["A"] = "mutated"
        recorder = RecordingLauncher(store)
        with self._patched_launcher(recorder):
            execute_local_command(
                store,
                execution_key="K",
                authority_scope="S",
                controller_generation=generation,
                command_spec=spec,
            )
        self.assertEqual(recorder.calls[0].argv, (executable, "stable"))
        self.assertEqual(recorder.calls[0].environment, (("A", "stable"),))

    # Exact v5 schema and explicit v4 -> v5 migration.
    def test_new_store_creates_exact_v5_schema(self):
        with AuthorityStore.initialize_new(self.path) as store:
            self.assertEqual(store._connection.execute("PRAGMA user_version").fetchone(), (5,))
            self.assertEqual(
                store._connection.execute(
                    "SELECT type, name FROM sqlite_schema "
                    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
                ).fetchall(),
                [
                    ("table", "controller_generations"),
                    ("table", "execution_admissions"),
                    ("table", "execution_command_bindings"),
                    ("table", "execution_keys"),
                    ("table", "execution_launches"),
                ],
            )
            self.assertEqual(store._connection.execute("SELECT * FROM execution_launches").fetchall(), [])

    def test_execution_launch_schema_literal_is_exact(self):
        with AuthorityStore.initialize_new(self.path) as store:
            sql = store._connection.execute(
                "SELECT sql FROM sqlite_schema WHERE name='execution_launches'"
            ).fetchone()[0]
            self.assertEqual(sql, authority._CREATE_EXECUTION_LAUNCHES_SQL.lstrip("\n"))

    def test_valid_v4_requires_explicit_migration_without_mutation(self):
        self._create_v4_store(with_authority=True)
        with self.assertRaises(AuthorityStoreMigrationRequiredError):
            AuthorityStore.open_existing(self.path)
        connection = sqlite3.connect(self.path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (4,))
            self.assertEqual(
                connection.execute("SELECT * FROM execution_admissions").fetchall(),
                [("K", "S", 1)],
            )
            self.assertEqual(
                connection.execute(
                    "SELECT name FROM sqlite_schema WHERE name='execution_launches'"
                ).fetchall(),
                [],
            )
        finally:
            connection.close()

    def test_v4_to_v5_preserves_authority_and_invents_zero_launches(self):
        self._create_v4_store(with_authority=True)
        AuthorityStore.migrate_v4_to_v5(self.path)
        with AuthorityStore.open_existing(self.path) as store:
            self.assertEqual(store._connection.execute("PRAGMA user_version").fetchone(), (5,))
            self.assertEqual(store.read_generation("S"), 1)
            self.assertTrue(store.execution_key_exists("K"))
            self.assertEqual(store.read_command_spec_hash("K"), "H")
            self.assertEqual(store.read_execution_admission("K").authority_scope, "S")
            self.assertIsNone(store.read_execution_launch("K"))

    def test_malformed_v4_and_unexpected_objects_fail_closed(self):
        self._create_v4_store()
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("CREATE TABLE unexpected(value INTEGER)")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.migrate_v4_to_v5(self.path)

    def test_malformed_launch_state_fails_closed(self):
        store, generation, _spec, command_hash = self._prepare()
        store.claim_execution_launch("K", "S", generation, command_hash)
        store.close()
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute(
                "UPDATE execution_launches SET launch_state='retryable' "
                "WHERE execution_key='K'"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_launch_cross_table_binding_corruption_fails_closed(self):
        store, generation, _spec, command_hash = self._prepare()
        store.claim_execution_launch("K", "S", generation, command_hash)
        store.close()
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                "UPDATE execution_command_bindings SET command_spec_hash='different' "
                "WHERE execution_key='K'"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_unexpected_v5_persisted_object_fails_closed(self):
        AuthorityStore.initialize_new(self.path).close()
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("CREATE VIEW unexpected AS SELECT * FROM execution_launches")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(AuthorityStoreMalformedError):
            AuthorityStore.open_existing(self.path)

    def test_v4_to_v5_commit_uncertainty_remains_conservative(self):
        self._create_v4_store()
        real_connect = AuthorityStore._connect_rw

        class Proxy:
            def __init__(self, connection):
                self._connection = connection

            def __getattr__(self, name):
                return getattr(self._connection, name)

            @property
            def in_transaction(self):
                return self._connection.in_transaction

            def execute(self, sql, *args, **kwargs):
                if sql == "COMMIT":
                    raise sqlite3.OperationalError("injected commit failure")
                return self._connection.execute(sql, *args, **kwargs)

            def close(self):
                self._connection.close()

        def connect(path):
            return Proxy(real_connect(path))

        with mock.patch.object(AuthorityStore, "_connect_rw", side_effect=connect):
            with self.assertRaisesRegex(AuthorityStoreError, "outcome is uncertain"):
                AuthorityStore.migrate_v4_to_v5(self.path)


if __name__ == "__main__":
    unittest.main()
