# This file is part of Umbilical.
#
# Umbilical is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, version 2.

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import buildbot.umbilical_workgraph_client as client
import buildbot.umbilical_workgraph_validation as validation
from buildbot.umbilical_authority import AuthorityStore
from buildbot.umbilical_authority import AuthorityStoreExistsError
from buildbot.umbilical_authority import AuthorityStoreMissingError
from buildbot.umbilical_authority import ExecutionLaunchState
from buildbot.umbilical_local_execution import SubprocessLocalProcessLauncher

_REVISION_A = "663a98f92709a30352bc5a65249a660481c664d9"
_REVISION_B = "a" * 40
_TREE_A = "b" * 40
_TREE_B = "c" * 40
_CONTRACT_TREE_A = "d" * 40
_CONTRACT_TREE_B = "e" * 40


class WorkGraphClientTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.deployment_root = self.root / "deployment"
        self.authority_db = self.deployment_root / "authority.sqlite"
        self.source = self.root / "source"
        self.source.mkdir()
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()

    def _request(self, revision=_REVISION_A):
        return client.WorkGraphRequest(
            revision=revision,
            source=self.source,
            timeout_seconds=30,
        )

    @staticmethod
    def _target(revision=_REVISION_A, tree=_TREE_A):
        return client.VerifiedWorkGraphTarget("4i7/WorkGraph", 1338331328, revision, tree)

    def _initialize(self):
        with mock.patch.object(client, "_deployment_root", return_value=self.deployment_root):
            return client.initialize_workgraph_client()

    def _run(self, request, publisher, *, launcher=0, target=None):
        target = (
            self._target(request.revision, _TREE_A if request.revision == _REVISION_A else _TREE_B)
            if target is None
            else target
        )
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test-token"}), mock.patch.object(
            client, "_deployment_root", return_value=self.deployment_root
        ), mock.patch.object(
            client, "verify_workgraph_target", return_value=target
        ), mock.patch.object(
            client, "prepare_exact_checkout", return_value=self.checkout
        ), mock.patch.object(
            client, "_contract_tree", return_value=_CONTRACT_TREE_A
        ), mock.patch.object(client, "_run_integrity_preflight"), mock.patch.object(
            SubprocessLocalProcessLauncher, "launch", return_value=launcher
        ) as launch:
            result = client.run_workgraph_client(request, publisher=publisher)
        return result, launch

    def test_authenticated_target_captures_exact_commit_and_tree(self):
        repository = {"full_name": "4i7/WorkGraph", "id": 1338331328}
        commit = {"sha": _REVISION_A, "commit": {"tree": {"sha": _TREE_A}}}
        with mock.patch.object(client, "_github_json", side_effect=(repository, commit)):
            self.assertEqual(client.verify_workgraph_target(_REVISION_A, "token"), self._target())

    def test_authenticated_target_rejects_repository_name_or_id_drift(self):
        for repository in (
            {"full_name": "other/WorkGraph", "id": 1338331328},
            {"full_name": "4i7/WorkGraph", "id": 1},
        ):
            with self.subTest(repository=repository), mock.patch.object(
                client, "_github_json", return_value=repository
            ):
                with self.assertRaises(client.WorkGraphClientError):
                    client.verify_workgraph_target(_REVISION_A, "token")

    def test_absent_or_mismatched_remote_commit_is_rejected_before_store_open(self):
        request = self._request()
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test-token"}), mock.patch.object(
            client, "verify_workgraph_target", side_effect=client.WorkGraphClientError("missing")
        ), mock.patch.object(client, "_open_store") as open_store:
            with self.assertRaises(client.WorkGraphClientError):
                client.run_workgraph_client(request)
        open_store.assert_not_called()

    def test_init_creates_one_fixed_store_and_generation(self):
        self.assertEqual(self._initialize(), 1)
        with AuthorityStore.open_existing(self.authority_db) as store:
            self.assertEqual(store.read_generation(client._AUTHORITY_SCOPE), 1)
        with self.assertRaises(AuthorityStoreExistsError):
            self._initialize()

    def test_normal_run_requires_existing_fixed_store(self):
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test-token"}), mock.patch.object(
            client, "_deployment_root", return_value=self.deployment_root
        ), mock.patch.object(
            client, "verify_workgraph_target", return_value=self._target()
        ), mock.patch.object(client, "_contract_tree", return_value=_CONTRACT_TREE_A):
            with self.assertRaises(AuthorityStoreMissingError):
                client.run_workgraph_client(self._request())

    def test_authority_store_inside_disposable_root_is_rejected(self):
        with mock.patch.object(client, "_deployment_root", return_value=self.deployment_root):
            with self.assertRaises(client.WorkGraphClientError):
                client._assert_authority_store_outside_checkouts(
                    self.deployment_root / "checkouts" / "authority.sqlite"
                )

    def test_command_binds_expected_remote_commit_and_tree(self):
        target = self._target()
        runtime = Path(sys.executable).resolve()
        with mock.patch.object(
            client, "_deployment_root", return_value=self.deployment_root
        ), mock.patch.object(client, "_current_python_executable", return_value=runtime):
            spec = client.build_command_spec(
                self._request(), target, self.checkout, _CONTRACT_TREE_A
            )
            same_spec = client.build_command_spec(
                self._request(), target, self.checkout, _CONTRACT_TREE_A
            )
        self.assertIn(target.revision, spec.argv)
        self.assertIn(target.tree_sha, spec.argv)
        self.assertIn(_CONTRACT_TREE_A, spec.argv)
        self.assertEqual(spec.executable, str(runtime))
        self.assertEqual(spec.argv[0], str(runtime))
        self.assertNotIn("GH_TOKEN", dict(spec.environment))
        self.assertEqual(client.command_spec_hash(spec), client.command_spec_hash(same_spec))

    def test_contract_identity_is_deterministic_and_changes_with_tree(self):
        first = client.validation_contract_id(_CONTRACT_TREE_A)
        self.assertEqual(first, client.validation_contract_id(_CONTRACT_TREE_A))
        self.assertNotEqual(first, client.validation_contract_id(_CONTRACT_TREE_B))
        keys = {
            tree: client.derive_execution_key(
                repository_identity="github-repository-id:1338331328",
                subject_identity=client._SUBJECT,
                revision_identity=_REVISION_A,
                causal_root=client.validation_contract_id(tree),
            )
            for tree in (_CONTRACT_TREE_A, _CONTRACT_TREE_B)
        }
        self.assertNotEqual(keys[_CONTRACT_TREE_A], keys[_CONTRACT_TREE_B])

    def test_production_client_contains_no_manual_causal_root_versions(self):
        source = Path(client.__file__).read_text(encoding="utf-8")
        for version in ("validation-v1", "validation-v2", "validation-v3"):
            self.assertNotIn(version, source)

    def test_dirty_contract_fails_before_authority_store_open(self):
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test-token"}), mock.patch.object(
            client, "verify_workgraph_target", return_value=self._target()
        ), mock.patch.object(
            client,
            "_contract_tree",
            side_effect=client.WorkGraphClientError("contract is dirty"),
        ), mock.patch.object(client, "_open_store") as open_store:
            with self.assertRaisesRegex(client.WorkGraphClientError, "contract is dirty"):
                client.run_workgraph_client(self._request())
        open_store.assert_not_called()

    def test_preflight_and_authoritative_specs_share_the_execution_contract(self):
        target = self._target()
        runtime = Path(sys.executable).resolve()
        with mock.patch.object(
            client, "_deployment_root", return_value=self.deployment_root
        ), mock.patch.object(client, "_current_python_executable", return_value=runtime):
            authoritative = client.build_command_spec(
                self._request(), target, self.checkout, _CONTRACT_TREE_A
            )
            preflight = client.build_command_spec(
                self._request(),
                target,
                self.checkout,
                _CONTRACT_TREE_A,
                integrity_only=True,
            )
        self.assertEqual(preflight.argv[:-1], authoritative.argv)
        self.assertEqual(preflight.argv[-1], "--integrity-only")
        self.assertEqual(preflight.executable, authoritative.executable)
        self.assertEqual(preflight.working_directory, authoritative.working_directory)
        self.assertEqual(preflight.environment, authoritative.environment)
        self.assertEqual(preflight.timeout_seconds, authoritative.timeout_seconds)

    def test_preflight_success_and_failure_consume_no_authority(self):
        self._initialize()
        spec = mock.Mock()
        for exit_code in (0, 2):
            with self.subTest(exit_code=exit_code), mock.patch.object(
                SubprocessLocalProcessLauncher, "launch", return_value=exit_code
            ):
                if exit_code == 0:
                    client._run_integrity_preflight(spec)
                else:
                    with self.assertRaises(client.WorkGraphClientError):
                        client._run_integrity_preflight(spec)
            with AuthorityStore.open_existing(self.authority_db) as store:
                self.assertFalse(store.execution_key_exists("preflight-only"))

    def test_run_preflight_failure_leaves_execution_unregistered(self):
        self._initialize()
        target = self._target()
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test-token"}), mock.patch.object(
            client, "_deployment_root", return_value=self.deployment_root
        ), mock.patch.object(
            client, "verify_workgraph_target", return_value=target
        ), mock.patch.object(
            client, "_contract_tree", return_value=_CONTRACT_TREE_A
        ), mock.patch.object(
            client, "prepare_exact_checkout", return_value=self.checkout
        ), mock.patch.object(
            client,
            "_run_integrity_preflight",
            side_effect=client.WorkGraphClientError("preflight failed"),
        ), mock.patch.object(client, "execute_local_command") as execute:
            with self.assertRaisesRegex(client.WorkGraphClientError, "preflight failed"):
                client.run_workgraph_client(self._request(), publisher=mock.Mock())
        execution_key = client.derive_execution_key(
            repository_identity="github-repository-id:1338331328",
            subject_identity=client._SUBJECT,
            revision_identity=_REVISION_A,
            causal_root=client.validation_contract_id(_CONTRACT_TREE_A),
        )
        with AuthorityStore.open_existing(self.authority_db) as store:
            self.assertFalse(store.execution_key_exists(execution_key))
        execute.assert_not_called()

    def test_contract_tree_is_rechecked_after_preflight_before_registration(self):
        self._initialize()
        target = self._target()
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test-token"}), mock.patch.object(
            client, "_deployment_root", return_value=self.deployment_root
        ), mock.patch.object(
            client, "verify_workgraph_target", return_value=target
        ), mock.patch.object(
            client, "_contract_tree", side_effect=(_CONTRACT_TREE_A, _CONTRACT_TREE_B)
        ), mock.patch.object(
            client, "prepare_exact_checkout", return_value=self.checkout
        ), mock.patch.object(client, "_run_integrity_preflight"), mock.patch.object(
            client, "execute_local_command"
        ) as execute:
            with self.assertRaisesRegex(client.WorkGraphClientError, "changed after preflight"):
                client.run_workgraph_client(self._request(), publisher=mock.Mock())
        execution_key = client.derive_execution_key(
            repository_identity="github-repository-id:1338331328",
            subject_identity=client._SUBJECT,
            revision_identity=_REVISION_A,
            causal_root=client.validation_contract_id(_CONTRACT_TREE_A),
        )
        with AuthorityStore.open_existing(self.authority_db) as store:
            self.assertFalse(store.execution_key_exists(execution_key))
        execute.assert_not_called()

    def test_deployment_paths_and_command_hash_ignore_environment_drift(self):
        known_local_app_data = self.root / "known-local-app-data"
        runtime = Path(sys.executable).resolve()
        key = "stable-execution-key"
        target = self._target()
        values = (
            {
                "LOCALAPPDATA": "C:/root-a",
                "USERPROFILE": "C:/user-a",
                "HOME": "C:/home-a",
                "TEMP": "C:/temp-a",
                "TMP": "C:/tmp-a",
            },
            {
                "LOCALAPPDATA": "D:/root-b",
                "USERPROFILE": "D:/user-b",
                "HOME": "D:/home-b",
                "TEMP": "D:/temp-b",
                "TMP": "D:/tmp-b",
            },
        )
        observed = []
        with mock.patch.object(
            client, "_known_local_app_data", return_value=known_local_app_data
        ), mock.patch.object(client, "_current_python_executable", return_value=runtime):
            for environment in values:
                with mock.patch.dict(os.environ, environment, clear=False):
                    checkout = client._checkout_directory(key)
                    spec = client.build_command_spec(
                        self._request(), target, checkout, _CONTRACT_TREE_A
                    )
                    observed.append((
                        client._authority_store_path(),
                        checkout,
                        client.command_spec_hash(spec),
                    ))
        self.assertEqual(observed[0], observed[1])
        self.assertEqual(
            observed[0][0],
            known_local_app_data / "Umbilical" / "workgraph-first-client-v1" / "authority.sqlite",
        )
        self.assertNotIn("python_executable", client.WorkGraphRequest.__dataclass_fields__)

    def test_production_cli_rejects_caller_selected_python(self):
        with self.assertRaises(SystemExit) as raised:
            client.main([
                "run",
                "--revision",
                _REVISION_A,
                "--source",
                str(self.source),
                "--python",
                str(self.root / "stub.exe"),
            ])
        self.assertEqual(raised.exception.code, 2)

    def test_checkout_verifier_rejects_head_tree_and_cleanliness_drift(self):
        target = self._target()
        for outputs in (("0" * 40,), (_REVISION_A, "0" * 40), (_REVISION_A, _TREE_A, "M x")):
            with self.subTest(outputs=outputs), mock.patch.object(
                client, "_run_git", side_effect=outputs
            ):
                with self.assertRaises(client.WorkGraphClientError):
                    client._verify_clean_checkout(self.checkout, target)

    def test_preexisting_checkout_is_reconstructed_not_trusted(self):
        checkout = self.deployment_root / "checkouts" / "stable"
        checkout.mkdir(parents=True)
        target = self._target()
        with mock.patch.object(
            client, "_deployment_root", return_value=self.deployment_root
        ), mock.patch.object(
            client, "_checkout_directory", return_value=checkout
        ), mock.patch.object(
            client,
            "_run_git",
            side_effect=(target.revision, "", "", target.revision, target.tree_sha, ""),
        ), mock.patch.object(
            client,
            "_git_argv",
            return_value=("C:/git.exe", "-c", "core.longpaths=true", "clone"),
        ), mock.patch.object(client.subprocess, "run", return_value=mock.Mock(returncode=0)):
            result = client.prepare_exact_checkout(target, self.source, "stable-key")
        self.assertEqual(result, checkout)

    def test_checkout_reconstruction_removes_windows_readonly_files(self):
        checkout = self.deployment_root / "checkouts" / "stable"
        checkout.mkdir(parents=True)
        readonly = checkout / "readonly"
        readonly.write_text("x", encoding="utf-8")
        os.chmod(readonly, stat.S_IREAD)
        with mock.patch.object(client, "_deployment_root", return_value=self.deployment_root):
            client._remove_disposable_checkout(checkout)
        self.assertFalse(checkout.exists())

    def test_two_revisions_share_the_initialized_generation(self):
        self._initialize()
        publisher = mock.Mock()
        self._run(self._request(_REVISION_A), publisher)
        self._run(self._request(_REVISION_B), publisher)
        with AuthorityStore.open_existing(self.authority_db) as store:
            self.assertEqual(store.read_generation(client._AUTHORITY_SCOPE), 1)
            for revision in (_REVISION_A, _REVISION_B):
                key = client.derive_execution_key(
                    repository_identity="github-repository-id:1338331328",
                    subject_identity=client._SUBJECT,
                    revision_identity=revision,
                    causal_root=client.validation_contract_id(_CONTRACT_TREE_A),
                )
                self.assertEqual(store.read_execution_admission(key).controller_generation, 1)

    def test_prelaunch_admission_survives_environment_drift_and_another_revision(self):
        known_local_app_data = self.root / "known-local-app-data"
        authority_db = (
            known_local_app_data / "Umbilical" / "workgraph-first-client-v1" / "authority.sqlite"
        )
        environment_a = {"LOCALAPPDATA": "C:/root-a", "TEMP": "C:/temp-a", "TMP": "C:/tmp-a"}
        environment_b = {"LOCALAPPDATA": "D:/root-b", "TEMP": "D:/temp-b", "TMP": "D:/tmp-b"}
        with mock.patch.object(client, "_known_local_app_data", return_value=known_local_app_data):
            self.assertEqual(client.initialize_workgraph_client(), 1)
        request_a = self._request(_REVISION_A)
        with mock.patch.dict(
            os.environ, {"GH_TOKEN": "test-token", **environment_a}, clear=False
        ), mock.patch.object(
            client, "_known_local_app_data", return_value=known_local_app_data
        ), mock.patch.object(
            client, "verify_workgraph_target", return_value=self._target()
        ), mock.patch.object(
            client, "prepare_exact_checkout", return_value=self.checkout
        ), mock.patch.object(
            client, "_contract_tree", return_value=_CONTRACT_TREE_A
        ), mock.patch.object(client, "_run_integrity_preflight"), mock.patch.object(
            client, "execute_local_command", side_effect=RuntimeError("crash before launch")
        ):
            with self.assertRaisesRegex(RuntimeError, "before launch"):
                client.run_workgraph_client(request_a, publisher=mock.Mock())
        with mock.patch.dict(
            os.environ, {"GH_TOKEN": "test-token", **environment_b}, clear=False
        ), mock.patch.object(
            client, "_known_local_app_data", return_value=known_local_app_data
        ), mock.patch.object(
            client, "verify_workgraph_target", return_value=self._target(_REVISION_B, _TREE_B)
        ), mock.patch.object(
            client, "prepare_exact_checkout", return_value=self.checkout
        ), mock.patch.object(
            client, "_contract_tree", return_value=_CONTRACT_TREE_A
        ), mock.patch.object(client, "_run_integrity_preflight"), mock.patch.object(
            SubprocessLocalProcessLauncher, "launch", return_value=0
        ):
            client.run_workgraph_client(self._request(_REVISION_B), publisher=mock.Mock())
        with mock.patch.dict(
            os.environ, {"GH_TOKEN": "test-token", **environment_b}, clear=False
        ), mock.patch.object(
            client, "_known_local_app_data", return_value=known_local_app_data
        ), mock.patch.object(
            client, "verify_workgraph_target", return_value=self._target()
        ), mock.patch.object(
            client, "prepare_exact_checkout", return_value=self.checkout
        ), mock.patch.object(
            client, "_contract_tree", return_value=_CONTRACT_TREE_A
        ), mock.patch.object(client, "_run_integrity_preflight"), mock.patch.object(
            SubprocessLocalProcessLauncher, "launch", return_value=0
        ) as launch:
            result = client.run_workgraph_client(request_a, publisher=mock.Mock())
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(launch.call_count, 1)
        with AuthorityStore.open_existing(authority_db) as store:
            self.assertEqual(store.read_generation(client._AUTHORITY_SCOPE), 1)

    def test_same_identity_launches_once_and_terminal_replay_only_publishes(self):
        self._initialize()
        publisher = mock.Mock()
        first, first_launch = self._run(self._request(), publisher)
        second, second_launch = self._run(self._request(), publisher)
        self.assertEqual(first.execution_key, second.execution_key)
        self.assertEqual(first_launch.call_count, 1)
        self.assertEqual(second_launch.call_count, 0)
        self.assertEqual(publisher.call_count, 2)
        self.assertEqual(second.launch_state, ExecutionLaunchState.TERMINAL.value)

    def test_content_addressed_contract_preserves_historical_terminal_records(self):
        self._initialize()
        request = self._request()
        publisher = mock.Mock()
        with mock.patch.object(
            client, "validation_contract_id", return_value="umbilical-workgraph-validation-v1"
        ):
            v1, v1_launch = self._run(request, publisher)
        with mock.patch.object(
            client, "validation_contract_id", return_value="umbilical-workgraph-validation-v2"
        ):
            v2, v2_launch = self._run(request, publisher, launcher=1)
        with AuthorityStore.open_existing(self.authority_db) as store:
            v1_terminal = store.read_execution_launch(v1.execution_key)
            v2_terminal = store.read_execution_launch(v2.execution_key)

        current_first, current_first_launch = self._run(request, publisher)
        current_second, current_second_launch = self._run(request, publisher)

        self.assertNotEqual(v1.execution_key, current_first.execution_key)
        self.assertNotEqual(v2.execution_key, current_first.execution_key)
        self.assertEqual(current_first.execution_key, current_second.execution_key)
        self.assertEqual(v1_launch.call_count, 1)
        self.assertEqual(v2_launch.call_count, 1)
        self.assertEqual(current_first_launch.call_count, 1)
        self.assertEqual(current_second_launch.call_count, 0)
        with AuthorityStore.open_existing(self.authority_db) as store:
            self.assertEqual(store.read_execution_launch(v1.execution_key), v1_terminal)
            self.assertEqual(store.read_execution_launch(v2.execution_key), v2_terminal)
            self.assertEqual(
                store.read_execution_launch(current_first.execution_key).state,
                ExecutionLaunchState.TERMINAL,
            )
            self.assertEqual(store.read_generation(client._AUTHORITY_SCOPE), 1)

    def test_unknown_restart_never_relaunches(self):
        self._initialize()
        request = self._request()
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test-token"}), mock.patch.object(
            client, "_deployment_root", return_value=self.deployment_root
        ), mock.patch.object(
            client, "verify_workgraph_target", return_value=self._target()
        ), mock.patch.object(
            client, "prepare_exact_checkout", return_value=self.checkout
        ), mock.patch.object(
            client, "_contract_tree", return_value=_CONTRACT_TREE_A
        ), mock.patch.object(client, "_run_integrity_preflight"), mock.patch.object(
            SubprocessLocalProcessLauncher, "launch", side_effect=OSError("lost")
        ) as first_launch:
            with self.assertRaises(OSError):
                client.run_workgraph_client(request, publisher=mock.Mock())
        held, second_launch = self._run(request, mock.Mock())
        self.assertEqual(first_launch.call_count, 1)
        self.assertEqual(second_launch.call_count, 0)
        self.assertEqual(held.launch_state, ExecutionLaunchState.UNKNOWN.value)

    def test_publication_failure_does_not_restore_validation_authority(self):
        self._initialize()
        publisher = mock.Mock(side_effect=client.PublicationError("unknown"))
        with self.assertRaises(client.PublicationError):
            self._run(self._request(), publisher)
        publisher.side_effect = None
        result, launch = self._run(self._request(), publisher)
        self.assertEqual(launch.call_count, 0)
        self.assertEqual(result.exit_code, 0)

    def test_publication_reauthenticates_and_targets_only_the_verified_sha(self):
        target = self._target()
        response = mock.MagicMock(status=201)
        response.__enter__.return_value = response
        with mock.patch.object(
            client, "verify_workgraph_target", return_value=target
        ) as verify, mock.patch.object(
            client.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            client.publish_terminal_status(target=target, exit_code=0, token="test-token")
        verify.assert_called_once_with(target.revision, "test-token")
        request = urlopen.call_args.args[0]
        self.assertTrue(request.full_url.endswith(target.revision))
        self.assertEqual(
            json.loads(request.data.decode("utf-8"))["context"], client._STATUS_CONTEXT
        )
        self.assertNotEqual(client._STATUS_CONTEXT, "workgraph/repository-valid")

    def test_publication_refuses_reauthentication_drift(self):
        target = self._target()
        with mock.patch.object(
            client, "verify_workgraph_target", return_value=self._target(tree="d" * 40)
        ), mock.patch.object(client.urllib.request, "urlopen") as urlopen:
            with self.assertRaises(client.PublicationError):
                client.publish_terminal_status(target=target, exit_code=0, token="test-token")
        urlopen.assert_not_called()


class WorkGraphValidationTests(unittest.TestCase):
    def test_wrapper_git_checks_enable_windows_long_paths(self):
        with mock.patch.object(validation.shutil, "which", return_value="C:/Git/bin/git.exe"):
            command = validation._git_argv(Path("C:/fixed-checkout"), "status")
        self.assertEqual(command[1:3], ("-c", "core.longpaths=true"))
        self.assertIs(client._git_argv, validation._git_argv)
        self.assertNotIn("core.longpaths=true", Path(client.__file__).read_text(encoding="utf-8"))

    def test_committed_clean_tree_rejects_tracked_and_untracked_changes(self):
        root = Path("C:/contract-root").resolve()
        for status in ("M master/buildbot/x.py", "?? untracked.txt"):
            with self.subTest(status=status), mock.patch.object(
                validation,
                "_git_output",
                side_effect=(str(root), _REVISION_A, _CONTRACT_TREE_A, status),
            ):
                self.assertIsNone(validation._committed_clean_tree(root))

    def test_integrity_only_checks_both_trees_without_running_validation(self):
        root = Path("C:/fixed-checkout")
        with mock.patch.object(
            validation, "_committed_clean_tree", return_value=_CONTRACT_TREE_A
        ), mock.patch.object(
            validation, "_checkout_is_exact_and_clean", return_value=True
        ), mock.patch.object(validation.subprocess, "run") as run:
            self.assertEqual(
                validation.run_validation(
                    root,
                    _REVISION_A,
                    _TREE_A,
                    _CONTRACT_TREE_A,
                    integrity_only=True,
                ),
                0,
            )
        run.assert_not_called()

    def test_wrapper_rejects_wrong_or_dirty_contract_tree(self):
        root = Path("C:/fixed-checkout")
        for actual in (_CONTRACT_TREE_B, None):
            with self.subTest(actual=actual), mock.patch.object(
                validation, "_committed_clean_tree", return_value=actual
            ), mock.patch.object(
                validation, "_checkout_is_exact_and_clean"
            ) as checkout_check, mock.patch.object(validation.subprocess, "run") as run:
                self.assertEqual(
                    validation.run_validation(root, _REVISION_A, _TREE_A, _CONTRACT_TREE_A),
                    2,
                )
            checkout_check.assert_not_called()
            run.assert_not_called()

    def test_wrapper_runs_the_two_fixed_stages_in_order_after_integrity_check(self):
        root = Path("C:/fixed-checkout")
        first = mock.Mock(returncode=0)
        second = mock.Mock(returncode=0)
        with mock.patch.object(
            validation, "_committed_clean_tree", return_value=_CONTRACT_TREE_A
        ), mock.patch.object(
            validation, "_checkout_is_exact_and_clean", return_value=True
        ), mock.patch.object(validation.subprocess, "run", side_effect=(first, second)) as run:
            self.assertEqual(
                validation.run_validation(root, _REVISION_A, _TREE_A, _CONTRACT_TREE_A),
                0,
            )
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                (sys.executable, "tools/validate.py"),
                (sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"),
            ],
        )
        self.assertTrue(all(call.kwargs["shell"] is False for call in run.call_args_list))

    def test_wrapper_does_not_run_validation_when_integrity_check_fails(self):
        with mock.patch.object(
            validation, "_committed_clean_tree", return_value=_CONTRACT_TREE_A
        ), mock.patch.object(
            validation, "_checkout_is_exact_and_clean", return_value=False
        ), mock.patch.object(validation.subprocess, "run") as run:
            self.assertEqual(
                validation.run_validation(
                    Path("C:/fixed-checkout"),
                    _REVISION_A,
                    _TREE_A,
                    _CONTRACT_TREE_A,
                ),
                2,
            )
        run.assert_not_called()

    def test_wrapper_integrity_requires_exact_head_tree_and_empty_status(self):
        for outputs in (
            (_REVISION_A, _TREE_A, ""),
            ("0" * 40, _TREE_A, ""),
            (_REVISION_A, _TREE_A, "? x"),
        ):
            with self.subTest(outputs=outputs), mock.patch.object(
                validation, "_git_output", side_effect=outputs
            ):
                self.assertEqual(
                    validation._checkout_is_exact_and_clean(
                        Path("C:/fixed-checkout"), _REVISION_A, _TREE_A
                    ),
                    outputs == (_REVISION_A, _TREE_A, ""),
                )
