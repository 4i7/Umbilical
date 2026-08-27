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


class WorkGraphClientTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.authority_db = self.root / "authority.sqlite"
        self.source = self.root / "source"
        self.source.mkdir()
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()

    def _request(self, revision=_REVISION_A):
        return client.WorkGraphRequest(
            revision=revision,
            source=self.source,
            python_executable=Path(sys.executable).resolve(),
            timeout_seconds=30,
        )

    @staticmethod
    def _target(revision=_REVISION_A, tree=_TREE_A):
        return client.VerifiedWorkGraphTarget("4i7/WorkGraph", 1338331328, revision, tree)

    def _initialize(self):
        with mock.patch.object(client, "_authority_store_path", return_value=self.authority_db):
            return client.initialize_workgraph_client()

    def _run(self, request, publisher, *, launcher=0, target=None):
        target = self._target(request.revision, _TREE_A if request.revision == _REVISION_A else _TREE_B) if target is None else target
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test-token"}), mock.patch.object(
            client, "_authority_store_path", return_value=self.authority_db
        ), mock.patch.object(
            client, "verify_workgraph_target", return_value=target
        ), mock.patch.object(
            client, "prepare_exact_checkout", return_value=self.checkout
        ), mock.patch.object(
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
            client, "_authority_store_path", return_value=self.authority_db
        ), mock.patch.object(client, "verify_workgraph_target", return_value=self._target()):
            with self.assertRaises(AuthorityStoreMissingError):
                client.run_workgraph_client(self._request())

    def test_authority_store_inside_disposable_root_is_rejected(self):
        checkout_root = Path(tempfile.gettempdir()) / "U"
        with self.assertRaises(client.WorkGraphClientError):
            client._assert_authority_store_outside_checkouts(checkout_root / "authority.sqlite")

    def test_command_binds_expected_remote_commit_and_tree(self):
        target = self._target()
        with mock.patch.object(client, "_authority_store_path", return_value=self.authority_db):
            spec = client.build_command_spec(self._request(), target, self.checkout)
            same_spec = client.build_command_spec(self._request(), target, self.checkout)
        self.assertIn(target.revision, spec.argv)
        self.assertIn(target.tree_sha, spec.argv)
        self.assertNotIn("GH_TOKEN", dict(spec.environment))
        self.assertEqual(client.command_spec_hash(spec), client.command_spec_hash(same_spec))

    def test_checkout_verifier_rejects_head_tree_and_cleanliness_drift(self):
        target = self._target()
        for outputs in (("0" * 40,), (_REVISION_A, "0" * 40), (_REVISION_A, _TREE_A, "M x")):
            with self.subTest(outputs=outputs), mock.patch.object(client, "_run_git", side_effect=outputs):
                with self.assertRaises(client.WorkGraphClientError):
                    client._verify_clean_checkout(self.checkout, target)

    def test_preexisting_checkout_is_reconstructed_not_trusted(self):
        checkout = self.root / "U" / "stable"
        checkout.mkdir(parents=True)
        target = self._target()
        with mock.patch.object(client, "_checkout_directory", return_value=checkout), mock.patch.object(
            client, "_run_git", side_effect=(target.revision, "", "", target.revision, target.tree_sha, "")
        ), mock.patch.object(client, "_git_executable", return_value="C:/git.exe"), mock.patch.object(
            client.subprocess, "run", return_value=mock.Mock(returncode=0)
        ):
            result = client.prepare_exact_checkout(target, self.source, "stable-key")
        self.assertEqual(result, checkout)

    def test_checkout_reconstruction_removes_windows_readonly_files(self):
        checkout = self.root / "U" / "stable"
        checkout.mkdir(parents=True)
        readonly = checkout / "readonly"
        readonly.write_text("x", encoding="utf-8")
        os.chmod(readonly, stat.S_IREAD)
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
                    causal_root=client._CAUSAL_ROOT,
                )
                self.assertEqual(store.read_execution_admission(key).controller_generation, 1)

    def test_prelaunch_admission_survives_another_revision(self):
        self._initialize()
        request_a = self._request(_REVISION_A)
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test-token"}), mock.patch.object(
            client, "_authority_store_path", return_value=self.authority_db
        ), mock.patch.object(
            client, "verify_workgraph_target", return_value=self._target()
        ), mock.patch.object(
            client, "prepare_exact_checkout", return_value=self.checkout
        ), mock.patch.object(client, "execute_local_command", side_effect=RuntimeError("crash before launch")):
            with self.assertRaisesRegex(RuntimeError, "before launch"):
                client.run_workgraph_client(request_a, publisher=mock.Mock())
        self._run(self._request(_REVISION_B), mock.Mock())
        result, launch = self._run(request_a, mock.Mock())
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(launch.call_count, 1)
        with AuthorityStore.open_existing(self.authority_db) as store:
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

    def test_unknown_restart_never_relaunches(self):
        self._initialize()
        request = self._request()
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test-token"}), mock.patch.object(
            client, "_authority_store_path", return_value=self.authority_db
        ), mock.patch.object(
            client, "verify_workgraph_target", return_value=self._target()
        ), mock.patch.object(
            client, "prepare_exact_checkout", return_value=self.checkout
        ), mock.patch.object(
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
        with mock.patch.object(client, "verify_workgraph_target", return_value=target) as verify, mock.patch.object(
            client.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            client.publish_terminal_status(target=target, exit_code=0, token="test-token")
        verify.assert_called_once_with(target.revision, "test-token")
        request = urlopen.call_args.args[0]
        self.assertTrue(request.full_url.endswith(target.revision))
        self.assertEqual(json.loads(request.data.decode("utf-8"))["context"], client._STATUS_CONTEXT)
        self.assertNotEqual(client._STATUS_CONTEXT, "workgraph/repository-valid")

    def test_publication_refuses_reauthentication_drift(self):
        target = self._target()
        with mock.patch.object(client, "verify_workgraph_target", return_value=self._target(tree="d" * 40)), mock.patch.object(
            client.urllib.request, "urlopen"
        ) as urlopen:
            with self.assertRaises(client.PublicationError):
                client.publish_terminal_status(target=target, exit_code=0, token="test-token")
        urlopen.assert_not_called()


class WorkGraphValidationTests(unittest.TestCase):
    def test_wrapper_runs_the_two_fixed_stages_in_order_after_integrity_check(self):
        root = Path("C:/fixed-checkout")
        first = mock.Mock(returncode=0)
        second = mock.Mock(returncode=0)
        with mock.patch.object(validation, "_checkout_is_exact_and_clean", return_value=True), mock.patch.object(
            validation.subprocess, "run", side_effect=(first, second)
        ) as run:
            self.assertEqual(validation.run_validation(root, _REVISION_A, _TREE_A), 0)
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                (sys.executable, "tools/validate.py"),
                (sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"),
            ],
        )
        self.assertTrue(all(call.kwargs["shell"] is False for call in run.call_args_list))

    def test_wrapper_does_not_run_validation_when_integrity_check_fails(self):
        with mock.patch.object(validation, "_checkout_is_exact_and_clean", return_value=False), mock.patch.object(
            validation.subprocess, "run"
        ) as run:
            self.assertEqual(validation.run_validation(Path("C:/fixed-checkout"), _REVISION_A, _TREE_A), 2)
        run.assert_not_called()

    def test_wrapper_integrity_requires_exact_head_tree_and_empty_status(self):
        for outputs in ((_REVISION_A, _TREE_A, ""), ("0" * 40, _TREE_A, ""), (_REVISION_A, _TREE_A, "? x")):
            with self.subTest(outputs=outputs), mock.patch.object(
                validation, "_git_output", side_effect=outputs
            ):
                self.assertEqual(
                    validation._checkout_is_exact_and_clean(Path("C:/fixed-checkout"), _REVISION_A, _TREE_A),
                    outputs == (_REVISION_A, _TREE_A, ""),
                )
