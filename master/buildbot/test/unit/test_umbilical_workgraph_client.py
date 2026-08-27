# This file is part of Umbilical.
#
# Umbilical is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, version 2.

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import buildbot.umbilical_workgraph_client as client
import buildbot.umbilical_workgraph_validation as validation
from buildbot.umbilical_authority import ExecutionLaunchState


_REVISION = "663a98f92709a30352bc5a65249a660481c664d9"


class WorkGraphClientTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        self.request = client.WorkGraphRequest(
            authority_db=self.root / "authority.sqlite3",
            repository="4i7/WorkGraph",
            repository_id=1338331328,
            revision=_REVISION,
            source=self.root / "source",
            python_executable=Path(sys.executable).resolve(),
            timeout_seconds=30,
        )

    def _run(self, publisher, launcher=0):
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test-token"}), mock.patch.object(
            client, "verify_repository_identity"
        ), mock.patch.object(
            client, "prepare_exact_checkout", return_value=self.checkout
        ), mock.patch.object(
            client.SubprocessLocalProcessLauncher, "launch", return_value=launcher
        ) as launch:
            result = client.run_workgraph_client(self.request, publisher=publisher)
        return result, launch

    def test_same_identity_reuses_key_and_blocks_second_physical_launch(self):
        publisher = mock.Mock()
        first, first_launch = self._run(publisher)
        second, second_launch = self._run(publisher)

        self.assertEqual(first.execution_key, second.execution_key)
        self.assertEqual(first_launch.call_count, 1)
        self.assertEqual(second_launch.call_count, 0)
        self.assertEqual(first.exit_code, 0)
        self.assertEqual(second.exit_code, 0)
        self.assertEqual(publisher.call_count, 2)

    def test_revision_and_repository_identity_change_execution_key(self):
        baseline = client.derive_execution_key(
            repository_identity="github-repository-id:1338331328",
            subject_identity="workgraph/repository-valid",
            revision_identity=_REVISION,
            causal_root="umbilical-workgraph-validation-v1",
        )
        self.assertNotEqual(
            client.derive_execution_key(
                repository_identity="github-repository-id:1338331328",
                subject_identity="workgraph/repository-valid",
                revision_identity="0" * 40,
                causal_root="umbilical-workgraph-validation-v1",
            ),
            baseline,
        )
        self.assertNotEqual(
            client.derive_execution_key(
                repository_identity="github-repository-id:1",
                subject_identity="workgraph/repository-valid",
                revision_identity=_REVISION,
                causal_root="umbilical-workgraph-validation-v1",
            ),
            baseline,
        )

    def test_wrong_repository_identity_is_rejected_before_checkout(self):
        with self.assertRaises(client.WorkGraphClientError):
            client.WorkGraphRequest(
                authority_db=self.root / "authority.sqlite3",
                repository="other/repository",
                repository_id=1338331328,
                revision=_REVISION,
                source=self.root,
                python_executable=Path(sys.executable).resolve(),
            )

    def test_unknown_launch_is_held_without_a_restart_launch(self):
        publisher = mock.Mock()
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test-token"}), mock.patch.object(
            client, "verify_repository_identity"
        ), mock.patch.object(
            client, "prepare_exact_checkout", return_value=self.checkout
        ), mock.patch.object(
            client.SubprocessLocalProcessLauncher, "launch", side_effect=OSError("lost")
        ) as first_launch:
            with self.assertRaises(OSError):
                client.run_workgraph_client(self.request, publisher=publisher)

        with mock.patch.dict(os.environ, {"GH_TOKEN": "test-token"}), mock.patch.object(
            client, "verify_repository_identity"
        ), mock.patch.object(
            client.SubprocessLocalProcessLauncher, "launch"
        ) as second_launch:
            held = client.run_workgraph_client(self.request, publisher=publisher)

        self.assertEqual(first_launch.call_count, 1)
        self.assertEqual(second_launch.call_count, 0)
        self.assertEqual(held.launch_state, ExecutionLaunchState.UNKNOWN.value)
        self.assertFalse(held.publication_attempted)

    def test_terminal_restart_republishes_without_relaunch(self):
        publisher = mock.Mock()
        self._run(publisher)
        result, launch = self._run(publisher)

        self.assertEqual(launch.call_count, 0)
        self.assertTrue(result.publication_attempted)
        self.assertEqual(result.launch_state, ExecutionLaunchState.TERMINAL.value)

    def test_publication_failure_cannot_restore_launch_authority(self):
        publisher = mock.Mock(side_effect=client.PublicationError("unknown"))
        with self.assertRaises(client.PublicationError):
            self._run(publisher)

        publisher.side_effect = None
        result, launch = self._run(publisher)
        self.assertEqual(launch.call_count, 0)
        self.assertEqual(result.exit_code, 0)

    def test_changed_command_for_existing_key_is_rejected(self):
        publisher = mock.Mock()
        execution_key = client.derive_execution_key(
            repository_identity="github-repository-id:1338331328",
            subject_identity="workgraph/repository-valid",
            revision_identity=self.request.revision,
            causal_root="umbilical-workgraph-validation-v1",
        )
        baseline = client.build_command_spec(self.request, self.checkout)
        with client._open_store(self.request.authority_db) as store:
            store.register_execution_key(execution_key)
            store.bind_command_spec_hash(execution_key, client.command_spec_hash(baseline))
        changed = client.WorkGraphRequest(
            authority_db=self.request.authority_db,
            repository=self.request.repository,
            repository_id=self.request.repository_id,
            revision=self.request.revision,
            source=self.request.source,
            python_executable=self.request.python_executable,
            timeout_seconds=31,
        )
        with mock.patch.dict(os.environ, {"GH_TOKEN": "test-token"}), mock.patch.object(
            client, "verify_repository_identity"
        ), mock.patch.object(
            client, "prepare_exact_checkout", return_value=self.checkout
        ):
            with self.assertRaises(client.CommandSpecConflictError):
                client.run_workgraph_client(changed, publisher=publisher)

    def test_existing_wrong_checkout_is_rejected_before_launch(self):
        execution_key = f"key-{self.root.name}"
        checkout = client._checkout_directory(self.request, execution_key)
        checkout.mkdir(parents=True)
        with mock.patch.object(client, "_verify_source_repository"), mock.patch.object(
            client, "_run_git", return_value="0" * 40
        ):
            with self.assertRaisesRegex(client.WorkGraphClientError, "wrong revision"):
                client.prepare_exact_checkout(self.request, execution_key)

    def test_publication_targets_only_the_requested_sha(self):
        with self.assertRaises(client.PublicationError):
            client.publish_terminal_status(
                request=self.request,
                target_revision="0" * 40,
                exit_code=0,
                token="test-token",
            )

        response = mock.MagicMock(status=201)
        response.__enter__.return_value = response
        with mock.patch.object(client.urllib.request, "urlopen", return_value=response) as urlopen:
            client.publish_terminal_status(
                request=self.request,
                target_revision=_REVISION,
                exit_code=0,
                token="test-token",
            )
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertTrue(request.full_url.endswith(_REVISION))
        self.assertEqual(json.loads(request.data.decode("utf-8"))["context"], client._STATUS_CONTEXT)


class WorkGraphValidationTests(unittest.TestCase):
    def test_wrapper_runs_the_two_fixed_stages_in_order(self):
        root = Path("C:/fixed-checkout")
        first = mock.Mock(returncode=0)
        second = mock.Mock(returncode=0)
        with mock.patch.object(validation.subprocess, "run", side_effect=(first, second)) as run:
            self.assertEqual(validation.run_validation(root), 0)
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                (sys.executable, "tools/validate.py"),
                (sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"),
            ],
        )
        self.assertTrue(all(call.kwargs["shell"] is False for call in run.call_args_list))

    def test_wrapper_stops_after_the_first_failed_stage(self):
        with mock.patch.object(
            validation.subprocess, "run", return_value=mock.Mock(returncode=7)
        ) as run:
            self.assertEqual(validation.run_validation(Path("C:/fixed-checkout")), 7)
        run.assert_called_once()
