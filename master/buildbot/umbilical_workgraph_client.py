# This file is part of Umbilical.
#
# Umbilical is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, version 2.

"""The bounded Windows-only Umbilical client for WorkGraph validation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from typing import Optional

from buildbot.umbilical_authority import AuthorityStore
from buildbot.umbilical_authority import AuthorityStoreError
from buildbot.umbilical_authority import ExecutionLaunchState
from buildbot.umbilical_execution_identity import derive_execution_key
from buildbot.umbilical_local_execution import LocalCommandSpec
from buildbot.umbilical_local_execution import SubprocessLocalProcessLauncher
from buildbot.umbilical_local_execution import command_spec_hash
from buildbot.umbilical_local_execution import execute_local_command
from buildbot.umbilical_workgraph_validation import _committed_clean_tree
from buildbot.umbilical_workgraph_validation import _git_argv
from buildbot.umbilical_workgraph_validation import _git_output

_REPOSITORY = "4i7/WorkGraph"
_REPOSITORY_ID = 1338331328
_SUBJECT = "workgraph/repository-valid"
_CONTRACT_ID_PREFIX = "umbilical-workgraph-validation-tree:"
_AUTHORITY_SCOPE = "umbilical/workgraph-first-client/v1"
_STATUS_CONTEXT = "workgraph/umbilical-repository-valid"
_REVISION = re.compile(r"[0-9a-f]{40}\Z")


class WorkGraphClientError(RuntimeError):
    """Raised when the fixed WorkGraph client cannot safely continue."""


class PublicationError(WorkGraphClientError):
    """Raised when a terminal result cannot be published with known outcome."""


@dataclass(frozen=True)
class VerifiedWorkGraphTarget:
    """The one authenticated remote target consumed by a client invocation."""

    repository_full_name: str
    repository_id: int
    revision: str
    tree_sha: str


@dataclass(frozen=True)
class WorkGraphRequest:
    revision: str
    source: Path
    timeout_seconds: int = 1800

    def __post_init__(self) -> None:
        if type(self.revision) is not str or _REVISION.fullmatch(self.revision) is None:
            raise WorkGraphClientError("revision must be an exact lowercase 40-hex SHA")
        if self.timeout_seconds <= 0:
            raise WorkGraphClientError("timeout_seconds must be positive")
        if not self.source.is_absolute():
            raise WorkGraphClientError("source must be an absolute path")


@dataclass(frozen=True)
class WorkGraphClientResult:
    execution_key: str
    command_spec_hash: Optional[str]  # noqa: UP007  # Python 3.8 support
    exit_code: Optional[int]  # noqa: UP007  # Python 3.8 support
    launch_state: Optional[str]  # noqa: UP007  # Python 3.8 support
    publication_attempted: bool


def _run_git(directory: Path, *arguments: str) -> str:
    output = _git_output(directory, *arguments)
    if output is None:
        raise WorkGraphClientError("fixed git checkout preparation failed")
    return output


def _contract_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _contract_tree() -> str:
    tree = _committed_clean_tree(_contract_root())
    if tree is None:
        raise WorkGraphClientError("Umbilical validation contract must be committed and clean")
    return tree


def validation_contract_id(contract_tree: str) -> str:
    if type(contract_tree) is not str or _REVISION.fullmatch(contract_tree) is None:
        raise WorkGraphClientError("contract tree must be an exact lowercase 40-hex SHA")
    return _CONTRACT_ID_PREFIX + contract_tree


def _github_json(path: str, token: str) -> object:
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "umbilical-workgraph-first-client",
    }
    try:
        with urllib.request.urlopen(
            urllib.request.Request(f"https://api.github.com{path}", headers=headers), timeout=30
        ) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, urllib.error.HTTPError, urllib.error.URLError) as exc:
        raise WorkGraphClientError("authenticated GitHub target lookup failed") from exc


def verify_workgraph_target(revision: str, token: str) -> VerifiedWorkGraphTarget:
    """Resolve one exact WorkGraph commit and tree through authenticated GitHub reads."""
    if type(revision) is not str or _REVISION.fullmatch(revision) is None:
        raise WorkGraphClientError("revision must be an exact lowercase 40-hex SHA")
    repository = _github_json(f"/repos/{_REPOSITORY}", token)
    if type(repository) is not dict:
        raise WorkGraphClientError("GitHub repository response is malformed")
    if repository.get("full_name") != _REPOSITORY or repository.get("id") != _REPOSITORY_ID:
        raise WorkGraphClientError(
            "GitHub repository identity does not match fixed WorkGraph authority"
        )
    commit = _github_json(f"/repos/{_REPOSITORY}/commits/{revision}", token)
    if type(commit) is not dict or commit.get("sha") != revision:
        raise WorkGraphClientError("GitHub exact commit response does not match requested revision")
    commit_data = commit.get("commit")
    tree = commit_data.get("tree") if type(commit_data) is dict else None
    tree_sha = tree.get("sha") if type(tree) is dict else None
    if type(tree_sha) is not str or _REVISION.fullmatch(tree_sha) is None:
        raise WorkGraphClientError("GitHub exact commit response is missing a valid tree SHA")
    return VerifiedWorkGraphTarget(_REPOSITORY, _REPOSITORY_ID, revision, tree_sha)


def _known_local_app_data() -> Path:
    """Return the Windows Local AppData known folder, independent of process environment."""
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.c_ulong),
            ("Data2", ctypes.c_ushort),
            ("Data3", ctypes.c_ushort),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    folder_id = GUID(
        0xF1B32785,
        0x6FBA,
        0x4FCF,
        (ctypes.c_ubyte * 8)(0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91),
    )
    path = ctypes.c_wchar_p()
    shell32 = ctypes.windll.shell32
    shell32.SHGetKnownFolderPath.argtypes = (
        ctypes.POINTER(GUID),
        wintypes.DWORD,
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_wchar_p),
    )
    shell32.SHGetKnownFolderPath.restype = ctypes.c_long
    result = shell32.SHGetKnownFolderPath(ctypes.byref(folder_id), 0, None, ctypes.byref(path))
    if result != 0 or not path.value:
        raise WorkGraphClientError("Windows Local AppData known-folder lookup failed")
    try:
        return Path(path.value).resolve()
    finally:
        ctypes.windll.ole32.CoTaskMemFree(ctypes.cast(path, ctypes.c_void_p))


def _deployment_root() -> Path:
    return (_known_local_app_data() / "Umbilical" / "workgraph-first-client-v1").resolve()


def _authority_store_path() -> Path:
    return _deployment_root() / "authority.sqlite"


def _checkout_root() -> Path:
    return _deployment_root() / "checkouts"


def _checkout_directory(execution_key: str) -> Path:
    safe_id = hashlib.sha256(execution_key.encode("utf-8")).hexdigest()
    return _checkout_root() / safe_id[:32]


def _assert_authority_store_outside_checkouts(path: Path) -> None:
    checkout_root = _checkout_root().resolve()
    try:
        path.resolve().relative_to(checkout_root)
    except ValueError:
        return
    raise WorkGraphClientError("fixed authority store must remain outside disposable checkouts")


def initialize_workgraph_client() -> int:
    """Create the sole authority universe and its first controller generation."""
    if os.name != "nt":
        raise WorkGraphClientError("the WorkGraph first client is supported only on Windows")
    path = _authority_store_path()
    _assert_authority_store_outside_checkouts(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with AuthorityStore.initialize_new(path) as store:
        return store.acquire_generation(_AUTHORITY_SCOPE)


def _remove_disposable_checkout(checkout: Path) -> None:
    parent = checkout.parent.resolve()
    if checkout.parent != parent or parent != _checkout_root().resolve():
        raise WorkGraphClientError("refusing to reconstruct an unexpected checkout path")
    if checkout.is_symlink():
        checkout.unlink()
    elif checkout.is_dir():

        def clear_readonly(function: Callable[..., object], path: str, _exception: object) -> None:
            os.chmod(path, stat.S_IWRITE)
            function(path)

        shutil.rmtree(checkout, onerror=clear_readonly)
    else:
        raise WorkGraphClientError("existing checkout path is not a disposable directory")


def _verify_clean_checkout(checkout: Path, target: VerifiedWorkGraphTarget) -> None:
    if _run_git(checkout, "rev-parse", "HEAD") != target.revision:
        raise WorkGraphClientError(
            "checked-out WorkGraph HEAD does not match authenticated revision"
        )
    if _run_git(checkout, "rev-parse", "HEAD^{tree}") != target.tree_sha:
        raise WorkGraphClientError("checked-out WorkGraph tree does not match authenticated tree")
    if _run_git(checkout, "status", "--porcelain", "--untracked-files=all"):
        raise WorkGraphClientError("checked-out WorkGraph tree is not clean")


def prepare_exact_checkout(
    target: VerifiedWorkGraphTarget, source: Path, execution_key: str
) -> Path:
    """Reconstruct a clean deterministic checkout from an authenticated target."""
    if not source.is_dir():
        raise WorkGraphClientError("source must be an existing local WorkGraph clone or mirror")
    if (
        _run_git(source, "rev-parse", "--verify", f"{target.revision}^{{commit}}")
        != target.revision
    ):
        raise WorkGraphClientError("authenticated WorkGraph revision is not available from source")
    checkout = _checkout_directory(execution_key)
    if checkout.exists() or checkout.is_symlink():
        _remove_disposable_checkout(checkout)
    checkout.parent.mkdir(parents=True, exist_ok=True)
    clone_command = _git_argv(
        source.parent,
        "clone",
        "--no-hardlinks",
        "--no-checkout",
        "--",
        str(source),
        str(checkout),
    )
    if clone_command is None:
        raise WorkGraphClientError("an absolute git executable is required")
    completed = subprocess.run(
        clone_command,
        check=False,
        shell=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise WorkGraphClientError("fixed git checkout preparation failed")
    _run_git(checkout, "remote", "remove", "origin")
    _run_git(checkout, "checkout", "--detach", target.revision)
    _verify_clean_checkout(checkout, target)
    return checkout


def _current_python_executable() -> Path:
    return Path(sys.executable).resolve()


def _command_environment(authority_db: Path, python_executable: Path) -> dict[str, str]:
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise WorkGraphClientError("SystemRoot is required on Windows")
    temporary_directory = authority_db.parent / "temporary"
    temporary_directory.mkdir(parents=True, exist_ok=True)
    git_command = _git_argv(authority_db.parent, "--version")
    if git_command is None:
        raise WorkGraphClientError("an absolute git executable is required")
    git_directory = Path(git_command[0]).parent
    return {
        "PATH": f"{python_executable.parent};{git_directory};{Path(system_root) / 'System32'}",
        "PYTHONUTF8": "1",
        "SYSTEMROOT": system_root,
        "TEMP": str(temporary_directory),
        "TMP": str(temporary_directory),
    }


def build_command_spec(
    request: WorkGraphRequest,
    target: VerifiedWorkGraphTarget,
    checkout: Path,
    contract_tree: str,
    *,
    integrity_only: bool = False,
) -> LocalCommandSpec:
    wrapper = Path(__file__).with_name("umbilical_workgraph_validation.py").resolve()
    authority_db = _authority_store_path()
    python_executable = _current_python_executable()
    argv = [
        str(python_executable),
        str(wrapper),
        "--checkout-root",
        str(checkout),
        "--expected-revision",
        target.revision,
        "--expected-tree",
        target.tree_sha,
        "--expected-contract-tree",
        contract_tree,
    ]
    if integrity_only:
        argv.append("--integrity-only")
    return LocalCommandSpec.snapshot(
        executable=str(python_executable),
        argv=argv,
        working_directory=str(checkout),
        environment=_command_environment(authority_db, python_executable),
        timeout_seconds=request.timeout_seconds,
    )


def _run_integrity_preflight(command_spec: LocalCommandSpec) -> None:
    if SubprocessLocalProcessLauncher().launch(command_spec) != 0:
        raise WorkGraphClientError("WorkGraph integrity preflight failed")


def publish_terminal_status(*, target: VerifiedWorkGraphTarget, exit_code: int, token: str) -> None:
    """Reauthenticate the exact target immediately before publishing its terminal result."""
    if verify_workgraph_target(target.revision, token) != target:
        raise PublicationError("GitHub target changed before status publication")
    payload = {
        "state": "success" if exit_code == 0 else "failure",
        "context": _STATUS_CONTEXT,
        "description": (
            "WorkGraph repository validation passed"
            if exit_code == 0
            else "WorkGraph repository validation did not pass"
        ),
    }
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "umbilical-workgraph-first-client",
    }
    try:
        with urllib.request.urlopen(
            urllib.request.Request(
                f"https://api.github.com/repos/{target.repository_full_name}/statuses/{target.revision}",
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            ),
            timeout=30,
        ) as response:
            if response.status != 201:
                raise PublicationError("GitHub status publication returned an unexpected response")
    except PublicationError:
        raise
    except (OSError, urllib.error.HTTPError, urllib.error.URLError) as exc:
        raise PublicationError("GitHub status publication outcome is unknown") from exc


def _require_token() -> str:
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise WorkGraphClientError("GH_TOKEN is required for authenticated WorkGraph operations")
    return token


def _open_store() -> AuthorityStore:
    path = _authority_store_path()
    _assert_authority_store_outside_checkouts(path)
    return AuthorityStore.open_existing(path)


def run_workgraph_client(
    request: WorkGraphRequest,
    *,
    publisher: Callable[..., None] = publish_terminal_status,
) -> WorkGraphClientResult:
    """Run or observe exactly one WorkGraph validation execution authority."""
    if os.name != "nt":
        raise WorkGraphClientError("the WorkGraph first client is supported only on Windows")
    token = _require_token()
    target = verify_workgraph_target(request.revision, token)
    contract_tree = _contract_tree()
    execution_key = derive_execution_key(
        repository_identity=f"github-repository-id:{target.repository_id}",
        subject_identity=_SUBJECT,
        revision_identity=target.revision,
        causal_root=validation_contract_id(contract_tree),
    )

    with _open_store() as store:
        exists = store.execution_key_exists(execution_key)
        if exists:
            prior = store.read_execution_launch(execution_key)
            if prior is not None:
                if prior.state is not ExecutionLaunchState.TERMINAL:
                    return WorkGraphClientResult(
                        execution_key, prior.command_spec_hash, None, prior.state.value, False
                    )
                if prior.exit_code is None:
                    raise WorkGraphClientError("terminal launch is missing its exit code")
                publisher(target=target, exit_code=prior.exit_code, token=token)
                return WorkGraphClientResult(
                    execution_key, prior.command_spec_hash, prior.exit_code, prior.state.value, True
                )

        checkout = prepare_exact_checkout(target, request.source, execution_key)
        command_spec = build_command_spec(request, target, checkout, contract_tree)
        preflight_spec = build_command_spec(
            request, target, checkout, contract_tree, integrity_only=True
        )
        _run_integrity_preflight(preflight_spec)
        if _contract_tree() != contract_tree:
            raise WorkGraphClientError("Umbilical validation contract changed after preflight")
        command_hash = command_spec_hash(command_spec)
        if not exists:
            store.register_execution_key(execution_key)
        store.bind_command_spec_hash(execution_key, command_hash)
        generation = store.read_generation(_AUTHORITY_SCOPE)
        if generation is None:
            raise WorkGraphClientError(
                "fixed authority store has no initialized controller generation"
            )
        admission = store.read_execution_admission(execution_key)
        if admission is None:
            store.admit_execution(execution_key, _AUTHORITY_SCOPE, generation)
        elif admission.controller_generation != generation:
            raise WorkGraphClientError(
                "existing WorkGraph admission is not in the current generation"
            )

        execution = execute_local_command(
            store,
            execution_key=execution_key,
            authority_scope=_AUTHORITY_SCOPE,
            controller_generation=generation,
            command_spec=command_spec,
        )
        publisher(target=target, exit_code=execution.exit_code, token=token)
        return WorkGraphClientResult(
            execution_key,
            execution.command_spec_hash,
            execution.exit_code,
            ExecutionLaunchState.TERMINAL.value,
            True,
        )


def main(argv: Optional[list[str]] = None) -> int:  # noqa: UP007  # Python 3.8 support
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init")
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--revision", required=True)
    run_parser.add_argument("--source", required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "init":
            print(json.dumps({"controller_generation": initialize_workgraph_client()}))
            return 0
        request = WorkGraphRequest(
            revision=arguments.revision,
            source=Path(arguments.source).resolve(),
        )
        result = run_workgraph_client(request)
    except (AuthorityStoreError, WorkGraphClientError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result.__dict__, sort_keys=True))
    if result.exit_code is None:
        return 2
    return 0 if result.exit_code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
