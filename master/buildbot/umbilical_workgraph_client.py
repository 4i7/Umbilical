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
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from typing import Optional

from buildbot.umbilical_authority import AuthorityStore
from buildbot.umbilical_authority import ExecutionLaunchState
from buildbot.umbilical_authority import CommandSpecConflictError
from buildbot.umbilical_execution_identity import derive_execution_key
from buildbot.umbilical_local_execution import LocalCommandSpec
from buildbot.umbilical_local_execution import SubprocessLocalProcessLauncher
from buildbot.umbilical_local_execution import command_spec_hash
from buildbot.umbilical_local_execution import execute_local_command

_REPOSITORY = "4i7/WorkGraph"
_REPOSITORY_ID = 1338331328
_SUBJECT = "workgraph/repository-valid"
_CAUSAL_ROOT = "umbilical-workgraph-validation-v1"
_AUTHORITY_SCOPE = "umbilical/workgraph-first-client/v1"
_STATUS_CONTEXT = "workgraph/umbilical-repository-valid"
_REVISION = re.compile(r"[0-9a-f]{40}\Z")


class WorkGraphClientError(RuntimeError):
    """Raised when the fixed WorkGraph client cannot safely continue."""


class PublicationError(WorkGraphClientError):
    """Raised when a terminal result cannot be published with known outcome."""


@dataclass(frozen=True)
class WorkGraphRequest:
    authority_db: Path
    repository: str
    repository_id: int
    revision: str
    source: Path
    python_executable: Path
    timeout_seconds: int = 1800

    def __post_init__(self) -> None:
        if self.repository != _REPOSITORY or self.repository_id != _REPOSITORY_ID:
            raise WorkGraphClientError("only the fixed 4i7/WorkGraph client is supported")
        if type(self.revision) is not str or _REVISION.fullmatch(self.revision) is None:
            raise WorkGraphClientError("revision must be an exact lowercase 40-hex SHA")
        if self.timeout_seconds <= 0:
            raise WorkGraphClientError("timeout_seconds must be positive")
        for name, value in (
            ("authority_db", self.authority_db),
            ("source", self.source),
            ("python_executable", self.python_executable),
        ):
            if not value.is_absolute():
                raise WorkGraphClientError(f"{name} must be an absolute path")


@dataclass(frozen=True)
class WorkGraphClientResult:
    execution_key: str
    command_spec_hash: Optional[str]
    exit_code: Optional[int]
    launch_state: Optional[str]
    publication_attempted: bool


def _git_executable() -> str:
    executable = shutil.which("git")
    if executable is None or not os.path.isabs(executable):
        raise WorkGraphClientError("an absolute git executable is required")
    return executable


def _run_git(directory: Path, *arguments: str) -> str:
    completed = subprocess.run(
        (_git_executable(), "-c", "core.longpaths=true", "-C", str(directory), *arguments),
        check=False,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise WorkGraphClientError("fixed git checkout preparation failed")
    return completed.stdout.strip()


def _verify_source_repository(source: Path) -> None:
    if not source.is_dir():
        raise WorkGraphClientError("source must be an existing local WorkGraph clone or mirror")
    remote = _run_git(source, "config", "--get", "remote.origin.url")
    if remote != "https://github.com/4i7/WorkGraph.git":
        raise WorkGraphClientError("source origin is not the fixed WorkGraph repository")


def verify_repository_identity(request: WorkGraphRequest, token: str) -> None:
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "umbilical-workgraph-first-client",
    }
    try:
        with urllib.request.urlopen(
            urllib.request.Request(
                "https://api.github.com/repos/4i7/WorkGraph", headers=headers
            ),
            timeout=30,
        ) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, urllib.error.HTTPError, urllib.error.URLError) as exc:
        raise WorkGraphClientError("GitHub repository identity lookup failed") from exc
    if payload.get("full_name") != request.repository or payload.get("id") != request.repository_id:
        raise WorkGraphClientError("GitHub repository identity does not match the request")


def _checkout_directory(request: WorkGraphRequest, execution_key: str) -> Path:
    safe_id = hashlib.sha256(execution_key.encode("utf-8")).hexdigest()
    return Path(tempfile.gettempdir()) / "U" / safe_id[:32]


def prepare_exact_checkout(request: WorkGraphRequest, execution_key: str) -> Path:
    """Create or prove one reconstructable detached checkout for the exact SHA."""
    _verify_source_repository(request.source)
    checkout = _checkout_directory(request, execution_key)
    if checkout.exists():
        if _run_git(checkout, "rev-parse", "HEAD") != request.revision:
            raise WorkGraphClientError("existing disposable checkout has the wrong revision")
        return checkout

    checkout.parent.mkdir(parents=True, exist_ok=True)
    if _run_git(request.source, "rev-parse", "--verify", f"{request.revision}^{{commit}}") != request.revision:
        raise WorkGraphClientError("requested WorkGraph revision is not available from source")
    completed = subprocess.run(
        (_git_executable(), "-c", "core.longpaths=true", "clone", "--no-checkout", "--", str(request.source), str(checkout)),
        check=False,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise WorkGraphClientError("fixed git checkout preparation failed")
    _run_git(checkout, "remote", "remove", "origin")
    _run_git(checkout, "checkout", "--detach", request.revision)
    if _run_git(checkout, "rev-parse", "HEAD") != request.revision:
        raise WorkGraphClientError("checked-out WorkGraph HEAD does not match requested revision")
    return checkout


def _command_environment(authority_db: Path, python_executable: Path) -> dict[str, str]:
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise WorkGraphClientError("SystemRoot is required on Windows")
    temporary_directory = authority_db.parent / "temporary"
    temporary_directory.mkdir(parents=True, exist_ok=True)
    return {
        "PATH": f"{python_executable.parent};{Path(system_root) / 'System32'}",
        "PYTHONUTF8": "1",
        "SYSTEMROOT": system_root,
        "TEMP": str(temporary_directory),
        "TMP": str(temporary_directory),
    }


def build_command_spec(request: WorkGraphRequest, checkout: Path) -> LocalCommandSpec:
    wrapper = Path(__file__).with_name("umbilical_workgraph_validation.py").resolve()
    return LocalCommandSpec.snapshot(
        executable=str(request.python_executable),
        argv=(str(request.python_executable), str(wrapper), "--checkout-root", str(checkout)),
        working_directory=str(checkout),
        environment=_command_environment(request.authority_db, request.python_executable),
        timeout_seconds=request.timeout_seconds,
    )


def publish_terminal_status(
    *, request: WorkGraphRequest, target_revision: str, exit_code: int, token: str
) -> None:
    """Publish only a durable terminal validation result to its exact SHA."""
    if target_revision != request.revision:
        raise PublicationError("publication target SHA does not match requested revision")
    if _REVISION.fullmatch(target_revision) is None:
        raise PublicationError("publication target SHA is invalid")
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
                f"https://api.github.com/repos/{request.repository}/statuses/{target_revision}",
                data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST",
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
        raise WorkGraphClientError("GH_TOKEN is required for exact commit-status publication")
    return token


def _open_store(path: Path) -> AuthorityStore:
    path.parent.mkdir(parents=True, exist_ok=True)
    return AuthorityStore.open_existing(path) if path.exists() else AuthorityStore.initialize_new(path)


def run_workgraph_client(
    request: WorkGraphRequest,
    *,
    publisher: Callable[..., None] = publish_terminal_status,
) -> WorkGraphClientResult:
    """Run or observe exactly one WorkGraph validation execution authority."""
    if os.name != "nt":
        raise WorkGraphClientError("the WorkGraph first client is supported only on Windows")
    token = _require_token()
    verify_repository_identity(request, token)
    execution_key = derive_execution_key(
        repository_identity=f"github-repository-id:{request.repository_id}",
        subject_identity=_SUBJECT,
        revision_identity=request.revision,
        causal_root=_CAUSAL_ROOT,
    )

    with _open_store(request.authority_db) as store:
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
                publisher(
                    request=request, target_revision=request.revision,
                    exit_code=prior.exit_code, token=token,
                )
                return WorkGraphClientResult(
                    execution_key, prior.command_spec_hash, prior.exit_code,
                    prior.state.value, True,
                )

        checkout = prepare_exact_checkout(request, execution_key)
        command_spec = build_command_spec(request, checkout)
        command_hash = command_spec_hash(command_spec)
        if not exists:
            store.register_execution_key(execution_key)
        store.bind_command_spec_hash(execution_key, command_hash)
        admission = store.read_execution_admission(execution_key)
        if admission is None:
            generation = store.acquire_generation(_AUTHORITY_SCOPE)
            store.admit_execution(execution_key, _AUTHORITY_SCOPE, generation)
        else:
            generation = admission.controller_generation

        execution = execute_local_command(
            store,
            execution_key=execution_key,
            authority_scope=_AUTHORITY_SCOPE,
            controller_generation=generation,
            command_spec=command_spec,
        )
        publisher(
            request=request, target_revision=request.revision,
            exit_code=execution.exit_code, token=token,
        )
        return WorkGraphClientResult(
            execution_key, execution.command_spec_hash, execution.exit_code,
            ExecutionLaunchState.TERMINAL.value, True,
        )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority-db", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-id", required=True, type=int)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--python", default=sys.executable)
    arguments = parser.parse_args(argv)
    try:
        request = WorkGraphRequest(
            authority_db=Path(arguments.authority_db).resolve(),
            repository=arguments.repository,
            repository_id=arguments.repository_id,
            revision=arguments.revision,
            source=Path(arguments.source).resolve(),
            python_executable=Path(arguments.python).resolve(),
        )
        result = run_workgraph_client(request)
    except WorkGraphClientError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result.__dict__, sort_keys=True))
    if result.exit_code is None:
        return 2
    return 0 if result.exit_code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
