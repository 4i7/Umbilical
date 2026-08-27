# This file is part of Umbilical.
#
# Umbilical is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, version 2.
#
# Umbilical is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# Umbilical-owned minimal local execution boundary.  Scheduling, retries,
# worker coordination, logging, and Buildbot build semantics deliberately stay
# outside this module.

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from typing import Mapping
from typing import Sequence

from buildbot.umbilical_authority import AuthorityScope
from buildbot.umbilical_authority import AuthorityStore
from buildbot.umbilical_authority import CommandSpecHash
from buildbot.umbilical_authority import ExecutionKey

_COMMAND_SPEC_DOMAIN = b"umbilical-local-command-spec-v1\x00"
_MAX_FRAMED_BYTES = (1 << 64) - 1


class InvalidLocalCommandSpecError(ValueError):
    """Raised when a local command cannot have exact deterministic identity."""


@dataclass(frozen=True)
class LocalCommandSpec:
    """Immutable snapshot of the exact command passed to the local launcher.

    ``environment`` replaces the child environment; it is never implicitly
    merged with the controller's ambient environment.  ``argv`` and
    ``environment`` are tuples so caller-owned mutable containers cannot change
    between hashing, durable launch claiming, and the physical launch call.
    """

    executable: str
    argv: tuple[str, ...]
    working_directory: str
    environment: tuple[tuple[str, str], ...]
    timeout_seconds: int

    def __post_init__(self) -> None:
        _validate_text("executable", self.executable, allow_empty=False, forbid_nul=True)
        if not os.path.isabs(self.executable):
            raise InvalidLocalCommandSpecError("executable must be an absolute native path")

        if type(self.argv) is not tuple or not self.argv:
            raise InvalidLocalCommandSpecError("argv must be an exact non-empty tuple")
        for index, argument in enumerate(self.argv):
            _validate_text(f"argv[{index}]", argument, allow_empty=True, forbid_nul=True)

        _validate_text(
            "working_directory",
            self.working_directory,
            allow_empty=False,
            forbid_nul=True,
        )
        if not os.path.isabs(self.working_directory):
            raise InvalidLocalCommandSpecError(
                "working_directory must be an absolute native path"
            )

        if type(self.environment) is not tuple:
            raise InvalidLocalCommandSpecError("environment must be an exact tuple")
        previous_key_bytes = None
        seen_keys = set()
        for index, item in enumerate(self.environment):
            if type(item) is not tuple or len(item) != 2:
                raise InvalidLocalCommandSpecError(
                    f"environment[{index}] must be an exact (name, value) tuple"
                )
            name, value = item
            name_bytes = _validate_text(
                f"environment[{index}].name",
                name,
                allow_empty=False,
                forbid_nul=True,
            )
            if "=" in name:
                raise InvalidLocalCommandSpecError(
                    "environment variable names must not contain '='"
                )
            _validate_text(
                f"environment[{index}].value",
                value,
                allow_empty=True,
                forbid_nul=True,
            )
            if name in seen_keys:
                raise InvalidLocalCommandSpecError(
                    "environment variable names must be unique"
                )
            if previous_key_bytes is not None and name_bytes <= previous_key_bytes:
                raise InvalidLocalCommandSpecError(
                    "environment must be sorted by exact UTF-8 name bytes"
                )
            previous_key_bytes = name_bytes
            seen_keys.add(name)

        if type(self.timeout_seconds) is not int or self.timeout_seconds <= 0:
            raise InvalidLocalCommandSpecError(
                "timeout_seconds must be an exact positive integer"
            )
        if self.timeout_seconds > _MAX_FRAMED_BYTES:
            raise InvalidLocalCommandSpecError(
                "timeout_seconds exceeds unsigned 64-bit canonical framing"
            )

    @classmethod
    def snapshot(
        cls,
        *,
        executable: str,
        argv: Sequence[str],
        working_directory: str,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> "LocalCommandSpec":
        """Freeze caller-owned command containers before authority evaluation."""
        if isinstance(argv, (str, bytes, bytearray)):
            raise InvalidLocalCommandSpecError("argv must be a sequence of arguments")
        try:
            frozen_argv = tuple(argv)
        except TypeError as exc:
            raise InvalidLocalCommandSpecError("argv must be iterable") from exc

        if not isinstance(environment, Mapping):
            raise InvalidLocalCommandSpecError("environment must be a mapping")
        try:
            frozen_environment = tuple(environment.items())
        except (RuntimeError, TypeError) as exc:
            raise InvalidLocalCommandSpecError(
                "environment could not be snapshotted deterministically"
            ) from exc

        validated_items = []
        seen_names = set()
        for index, item in enumerate(frozen_environment):
            if type(item) is not tuple or len(item) != 2:
                raise InvalidLocalCommandSpecError(
                    f"environment item {index} is not an exact pair"
                )
            name, value = item
            name_bytes = _validate_text(
                f"environment[{index}].name",
                name,
                allow_empty=False,
                forbid_nul=True,
            )
            if "=" in name:
                raise InvalidLocalCommandSpecError(
                    "environment variable names must not contain '='"
                )
            _validate_text(
                f"environment[{index}].value",
                value,
                allow_empty=True,
                forbid_nul=True,
            )
            if name in seen_names:
                raise InvalidLocalCommandSpecError(
                    "environment variable names must be unique"
                )
            seen_names.add(name)
            validated_items.append((name_bytes, name, value))
        validated_items.sort(key=lambda item: item[0])
        frozen_environment = tuple((name, value) for _, name, value in validated_items)

        return cls(
            executable=executable,
            argv=frozen_argv,
            working_directory=working_directory,
            environment=frozen_environment,
            timeout_seconds=timeout_seconds,
        )


@dataclass(frozen=True)
class LocalExecutionResult:
    """Minimal terminal local-process observation; never future launch authority."""

    execution_key: ExecutionKey
    command_spec_hash: CommandSpecHash
    exit_code: int


class SubprocessLocalProcessLauncher:
    """Narrow synchronous process side-effect adapter.

    Buildbot's mature ``RunProcess`` remains in the imported worker substrate,
    but it also owns Twisted worker protocol, shell fallback, mutable command
    conversion, logging, timeout callbacks, and Windows JobObject policy.  U1F
    needs none of that authority.  This adapter therefore uses exact argv with
    ``shell=False`` and leaves richer process supervision for a later layer.
    """

    def launch(self, command_spec: LocalCommandSpec) -> int:
        completed = subprocess.run(
            command_spec.argv,
            executable=command_spec.executable,
            cwd=command_spec.working_directory,
            env=dict(command_spec.environment),
            timeout=command_spec.timeout_seconds,
            stdin=subprocess.DEVNULL,
            check=False,
            shell=False,
            close_fds=True,
        )
        return completed.returncode


def _validate_text(
    name: str,
    value: object,
    *,
    allow_empty: bool,
    forbid_nul: bool,
) -> bytes:
    if type(value) is not str or (not allow_empty and value == ""):
        requirement = "string" if allow_empty else "non-empty string"
        raise InvalidLocalCommandSpecError(f"{name} must be an exact {requirement}")
    if forbid_nul and "\x00" in value:
        raise InvalidLocalCommandSpecError(f"{name} must not contain NUL")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise InvalidLocalCommandSpecError(
            f"{name} must be strictly UTF-8 encodable"
        ) from exc
    if len(encoded) > _MAX_FRAMED_BYTES:
        raise InvalidLocalCommandSpecError(
            f"{name} UTF-8 byte length exceeds unsigned 64-bit framing"
        )
    return encoded


def _frame_bytes(value: bytes) -> bytes:
    if len(value) > _MAX_FRAMED_BYTES:
        raise InvalidLocalCommandSpecError(
            "canonical component exceeds unsigned 64-bit framing"
        )
    return len(value).to_bytes(8, byteorder="big", signed=False) + value


def _frame_field(name: str, value: str) -> bytes:
    return _frame_bytes(name.encode("ascii")) + _frame_bytes(
        _validate_text(name, value, allow_empty=False, forbid_nul=True)
    )


def canonical_command_spec_bytes(command_spec: LocalCommandSpec) -> bytes:
    """Return deterministic domain-separated v1 bytes for one frozen command."""
    if type(command_spec) is not LocalCommandSpec:
        raise InvalidLocalCommandSpecError(
            "command_spec must be an exact LocalCommandSpec"
        )

    payload = bytearray(_COMMAND_SPEC_DOMAIN)
    payload.extend(_frame_field("executable", command_spec.executable))

    payload.extend(_frame_bytes(b"argv"))
    payload.extend(len(command_spec.argv).to_bytes(8, byteorder="big", signed=False))
    for argument in command_spec.argv:
        payload.extend(
            _frame_bytes(
                _validate_text("argv", argument, allow_empty=True, forbid_nul=True)
            )
        )

    payload.extend(_frame_field("working_directory", command_spec.working_directory))

    payload.extend(_frame_bytes(b"environment"))
    payload.extend(
        len(command_spec.environment).to_bytes(8, byteorder="big", signed=False)
    )
    for name, value in command_spec.environment:
        payload.extend(
            _frame_bytes(
                _validate_text(
                    "environment.name", name, allow_empty=False, forbid_nul=True
                )
            )
        )
        payload.extend(
            _frame_bytes(
                _validate_text(
                    "environment.value", value, allow_empty=True, forbid_nul=True
                )
            )
        )

    payload.extend(_frame_bytes(b"timeout_seconds"))
    payload.extend(command_spec.timeout_seconds.to_bytes(8, byteorder="big", signed=False))
    return bytes(payload)


def command_spec_hash(command_spec: LocalCommandSpec) -> CommandSpecHash:
    """Hash the exact frozen local command for the existing U1D binding."""
    digest = hashlib.sha256(canonical_command_spec_bytes(command_spec)).hexdigest()
    return "ucsh1:sha256:" + digest


def execute_local_command(
    store: AuthorityStore,
    *,
    execution_key: ExecutionKey,
    authority_scope: AuthorityScope,
    controller_generation: int,
    command_spec: LocalCommandSpec,
) -> LocalExecutionResult:
    """Consume launch authority once, then make at most one physical launch call.

    The first transaction commits an irreversible launch intent under the
    generation fence.  The second transaction commits UNKNOWN before entering
    the fixed external launcher.  Therefore any exception, timeout, crash,
    handle loss, or post-launch durable-write failure can never restore launch
    authority for this ExecutionKey.
    """
    if type(command_spec) is not LocalCommandSpec:
        raise InvalidLocalCommandSpecError(
            "command_spec must be an exact LocalCommandSpec"
        )
    frozen_hash = command_spec_hash(command_spec)

    store.claim_execution_launch(
        execution_key,
        authority_scope,
        controller_generation,
        frozen_hash,
    )
    store.mark_execution_launch_unknown(execution_key, frozen_hash)

    exit_code = SubprocessLocalProcessLauncher().launch(command_spec)
    if type(exit_code) is not int:
        # UNKNOWN was committed before the launcher call; invalid observation
        # cannot be promoted to terminal authority evidence.
        raise TypeError("local process launcher must return an exact integer exit code")

    store.record_execution_terminal_result(execution_key, frozen_hash, exit_code)
    return LocalExecutionResult(
        execution_key=execution_key,
        command_spec_hash=frozen_hash,
        exit_code=exit_code,
    )
