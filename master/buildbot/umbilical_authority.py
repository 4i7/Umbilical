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
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Umbilical-owned authority primitive. This module is intentionally independent
# of Buildbot's DBConnector and migrations.

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional
from typing import Union

AuthorityScope = str
ExecutionKey = str
CommandSpecHash = str
PathLike = Union[str, os.PathLike[str]]

_V1_SCHEMA_VERSION = 1
_V2_SCHEMA_VERSION = 2
_V3_SCHEMA_VERSION = 3
_V4_SCHEMA_VERSION = 4
_SCHEMA_VERSION = 5
_MAX_GENERATION = (1 << 63) - 1
_MIN_SQLITE_INTEGER = -(1 << 63)
_MAX_SQLITE_INTEGER = (1 << 63) - 1

_CREATE_GENERATIONS_SQL = """
CREATE TABLE controller_generations (
    scope TEXT NOT NULL PRIMARY KEY
        CHECK(typeof(scope) = 'text' AND scope <> ''),
    generation INTEGER NOT NULL
        CHECK(typeof(generation) = 'integer' AND generation > 0)
) WITHOUT ROWID
"""
_CREATE_EXECUTION_KEYS_SQL = """
CREATE TABLE execution_keys (
    execution_key TEXT NOT NULL PRIMARY KEY
        CHECK(typeof(execution_key) = 'text' AND execution_key <> '')
) WITHOUT ROWID
"""
_CREATE_EXECUTION_COMMAND_BINDINGS_SQL = """
CREATE TABLE execution_command_bindings (
    execution_key TEXT NOT NULL PRIMARY KEY
        CHECK(typeof(execution_key) = 'text' AND execution_key <> ''),
    command_spec_hash TEXT NOT NULL
        CHECK(typeof(command_spec_hash) = 'text' AND command_spec_hash <> '')
) WITHOUT ROWID
"""
_CREATE_EXECUTION_ADMISSIONS_SQL = """
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
_CREATE_EXECUTION_LAUNCHES_SQL = """
CREATE TABLE execution_launches (
    execution_key TEXT NOT NULL PRIMARY KEY
        CHECK(typeof(execution_key) = 'text' AND execution_key <> ''),
    command_spec_hash TEXT NOT NULL
        CHECK(typeof(command_spec_hash) = 'text' AND command_spec_hash <> ''),
    authority_scope TEXT NOT NULL
        CHECK(typeof(authority_scope) = 'text' AND authority_scope <> ''),
    controller_generation INTEGER NOT NULL
        CHECK(
            typeof(controller_generation) = 'integer'
            AND controller_generation > 0
        ),
    launch_state TEXT NOT NULL
        CHECK(
            typeof(launch_state) = 'text'
            AND launch_state IN ('intent', 'unknown', 'terminal')
        ),
    exit_code INTEGER
        CHECK(
            (launch_state IN ('intent', 'unknown') AND exit_code IS NULL)
            OR (launch_state = 'terminal' AND typeof(exit_code) = 'integer')
        )
) WITHOUT ROWID
"""


class AuthorityStoreError(RuntimeError):
    """Base exception for durable Umbilical authority-store failures."""


class AuthorityStoreExistsError(AuthorityStoreError):
    """Raised when initialization is requested for an existing path."""


class AuthorityStoreMissingError(AuthorityStoreError):
    """Raised when an existing authority store is required but absent."""


class AuthorityStoreMalformedError(AuthorityStoreError):
    """Raised when durable authority state is corrupt or structurally invalid."""


class AuthorityStoreVersionError(AuthorityStoreMalformedError):
    """Raised when the durable authority schema version is unsupported."""


class AuthorityStoreMigrationRequiredError(AuthorityStoreVersionError):
    """Raised when a valid older schema requires an explicit migration."""


class GenerationOverflowError(AuthorityStoreError):
    """Raised rather than reusing a ControllerGeneration after integer exhaustion."""


class ExecutionKeyNotRegisteredError(AuthorityStoreError):
    """Raised when an operation requires a registered ExecutionKey."""


class CommandSpecConflictError(AuthorityStoreError):
    """Raised when an ExecutionKey is already bound to a different command hash."""


class ExecutionKeyNotCommandBoundError(AuthorityStoreError):
    """Raised when execution admission requires an immutable command binding."""


class CommandSpecHashMismatchError(AuthorityStoreError):
    """Raised when a concrete U1F command does not match the immutable U1D binding."""


class ControllerGenerationNotCurrentError(AuthorityStoreError):
    """Raised when expected ControllerGeneration is not current in the write fence."""


class ExecutionAdmissionConflictError(AuthorityStoreError):
    """Raised when an ExecutionKey already has a different durable admission."""


class ExecutionAdmissionMissingError(AuthorityStoreError):
    """Raised when U1F launch claiming requires a durable execution admission."""


class ExecutionAdmissionMismatchError(AuthorityStoreError):
    """Raised when U1F launch claiming does not exactly match durable admission."""


class ExecutionLaunchAlreadyClaimedError(AuthorityStoreError):
    """Raised whenever physical launch authority was already irreversibly consumed."""


class ExecutionLaunchStateError(AuthorityStoreError):
    """Raised when a launch-state transition is not legal for an existing claim."""


class InvalidAuthorityScopeError(ValueError):
    """Raised when a caller supplies an invalid opaque authority scope."""


class InvalidExecutionKeyError(ValueError):
    """Raised when a caller supplies an invalid opaque ExecutionKey."""


class InvalidCommandSpecHashError(ValueError):
    """Raised when a caller supplies an invalid opaque CommandSpecHash."""


class InvalidControllerGenerationError(ValueError):
    """Raised when a caller supplies a value outside ControllerGeneration domain."""


class InvalidProcessExitCodeError(ValueError):
    """Raised when terminal process observation is not an exact SQLite INTEGER."""


class ExecutionKeyRegistration(Enum):
    """Durable ExecutionKey registration result, without execution authority."""

    NEW = "new"
    DUPLICATE = "duplicate"


class CommandSpecBindingResult(Enum):
    """Durable immutable command-spec binding result, without execution authority."""

    BOUND = "bound"
    ALREADY_BOUND = "already_bound"


class ExecutionAdmissionResult(Enum):
    """Result of the durable generation-fenced execution-admission transition."""

    ADMITTED = "admitted"
    ALREADY_ADMITTED = "already_admitted"


class ExecutionLaunchState(Enum):
    """Durable physical-launch evidence; no state restores launch authority."""

    INTENT = "intent"
    UNKNOWN = "unknown"
    TERMINAL = "terminal"


@dataclass(frozen=True)
class ExecutionAdmission:
    """Immutable durable admission observation; not a launch token."""

    execution_key: ExecutionKey
    authority_scope: AuthorityScope
    controller_generation: int


@dataclass(frozen=True)
class ExecutionLaunch:
    """Immutable launch observation; existence means launch authority is consumed."""

    execution_key: ExecutionKey
    command_spec_hash: CommandSpecHash
    authority_scope: AuthorityScope
    controller_generation: int
    state: ExecutionLaunchState
    exit_code: Optional[int]


class AuthorityStore:
    """SQLite-backed durable generic Umbilical authority primitives.

    Callers must choose explicitly between :meth:`initialize_new`,
    :meth:`open_existing`, and versioned migration. No API in this class
    silently creates or migrates existing authority state.
    """

    def __init__(self, path: Path, connection: sqlite3.Connection) -> None:
        self._path = path
        self._connection: Optional[sqlite3.Connection] = connection
        self._poisoned = False

    @classmethod
    def initialize_new(cls, path: PathLike) -> "AuthorityStore":
        """Create a new exact current-schema authority store, failing if it exists."""
        store_path = cls._normalize_path(path)
        try:
            fd = os.open(store_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        except FileExistsError as exc:
            raise AuthorityStoreExistsError(
                f"authority store already exists: {store_path}"
            ) from exc
        except OSError as exc:
            raise AuthorityStoreError(
                f"unable to reserve new authority store: {store_path}"
            ) from exc
        else:
            os.close(fd)

        connection: Optional[sqlite3.Connection] = None
        try:
            connection = cls._connect_rw(store_path)
            cls._configure_durability(connection)
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(_CREATE_GENERATIONS_SQL)
            connection.execute(_CREATE_EXECUTION_KEYS_SQL)
            connection.execute(_CREATE_EXECUTION_COMMAND_BINDINGS_SQL)
            connection.execute(_CREATE_EXECUTION_ADMISSIONS_SQL)
            connection.execute(_CREATE_EXECUTION_LAUNCHES_SQL)
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            cls._validate_store(connection)
            connection.execute("COMMIT")
            return cls(store_path, connection)
        except AuthorityStoreError:
            if connection is not None:
                cls._rollback_if_needed(connection)
                connection.close()
            raise
        except sqlite3.DatabaseError as exc:
            if connection is not None:
                cls._rollback_if_needed(connection)
                connection.close()
            # The reserved path is intentionally left in place. Removing it
            # could turn failed initialization into a later silent reset.
            raise AuthorityStoreError(
                f"failed to initialize authority store: {store_path}"
            ) from exc

    @classmethod
    def open_existing(cls, path: PathLike) -> "AuthorityStore":
        """Open and validate existing current-schema state without migration."""
        store_path = cls._normalize_path(path)
        if not store_path.exists():
            raise AuthorityStoreMissingError(f"authority store is missing: {store_path}")

        connection: Optional[sqlite3.Connection] = None
        try:
            connection = cls._connect_rw(store_path)
            # Validate before any PRAGMA that could modify a valid SQLite file.
            cls._validate_store(connection)
            cls._configure_durability(connection)
            return cls(store_path, connection)
        except AuthorityStoreError:
            if connection is not None:
                connection.close()
            raise
        except sqlite3.DatabaseError as exc:
            if connection is not None:
                connection.close()
            raise AuthorityStoreMalformedError(
                f"authority store is unreadable or malformed: {store_path}"
            ) from exc

    @classmethod
    def migrate_v1_to_v2(cls, path: PathLike) -> None:
        """Explicitly migrate one exact valid v1 store to exact historical v2."""
        cls._migrate_one_table(
            path,
            source_version=_V1_SCHEMA_VERSION,
            target_version=_V2_SCHEMA_VERSION,
            migration_name="v1-to-v2",
            source_validator=cls._validate_v1_store,
            target_validator=cls._validate_v2_store,
            create_sql=_CREATE_EXECUTION_KEYS_SQL,
        )

    @classmethod
    def migrate_v2_to_v3(cls, path: PathLike) -> None:
        """Explicitly migrate one exact valid v2 store to exact historical v3."""
        cls._migrate_one_table(
            path,
            source_version=_V2_SCHEMA_VERSION,
            target_version=_V3_SCHEMA_VERSION,
            migration_name="v2-to-v3",
            source_validator=cls._validate_v2_store,
            target_validator=cls._validate_v3_store,
            create_sql=_CREATE_EXECUTION_COMMAND_BINDINGS_SQL,
        )

    @classmethod
    def migrate_v3_to_v4(cls, path: PathLike) -> None:
        """Explicitly migrate one exact valid v3 store to exact historical v4."""
        cls._migrate_one_table(
            path,
            source_version=_V3_SCHEMA_VERSION,
            target_version=_V4_SCHEMA_VERSION,
            migration_name="v3-to-v4",
            source_validator=cls._validate_v3_store,
            target_validator=cls._validate_v4_store,
            create_sql=_CREATE_EXECUTION_ADMISSIONS_SQL,
        )

    @classmethod
    def migrate_v4_to_v5(cls, path: PathLike) -> None:
        """Explicitly migrate one exact valid v4 store to exact current v5."""
        cls._migrate_one_table(
            path,
            source_version=_V4_SCHEMA_VERSION,
            target_version=_SCHEMA_VERSION,
            migration_name="v4-to-v5",
            source_validator=cls._validate_v4_store,
            target_validator=cls._validate_current_store,
            create_sql=_CREATE_EXECUTION_LAUNCHES_SQL,
        )

    @classmethod
    def _migrate_one_table(
        cls,
        path: PathLike,
        *,
        source_version: int,
        target_version: int,
        migration_name: str,
        source_validator,
        target_validator,
        create_sql: str,
    ) -> None:
        """Shared exact one-step migration transaction with accepted uncertainty model."""
        store_path = cls._normalize_path(path)
        if not store_path.exists():
            raise AuthorityStoreMissingError(f"authority store is missing: {store_path}")

        connection: Optional[sqlite3.Connection] = None
        commit_started = False
        try:
            connection = cls._connect_rw(store_path)
            version = cls._read_schema_version(connection)
            if version != source_version:
                raise AuthorityStoreVersionError(
                    f"{migration_name} migration requires schema version "
                    f"{source_version}, found {version}"
                )

            cls._configure_durability(connection)
            connection.execute("BEGIN IMMEDIATE")
            source_validator(connection)
            connection.execute(create_sql)
            connection.execute(f"PRAGMA user_version = {target_version}")
            target_validator(connection)
            commit_started = True
            connection.execute("COMMIT")
        except AuthorityStoreError:
            if connection is not None:
                if commit_started:
                    connection.close()
                else:
                    try:
                        cls._rollback_migration_if_needed(connection, migration_name)
                    finally:
                        connection.close()
            raise
        except sqlite3.DatabaseError as exc:
            if connection is not None:
                if commit_started:
                    connection.close()
                    raise AuthorityStoreError(
                        f"{migration_name} migration COMMIT outcome is uncertain; "
                        "inspect the durable store explicitly"
                    ) from exc
                try:
                    cls._rollback_migration_if_needed(connection, migration_name)
                finally:
                    connection.close()
            raise AuthorityStoreError(
                f"{migration_name} authority migration failed"
            ) from exc
        finally:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.DatabaseError:
                    pass

    @staticmethod
    def _normalize_path(path: PathLike) -> Path:
        # Do not resolve symlinks. O_CREAT|O_EXCL must observe an existing
        # symlink itself (including a broken one) rather than following it.
        expanded = os.path.expanduser(os.fspath(path))
        return Path(os.path.abspath(expanded))

    @staticmethod
    def _connect_rw(path: Path) -> sqlite3.Connection:
        # mode=rw is the no-create boundary for open/migration.
        uri = f"{path.as_uri()}?mode=rw"
        try:
            return sqlite3.connect(uri, uri=True, timeout=30.0, isolation_level=None)
        except sqlite3.OperationalError as exc:
            if not path.exists():
                raise AuthorityStoreMissingError(
                    f"authority store is missing: {path}"
                ) from exc
            raise AuthorityStoreError(f"unable to open authority store: {path}") from exc

    @staticmethod
    def _configure_durability(connection: sqlite3.Connection) -> None:
        row = connection.execute("PRAGMA journal_mode=WAL").fetchone()
        if row is None or str(row[0]).lower() != "wal":
            raise AuthorityStoreError("SQLite refused required WAL journal mode")
        connection.execute("PRAGMA synchronous=FULL")
        row = connection.execute("PRAGMA synchronous").fetchone()
        if row is None or row[0] != 2:
            raise AuthorityStoreError("SQLite refused required synchronous=FULL")

    @staticmethod
    def _canonical_stored_sql(sql: str) -> str:
        if sql.startswith("\n"):
            return sql[1:]
        return sql

    @staticmethod
    def _read_schema_version(connection: sqlite3.Connection) -> int:
        try:
            version_row = connection.execute("PRAGMA user_version").fetchone()
        except sqlite3.DatabaseError as exc:
            raise AuthorityStoreMalformedError(
                "unable to read authority schema version"
            ) from exc
        if version_row is None or type(version_row[0]) is not int:
            raise AuthorityStoreMalformedError("missing or malformed schema version")
        return version_row[0]

    @classmethod
    def _validate_store(cls, connection: sqlite3.Connection) -> None:
        # Historical stores are validated exactly before migration-required is reported.
        version = cls._read_schema_version(connection)
        if version == _V1_SCHEMA_VERSION:
            cls._validate_v1_store(connection)
            raise AuthorityStoreMigrationRequiredError(
                "authority schema version 1 requires explicit v1-to-v2 migration"
            )
        if version == _V2_SCHEMA_VERSION:
            cls._validate_v2_store(connection)
            raise AuthorityStoreMigrationRequiredError(
                "authority schema version 2 requires explicit v2-to-v3 migration"
            )
        if version == _V3_SCHEMA_VERSION:
            cls._validate_v3_store(connection)
            raise AuthorityStoreMigrationRequiredError(
                "authority schema version 3 requires explicit v3-to-v4 migration"
            )
        if version == _V4_SCHEMA_VERSION:
            cls._validate_v4_store(connection)
            raise AuthorityStoreMigrationRequiredError(
                "authority schema version 4 requires explicit v4-to-v5 migration"
            )
        cls._validate_current_store(connection)

    @classmethod
    def _validate_current_store(cls, connection: sqlite3.Connection) -> None:
        cls._validate_exact_store(
            connection,
            expected_version=_SCHEMA_VERSION,
            expected_objects={
                "controller_generations": _CREATE_GENERATIONS_SQL,
                "execution_admissions": _CREATE_EXECUTION_ADMISSIONS_SQL,
                "execution_command_bindings": _CREATE_EXECUTION_COMMAND_BINDINGS_SQL,
                "execution_keys": _CREATE_EXECUTION_KEYS_SQL,
                "execution_launches": _CREATE_EXECUTION_LAUNCHES_SQL,
            },
            validate_execution_keys=True,
            validate_command_bindings=True,
            validate_admissions=True,
            validate_launches=True,
        )

    @classmethod
    def _validate_v1_store(cls, connection: sqlite3.Connection) -> None:
        cls._validate_exact_store(
            connection,
            expected_version=_V1_SCHEMA_VERSION,
            expected_objects={"controller_generations": _CREATE_GENERATIONS_SQL},
            validate_execution_keys=False,
            validate_command_bindings=False,
            validate_admissions=False,
            validate_launches=False,
        )

    @classmethod
    def _validate_v2_store(cls, connection: sqlite3.Connection) -> None:
        cls._validate_exact_store(
            connection,
            expected_version=_V2_SCHEMA_VERSION,
            expected_objects={
                "controller_generations": _CREATE_GENERATIONS_SQL,
                "execution_keys": _CREATE_EXECUTION_KEYS_SQL,
            },
            validate_execution_keys=True,
            validate_command_bindings=False,
            validate_admissions=False,
            validate_launches=False,
        )

    @classmethod
    def _validate_v3_store(cls, connection: sqlite3.Connection) -> None:
        cls._validate_exact_store(
            connection,
            expected_version=_V3_SCHEMA_VERSION,
            expected_objects={
                "controller_generations": _CREATE_GENERATIONS_SQL,
                "execution_command_bindings": _CREATE_EXECUTION_COMMAND_BINDINGS_SQL,
                "execution_keys": _CREATE_EXECUTION_KEYS_SQL,
            },
            validate_execution_keys=True,
            validate_command_bindings=True,
            validate_admissions=False,
            validate_launches=False,
        )

    @classmethod
    def _validate_v4_store(cls, connection: sqlite3.Connection) -> None:
        cls._validate_exact_store(
            connection,
            expected_version=_V4_SCHEMA_VERSION,
            expected_objects={
                "controller_generations": _CREATE_GENERATIONS_SQL,
                "execution_admissions": _CREATE_EXECUTION_ADMISSIONS_SQL,
                "execution_command_bindings": _CREATE_EXECUTION_COMMAND_BINDINGS_SQL,
                "execution_keys": _CREATE_EXECUTION_KEYS_SQL,
            },
            validate_execution_keys=True,
            validate_command_bindings=True,
            validate_admissions=True,
            validate_launches=False,
        )

    @classmethod
    def _validate_exact_store(
        cls,
        connection: sqlite3.Connection,
        *,
        expected_version: int,
        expected_objects: dict[str, str],
        validate_execution_keys: bool,
        validate_command_bindings: bool,
        validate_admissions: bool,
        validate_launches: bool,
    ) -> None:
        try:
            integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
            if integrity_rows != [("ok",)]:
                raise AuthorityStoreMalformedError("SQLite integrity_check failed")

            version = cls._read_schema_version(connection)
            if version != expected_version:
                raise AuthorityStoreVersionError(
                    f"unsupported authority schema version: {version}"
                )

            schema_rows = connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_schema "
                "ORDER BY type, name"
            ).fetchall()
            user_schema_rows = [
                row
                for row in schema_rows
                if not (isinstance(row[1], str) and row[1].startswith("sqlite_"))
            ]
            if len(user_schema_rows) != len(expected_objects):
                raise AuthorityStoreMalformedError(
                    "authority schema contains unexpected persisted objects"
                )

            seen_names = set()
            for object_type, name, table_name, table_sql in user_schema_rows:
                if (
                    object_type != "table"
                    or name not in expected_objects
                    or table_name != name
                    or not isinstance(table_sql, str)
                    or name in seen_names
                ):
                    raise AuthorityStoreMalformedError(
                        "authority schema does not match the persisted-object allowlist"
                    )
                if table_sql != cls._canonical_stored_sql(expected_objects[name]):
                    raise AuthorityStoreMalformedError(
                        f"{name} definition does not match authority schema"
                    )
                seen_names.add(name)
            if seen_names != set(expected_objects):
                raise AuthorityStoreMalformedError(
                    "authority schema is missing required persisted objects"
                )

            cls._validate_controller_generations_table(connection)
            if validate_execution_keys:
                cls._validate_execution_keys_table(connection)
            if validate_command_bindings:
                cls._validate_execution_command_bindings_table(connection)
            if validate_admissions:
                cls._validate_execution_admissions_table(connection)
            if validate_launches:
                cls._validate_execution_launches_table(connection)
        except AuthorityStoreError:
            raise
        except sqlite3.DatabaseError as exc:
            raise AuthorityStoreMalformedError(
                "authority store validation failed"
            ) from exc

    @classmethod
    def _validate_controller_generations_table(
        cls, connection: sqlite3.Connection
    ) -> None:
        columns = connection.execute(
            "PRAGMA table_info(controller_generations)"
        ).fetchall()
        expected = [
            (0, "scope", "TEXT", 1, None, 1),
            (1, "generation", "INTEGER", 1, None, 0),
        ]
        if columns != expected:
            raise AuthorityStoreMalformedError(
                "controller_generations columns do not match authority schema"
            )
        rows = connection.execute(
            "SELECT scope, typeof(scope), generation, typeof(generation) "
            "FROM controller_generations"
        ).fetchall()
        for scope, scope_type, generation, generation_type in rows:
            cls._validate_persisted_scope(scope, scope_type)
            cls._validate_persisted_generation(generation, generation_type)

    @classmethod
    def _validate_execution_keys_table(cls, connection: sqlite3.Connection) -> None:
        columns = connection.execute("PRAGMA table_info(execution_keys)").fetchall()
        expected = [(0, "execution_key", "TEXT", 1, None, 1)]
        if columns != expected:
            raise AuthorityStoreMalformedError(
                "execution_keys columns do not match U1B schema"
            )
        rows = connection.execute(
            "SELECT execution_key, typeof(execution_key) FROM execution_keys"
        ).fetchall()
        for execution_key, sqlite_type in rows:
            cls._validate_persisted_execution_key(execution_key, sqlite_type)

    @classmethod
    def _validate_execution_command_bindings_table(
        cls, connection: sqlite3.Connection
    ) -> None:
        columns = connection.execute(
            "PRAGMA table_info(execution_command_bindings)"
        ).fetchall()
        expected = [
            (0, "execution_key", "TEXT", 1, None, 1),
            (1, "command_spec_hash", "TEXT", 1, None, 0),
        ]
        if columns != expected:
            raise AuthorityStoreMalformedError(
                "execution_command_bindings columns do not match U1D schema"
            )
        rows = connection.execute(
            "SELECT b.execution_key, typeof(b.execution_key), "
            "b.command_spec_hash, typeof(b.command_spec_hash), e.execution_key "
            "FROM execution_command_bindings AS b "
            "LEFT JOIN execution_keys AS e ON e.execution_key = b.execution_key"
        ).fetchall()
        for execution_key, key_type, command_spec_hash, hash_type, registered_key in rows:
            cls._validate_persisted_execution_key(execution_key, key_type)
            cls._validate_persisted_command_spec_hash(command_spec_hash, hash_type)
            if registered_key is None:
                raise AuthorityStoreMalformedError(
                    "persisted command binding references an unregistered ExecutionKey"
                )

    @classmethod
    def _validate_execution_admissions_table(
        cls, connection: sqlite3.Connection
    ) -> None:
        columns = connection.execute(
            "PRAGMA table_info(execution_admissions)"
        ).fetchall()
        expected = [
            (0, "execution_key", "TEXT", 1, None, 1),
            (1, "authority_scope", "TEXT", 1, None, 0),
            (2, "controller_generation", "INTEGER", 1, None, 0),
        ]
        if columns != expected:
            raise AuthorityStoreMalformedError(
                "execution_admissions columns do not match U1E schema"
            )
        rows = connection.execute(
            "SELECT a.execution_key, typeof(a.execution_key), "
            "a.authority_scope, typeof(a.authority_scope), "
            "a.controller_generation, typeof(a.controller_generation), "
            "e.execution_key, b.execution_key, "
            "g.generation, typeof(g.generation) "
            "FROM execution_admissions AS a "
            "LEFT JOIN execution_keys AS e ON e.execution_key = a.execution_key "
            "LEFT JOIN execution_command_bindings AS b "
            "ON b.execution_key = a.execution_key "
            "LEFT JOIN controller_generations AS g "
            "ON g.scope = a.authority_scope"
        ).fetchall()
        for (
            execution_key,
            key_type,
            authority_scope,
            scope_type,
            admitted_generation,
            admitted_generation_type,
            registered_key,
            bound_key,
            current_generation,
            current_generation_type,
        ) in rows:
            cls._validate_persisted_execution_key(execution_key, key_type)
            cls._validate_persisted_scope(authority_scope, scope_type)
            admitted = cls._validate_persisted_generation(
                admitted_generation, admitted_generation_type
            )
            if registered_key is None:
                raise AuthorityStoreMalformedError(
                    "persisted execution admission references an unregistered ExecutionKey"
                )
            if bound_key is None:
                raise AuthorityStoreMalformedError(
                    "persisted execution admission references an unbound ExecutionKey"
                )
            if current_generation is None:
                raise AuthorityStoreMalformedError(
                    "persisted execution admission references a missing authority scope"
                )
            current = cls._validate_persisted_generation(
                current_generation, current_generation_type
            )
            if admitted > current:
                raise AuthorityStoreMalformedError(
                    "persisted execution admission generation exceeds current generation"
                )

    @classmethod
    def _validate_execution_launches_table(
        cls, connection: sqlite3.Connection
    ) -> None:
        columns = connection.execute("PRAGMA table_info(execution_launches)").fetchall()
        expected = [
            (0, "execution_key", "TEXT", 1, None, 1),
            (1, "command_spec_hash", "TEXT", 1, None, 0),
            (2, "authority_scope", "TEXT", 1, None, 0),
            (3, "controller_generation", "INTEGER", 1, None, 0),
            (4, "launch_state", "TEXT", 1, None, 0),
            (5, "exit_code", "INTEGER", 0, None, 0),
        ]
        if columns != expected:
            raise AuthorityStoreMalformedError(
                "execution_launches columns do not match U1F schema"
            )
        rows = connection.execute(
            "SELECT l.execution_key, typeof(l.execution_key), "
            "l.command_spec_hash, typeof(l.command_spec_hash), "
            "l.authority_scope, typeof(l.authority_scope), "
            "l.controller_generation, typeof(l.controller_generation), "
            "l.launch_state, typeof(l.launch_state), "
            "l.exit_code, typeof(l.exit_code), "
            "e.execution_key, b.command_spec_hash, "
            "a.authority_scope, a.controller_generation, "
            "g.generation, typeof(g.generation) "
            "FROM execution_launches AS l "
            "LEFT JOIN execution_keys AS e ON e.execution_key = l.execution_key "
            "LEFT JOIN execution_command_bindings AS b "
            "ON b.execution_key = l.execution_key "
            "LEFT JOIN execution_admissions AS a "
            "ON a.execution_key = l.execution_key "
            "LEFT JOIN controller_generations AS g "
            "ON g.scope = l.authority_scope"
        ).fetchall()
        for (
            execution_key,
            key_type,
            command_spec_hash,
            hash_type,
            authority_scope,
            scope_type,
            controller_generation,
            generation_type,
            launch_state,
            launch_state_type,
            exit_code,
            exit_code_type,
            registered_key,
            bound_hash,
            admitted_scope,
            admitted_generation,
            current_generation,
            current_generation_type,
        ) in rows:
            key = cls._validate_persisted_execution_key(execution_key, key_type)
            command_hash = cls._validate_persisted_command_spec_hash(
                command_spec_hash, hash_type
            )
            scope = cls._validate_persisted_scope(authority_scope, scope_type)
            generation = cls._validate_persisted_generation(
                controller_generation, generation_type
            )
            state = cls._validate_persisted_launch_state(
                launch_state, launch_state_type
            )
            cls._validate_persisted_exit_code(exit_code, exit_code_type, state)
            if registered_key is None:
                raise AuthorityStoreMalformedError(
                    "persisted launch references an unregistered ExecutionKey"
                )
            if bound_hash is None or bound_hash != command_hash:
                raise AuthorityStoreMalformedError(
                    "persisted launch does not match immutable CommandSpecHash binding"
                )
            if admitted_scope is None or admitted_generation is None:
                raise AuthorityStoreMalformedError(
                    "persisted launch references a missing execution admission"
                )
            if admitted_scope != scope or admitted_generation != generation:
                raise AuthorityStoreMalformedError(
                    "persisted launch does not exactly match execution admission"
                )
            if current_generation is None:
                raise AuthorityStoreMalformedError(
                    "persisted launch references a missing authority scope"
                )
            current = cls._validate_persisted_generation(
                current_generation, current_generation_type
            )
            if generation > current:
                raise AuthorityStoreMalformedError(
                    "persisted launch generation exceeds current generation"
                )
            if registered_key != key:
                raise AuthorityStoreMalformedError(
                    "persisted launch ExecutionKey relation is not exact"
                )

    @staticmethod
    def _validate_scope(scope: AuthorityScope) -> None:
        # Preserve accepted AuthorityScope runtime semantics: str subclasses are accepted.
        if not isinstance(scope, str) or scope == "":
            raise InvalidAuthorityScopeError("AuthorityScope must be a non-empty string")

    @staticmethod
    def _validate_execution_key(execution_key: ExecutionKey) -> None:
        if type(execution_key) is not str or execution_key == "":
            raise InvalidExecutionKeyError(
                "ExecutionKey must be an exact non-empty string"
            )

    @staticmethod
    def _validate_command_spec_hash(command_spec_hash: CommandSpecHash) -> None:
        if type(command_spec_hash) is not str or command_spec_hash == "":
            raise InvalidCommandSpecHashError(
                "CommandSpecHash must be an exact non-empty string"
            )
        try:
            command_spec_hash.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise InvalidCommandSpecHashError(
                "CommandSpecHash must be strictly UTF-8 encodable"
            ) from exc

    @staticmethod
    def _validate_controller_generation(generation: object) -> int:
        if type(generation) is not int or generation <= 0 or generation > _MAX_GENERATION:
            raise InvalidControllerGenerationError(
                "ControllerGeneration must be a positive SQLite INTEGER value"
            )
        return generation

    @staticmethod
    def _validate_process_exit_code(exit_code: object) -> int:
        if (
            type(exit_code) is not int
            or exit_code < _MIN_SQLITE_INTEGER
            or exit_code > _MAX_SQLITE_INTEGER
        ):
            raise InvalidProcessExitCodeError(
                "process exit code must be an exact SQLite INTEGER value"
            )
        return exit_code

    @staticmethod
    def _validate_persisted_scope(scope: object, sqlite_type: object) -> str:
        if sqlite_type != "text" or not isinstance(scope, str) or scope == "":
            raise AuthorityStoreMalformedError("persisted authority scope is malformed")
        return scope

    @staticmethod
    def _validate_persisted_execution_key(
        execution_key: object, sqlite_type: object
    ) -> str:
        if sqlite_type != "text" or type(execution_key) is not str or execution_key == "":
            raise AuthorityStoreMalformedError(
                "persisted ExecutionKey must be a non-empty TEXT value"
            )
        return execution_key

    @staticmethod
    def _validate_persisted_command_spec_hash(
        command_spec_hash: object, sqlite_type: object
    ) -> str:
        if (
            sqlite_type != "text"
            or type(command_spec_hash) is not str
            or command_spec_hash == ""
        ):
            raise AuthorityStoreMalformedError(
                "persisted CommandSpecHash must be a non-empty TEXT value"
            )
        try:
            command_spec_hash.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise AuthorityStoreMalformedError(
                "persisted CommandSpecHash must be strictly UTF-8 encodable"
            ) from exc
        return command_spec_hash

    @staticmethod
    def _validate_persisted_generation(generation: object, sqlite_type: object) -> int:
        if sqlite_type != "integer" or type(generation) is not int or generation <= 0:
            raise AuthorityStoreMalformedError(
                "persisted ControllerGeneration must be a positive INTEGER"
            )
        if generation > _MAX_GENERATION:
            raise AuthorityStoreMalformedError(
                "persisted ControllerGeneration exceeds SQLite INTEGER range"
            )
        return generation

    @staticmethod
    def _validate_persisted_launch_state(
        launch_state: object, sqlite_type: object
    ) -> ExecutionLaunchState:
        if sqlite_type != "text" or type(launch_state) is not str:
            raise AuthorityStoreMalformedError(
                "persisted launch state must be an exact TEXT value"
            )
        try:
            return ExecutionLaunchState(launch_state)
        except ValueError as exc:
            raise AuthorityStoreMalformedError(
                "persisted launch state is unsupported"
            ) from exc

    @staticmethod
    def _validate_persisted_exit_code(
        exit_code: object,
        sqlite_type: object,
        state: ExecutionLaunchState,
    ) -> Optional[int]:
        if state in (ExecutionLaunchState.INTENT, ExecutionLaunchState.UNKNOWN):
            if exit_code is not None or sqlite_type != "null":
                raise AuthorityStoreMalformedError(
                    "non-terminal launch state must not carry an exit code"
                )
            return None
        if sqlite_type != "integer" or type(exit_code) is not int:
            raise AuthorityStoreMalformedError(
                "terminal launch state requires an INTEGER exit code"
            )
        if exit_code < _MIN_SQLITE_INTEGER or exit_code > _MAX_SQLITE_INTEGER:
            raise AuthorityStoreMalformedError(
                "persisted exit code exceeds SQLite INTEGER range"
            )
        return exit_code

    @staticmethod
    def _rollback_if_needed(connection: sqlite3.Connection) -> None:
        if connection.in_transaction:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.DatabaseError:
                pass

    @staticmethod
    def _rollback_migration_if_needed(
        connection: sqlite3.Connection, migration_name: str
    ) -> None:
        if connection.in_transaction:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.DatabaseError as exc:
                raise AuthorityStoreError(
                    f"{migration_name} migration rollback failed; "
                    "durable outcome requires inspection"
                ) from exc
            if connection.in_transaction:
                raise AuthorityStoreError(
                    f"{migration_name} migration remained active after rollback; "
                    "durable outcome requires inspection"
                )

    @staticmethod
    def _rollback_transaction(connection: sqlite3.Connection) -> None:
        """Rollback hook kept narrow so rollback failure can be tested deterministically."""
        connection.execute("ROLLBACK")

    def _require_usable_connection(self) -> sqlite3.Connection:
        if self._poisoned:
            raise AuthorityStoreError(
                "authority store is poisoned after uncertain transaction cleanup"
            )
        if self._connection is None:
            raise AuthorityStoreError("authority store is closed")
        return self._connection

    def _poison(self) -> None:
        self._poisoned = True
        connection = self._connection
        self._connection = None
        if connection is not None:
            try:
                connection.close()
            except sqlite3.DatabaseError:
                pass

    def _rollback_after_failure(self, connection: sqlite3.Connection) -> None:
        try:
            if connection.in_transaction:
                self._rollback_transaction(connection)
            if connection.in_transaction:
                raise sqlite3.OperationalError(
                    "authority transaction remained active after rollback"
                )
        except sqlite3.DatabaseError as exc:
            self._poison()
            raise AuthorityStoreError(
                "authority transaction rollback failed; store permanently poisoned"
            ) from exc

    def _handle_consequential_failure(
        self,
        connection: sqlite3.Connection,
        *,
        commit_started: bool,
        operation: str,
        cause: BaseException,
    ) -> None:
        if commit_started:
            self._poison()
            raise AuthorityStoreError(
                f"{operation} COMMIT outcome is uncertain; physical launch authority "
                "must be treated as consumed until durable state is inspected"
            ) from cause
        self._rollback_after_failure(connection)
        raise cause

    def acquire_generation(self, scope: AuthorityScope) -> int:
        """Atomically acquire the next durable generation for *scope*."""
        connection = self._require_usable_connection()
        self._validate_scope(scope)
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_store(connection)
            row = connection.execute(
                "SELECT generation, typeof(generation) "
                "FROM controller_generations WHERE scope = ?",
                (scope,),
            ).fetchone()
            if row is None:
                generation = 1
                connection.execute(
                    "INSERT INTO controller_generations(scope, generation) VALUES (?, ?)",
                    (scope, generation),
                )
            else:
                current = self._validate_persisted_generation(row[0], row[1])
                if current == _MAX_GENERATION:
                    raise GenerationOverflowError(
                        "ControllerGeneration exhausted SQLite INTEGER range"
                    )
                generation = current + 1
                cursor = connection.execute(
                    "UPDATE controller_generations SET generation = ? "
                    "WHERE scope = ? AND generation = ?",
                    (generation, scope, current),
                )
                if cursor.rowcount != 1:
                    raise AuthorityStoreMalformedError(
                        "generation update did not affect exactly one authority row"
                    )
            connection.execute("COMMIT")
            return generation
        except AuthorityStoreError:
            self._rollback_after_failure(connection)
            raise
        except sqlite3.DatabaseError as exc:
            self._rollback_after_failure(connection)
            raise AuthorityStoreError("generation acquisition failed") from exc

    def read_generation(self, scope: AuthorityScope) -> Optional[int]:
        """Observe the persisted generation from one validated SQLite snapshot."""
        connection = self._require_usable_connection()
        self._validate_scope(scope)
        try:
            connection.execute("BEGIN")
            self._validate_store(connection)
            row = connection.execute(
                "SELECT generation, typeof(generation) "
                "FROM controller_generations WHERE scope = ?",
                (scope,),
            ).fetchone()
            generation = (
                None
                if row is None
                else self._validate_persisted_generation(row[0], row[1])
            )
            connection.execute("COMMIT")
            return generation
        except AuthorityStoreError:
            self._rollback_after_failure(connection)
            raise
        except sqlite3.DatabaseError as exc:
            self._rollback_after_failure(connection)
            raise AuthorityStoreError("generation read failed") from exc

    def is_current_generation(self, scope: AuthorityScope, generation: object) -> bool:
        """Compare against a validated snapshot; this is not a consequential fence."""
        self._require_usable_connection()
        self._validate_scope(scope)
        if type(generation) is not int or generation <= 0 or generation > _MAX_GENERATION:
            return False
        current = self.read_generation(scope)
        return current is not None and current == generation

    def register_execution_key(
        self, execution_key: ExecutionKey
    ) -> ExecutionKeyRegistration:
        """Register an opaque durable identity exactly once, without execution authority."""
        connection = self._require_usable_connection()
        self._validate_execution_key(execution_key)
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_store(connection)
            row = connection.execute(
                "SELECT execution_key, typeof(execution_key) "
                "FROM execution_keys WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO execution_keys(execution_key) VALUES (?)",
                    (execution_key,),
                )
                result = ExecutionKeyRegistration.NEW
            else:
                persisted = self._validate_persisted_execution_key(row[0], row[1])
                if persisted != execution_key:
                    raise AuthorityStoreMalformedError(
                        "ExecutionKey lookup violated exact identity semantics"
                    )
                result = ExecutionKeyRegistration.DUPLICATE
            connection.execute("COMMIT")
            return result
        except AuthorityStoreError:
            self._rollback_after_failure(connection)
            raise
        except sqlite3.DatabaseError as exc:
            self._rollback_after_failure(connection)
            raise AuthorityStoreError("ExecutionKey registration failed") from exc

    def execution_key_exists(self, execution_key: ExecutionKey) -> bool:
        """Observe exact durable identity existence from one validated snapshot."""
        connection = self._require_usable_connection()
        self._validate_execution_key(execution_key)
        try:
            connection.execute("BEGIN")
            self._validate_store(connection)
            row = connection.execute(
                "SELECT execution_key, typeof(execution_key) "
                "FROM execution_keys WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            exists = row is not None
            if row is not None:
                persisted = self._validate_persisted_execution_key(row[0], row[1])
                if persisted != execution_key:
                    raise AuthorityStoreMalformedError(
                        "ExecutionKey lookup violated exact identity semantics"
                    )
            connection.execute("COMMIT")
            return exists
        except AuthorityStoreError:
            self._rollback_after_failure(connection)
            raise
        except sqlite3.DatabaseError as exc:
            self._rollback_after_failure(connection)
            raise AuthorityStoreError("ExecutionKey existence read failed") from exc

    def bind_command_spec_hash(
        self,
        execution_key: ExecutionKey,
        command_spec_hash: CommandSpecHash,
    ) -> CommandSpecBindingResult:
        """Bind one registered ExecutionKey to one immutable opaque CommandSpecHash."""
        connection = self._require_usable_connection()
        self._validate_execution_key(execution_key)
        self._validate_command_spec_hash(command_spec_hash)
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_store(connection)
            registered = connection.execute(
                "SELECT execution_key, typeof(execution_key) "
                "FROM execution_keys WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            if registered is None:
                raise ExecutionKeyNotRegisteredError(
                    "CommandSpecHash binding requires a registered ExecutionKey"
                )
            persisted_key = self._validate_persisted_execution_key(
                registered[0], registered[1]
            )
            if persisted_key != execution_key:
                raise AuthorityStoreMalformedError(
                    "ExecutionKey lookup violated exact identity semantics"
                )
            row = connection.execute(
                "SELECT command_spec_hash, typeof(command_spec_hash) "
                "FROM execution_command_bindings WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO execution_command_bindings"
                    "(execution_key, command_spec_hash) VALUES (?, ?)",
                    (execution_key, command_spec_hash),
                )
                result = CommandSpecBindingResult.BOUND
            else:
                persisted_hash = self._validate_persisted_command_spec_hash(row[0], row[1])
                if persisted_hash != command_spec_hash:
                    raise CommandSpecConflictError(
                        "ExecutionKey is already bound to a different CommandSpecHash"
                    )
                result = CommandSpecBindingResult.ALREADY_BOUND
            connection.execute("COMMIT")
            return result
        except AuthorityStoreError:
            self._rollback_after_failure(connection)
            raise
        except sqlite3.DatabaseError as exc:
            self._rollback_after_failure(connection)
            raise AuthorityStoreError("CommandSpecHash binding failed") from exc

    def read_command_spec_hash(
        self, execution_key: ExecutionKey
    ) -> Optional[CommandSpecHash]:
        """Observe an optional immutable command binding for one registered key."""
        connection = self._require_usable_connection()
        self._validate_execution_key(execution_key)
        try:
            connection.execute("BEGIN")
            self._validate_store(connection)
            registered = connection.execute(
                "SELECT execution_key, typeof(execution_key) "
                "FROM execution_keys WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            if registered is None:
                raise ExecutionKeyNotRegisteredError(
                    "CommandSpecHash read requires a registered ExecutionKey"
                )
            persisted_key = self._validate_persisted_execution_key(
                registered[0], registered[1]
            )
            if persisted_key != execution_key:
                raise AuthorityStoreMalformedError(
                    "ExecutionKey lookup violated exact identity semantics"
                )
            row = connection.execute(
                "SELECT command_spec_hash, typeof(command_spec_hash) "
                "FROM execution_command_bindings WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            command_spec_hash = (
                None
                if row is None
                else self._validate_persisted_command_spec_hash(row[0], row[1])
            )
            connection.execute("COMMIT")
            return command_spec_hash
        except AuthorityStoreError:
            self._rollback_after_failure(connection)
            raise
        except sqlite3.DatabaseError as exc:
            self._rollback_after_failure(connection)
            raise AuthorityStoreError("CommandSpecHash read failed") from exc

    def admit_execution(
        self,
        execution_key: ExecutionKey,
        authority_scope: AuthorityScope,
        expected_generation: object,
    ) -> ExecutionAdmissionResult:
        """Create at most one durable admission under an atomic generation fence."""
        connection = self._require_usable_connection()
        self._validate_execution_key(execution_key)
        self._validate_scope(authority_scope)
        generation = self._validate_controller_generation(expected_generation)
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_store(connection)

            registered = connection.execute(
                "SELECT execution_key, typeof(execution_key) "
                "FROM execution_keys WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            if registered is None:
                raise ExecutionKeyNotRegisteredError(
                    "execution admission requires a registered ExecutionKey"
                )
            persisted_key = self._validate_persisted_execution_key(
                registered[0], registered[1]
            )
            if persisted_key != execution_key:
                raise AuthorityStoreMalformedError(
                    "ExecutionKey lookup violated exact identity semantics"
                )

            binding = connection.execute(
                "SELECT command_spec_hash, typeof(command_spec_hash) "
                "FROM execution_command_bindings WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            if binding is None:
                raise ExecutionKeyNotCommandBoundError(
                    "execution admission requires an immutable CommandSpecHash binding"
                )
            self._validate_persisted_command_spec_hash(binding[0], binding[1])

            generation_row = connection.execute(
                "SELECT generation, typeof(generation) "
                "FROM controller_generations WHERE scope = ?",
                (authority_scope,),
            ).fetchone()
            if generation_row is None:
                raise ControllerGenerationNotCurrentError(
                    "expected ControllerGeneration is not current"
                )
            current_generation = self._validate_persisted_generation(
                generation_row[0], generation_row[1]
            )
            if current_generation != generation:
                raise ControllerGenerationNotCurrentError(
                    "expected ControllerGeneration is not current"
                )

            admission_row = connection.execute(
                "SELECT execution_key, typeof(execution_key), "
                "authority_scope, typeof(authority_scope), "
                "controller_generation, typeof(controller_generation) "
                "FROM execution_admissions WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            if admission_row is None:
                connection.execute(
                    "INSERT INTO execution_admissions"
                    "(execution_key, authority_scope, controller_generation) "
                    "VALUES (?, ?, ?)",
                    (execution_key, authority_scope, generation),
                )
                result = ExecutionAdmissionResult.ADMITTED
            else:
                admitted_key = self._validate_persisted_execution_key(
                    admission_row[0], admission_row[1]
                )
                admitted_scope = self._validate_persisted_scope(
                    admission_row[2], admission_row[3]
                )
                admitted_generation = self._validate_persisted_generation(
                    admission_row[4], admission_row[5]
                )
                if (
                    admitted_key != execution_key
                    or admitted_scope != authority_scope
                    or admitted_generation != generation
                ):
                    raise ExecutionAdmissionConflictError(
                        "ExecutionKey already has a different durable execution admission"
                    )
                result = ExecutionAdmissionResult.ALREADY_ADMITTED

            connection.execute("COMMIT")
            return result
        except AuthorityStoreError:
            self._rollback_after_failure(connection)
            raise
        except sqlite3.DatabaseError as exc:
            self._rollback_after_failure(connection)
            raise AuthorityStoreError("execution admission failed") from exc

    def read_execution_admission(
        self, execution_key: ExecutionKey
    ) -> Optional[ExecutionAdmission]:
        """Observe durable admission history without asserting current authority."""
        connection = self._require_usable_connection()
        self._validate_execution_key(execution_key)
        try:
            connection.execute("BEGIN")
            self._validate_store(connection)
            registered = connection.execute(
                "SELECT execution_key, typeof(execution_key) "
                "FROM execution_keys WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            if registered is None:
                raise ExecutionKeyNotRegisteredError(
                    "execution admission read requires a registered ExecutionKey"
                )
            persisted_key = self._validate_persisted_execution_key(
                registered[0], registered[1]
            )
            if persisted_key != execution_key:
                raise AuthorityStoreMalformedError(
                    "ExecutionKey lookup violated exact identity semantics"
                )
            row = connection.execute(
                "SELECT execution_key, typeof(execution_key), "
                "authority_scope, typeof(authority_scope), "
                "controller_generation, typeof(controller_generation) "
                "FROM execution_admissions WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            if row is None:
                admission = None
            else:
                admitted_key = self._validate_persisted_execution_key(row[0], row[1])
                admitted_scope = self._validate_persisted_scope(row[2], row[3])
                admitted_generation = self._validate_persisted_generation(row[4], row[5])
                admission = ExecutionAdmission(
                    execution_key=admitted_key,
                    authority_scope=admitted_scope,
                    controller_generation=admitted_generation,
                )
            connection.execute("COMMIT")
            return admission
        except AuthorityStoreError:
            self._rollback_after_failure(connection)
            raise
        except sqlite3.DatabaseError as exc:
            self._rollback_after_failure(connection)
            raise AuthorityStoreError("execution admission read failed") from exc

    def claim_execution_launch(
        self,
        execution_key: ExecutionKey,
        authority_scope: AuthorityScope,
        expected_generation: object,
        command_spec_hash: CommandSpecHash,
    ) -> ExecutionLaunch:
        """Irreversibly consume one key's physical-launch authority under the fence."""
        connection = self._require_usable_connection()
        self._validate_execution_key(execution_key)
        self._validate_scope(authority_scope)
        generation = self._validate_controller_generation(expected_generation)
        self._validate_command_spec_hash(command_spec_hash)
        commit_started = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_store(connection)

            registered = connection.execute(
                "SELECT execution_key, typeof(execution_key) "
                "FROM execution_keys WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            if registered is None:
                raise ExecutionKeyNotRegisteredError(
                    "launch claim requires a registered ExecutionKey"
                )
            persisted_key = self._validate_persisted_execution_key(
                registered[0], registered[1]
            )
            if persisted_key != execution_key:
                raise AuthorityStoreMalformedError(
                    "ExecutionKey lookup violated exact identity semantics"
                )

            binding = connection.execute(
                "SELECT command_spec_hash, typeof(command_spec_hash) "
                "FROM execution_command_bindings WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            if binding is None:
                raise ExecutionKeyNotCommandBoundError(
                    "launch claim requires an immutable CommandSpecHash binding"
                )
            bound_hash = self._validate_persisted_command_spec_hash(
                binding[0], binding[1]
            )
            if bound_hash != command_spec_hash:
                raise CommandSpecHashMismatchError(
                    "concrete command does not match immutable CommandSpecHash binding"
                )

            admission = connection.execute(
                "SELECT authority_scope, typeof(authority_scope), "
                "controller_generation, typeof(controller_generation) "
                "FROM execution_admissions WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            if admission is None:
                raise ExecutionAdmissionMissingError(
                    "launch claim requires a durable ExecutionAdmission"
                )
            admitted_scope = self._validate_persisted_scope(admission[0], admission[1])
            admitted_generation = self._validate_persisted_generation(
                admission[2], admission[3]
            )
            if admitted_scope != authority_scope or admitted_generation != generation:
                raise ExecutionAdmissionMismatchError(
                    "launch claim must exactly match durable ExecutionAdmission"
                )

            generation_row = connection.execute(
                "SELECT generation, typeof(generation) "
                "FROM controller_generations WHERE scope = ?",
                (authority_scope,),
            ).fetchone()
            if generation_row is None:
                raise ControllerGenerationNotCurrentError(
                    "admitted ControllerGeneration is no longer current"
                )
            current_generation = self._validate_persisted_generation(
                generation_row[0], generation_row[1]
            )
            if current_generation != generation:
                raise ControllerGenerationNotCurrentError(
                    "admitted ControllerGeneration is no longer current"
                )

            prior = connection.execute(
                "SELECT execution_key FROM execution_launches WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            if prior is not None:
                raise ExecutionLaunchAlreadyClaimedError(
                    "ExecutionKey physical launch authority is already consumed"
                )

            connection.execute(
                "INSERT INTO execution_launches"
                "(execution_key, command_spec_hash, authority_scope, "
                "controller_generation, launch_state, exit_code) "
                "VALUES (?, ?, ?, ?, 'intent', NULL)",
                (execution_key, command_spec_hash, authority_scope, generation),
            )
            result = ExecutionLaunch(
                execution_key=execution_key,
                command_spec_hash=command_spec_hash,
                authority_scope=authority_scope,
                controller_generation=generation,
                state=ExecutionLaunchState.INTENT,
                exit_code=None,
            )
            commit_started = True
            connection.execute("COMMIT")
            return result
        except AuthorityStoreError as exc:
            self._handle_consequential_failure(
                connection,
                commit_started=commit_started,
                operation="execution launch claim",
                cause=exc,
            )
            raise AssertionError("unreachable")
        except sqlite3.DatabaseError as exc:
            self._handle_consequential_failure(
                connection,
                commit_started=commit_started,
                operation="execution launch claim",
                cause=exc,
            )
            raise AssertionError("unreachable")

    def mark_execution_launch_unknown(
        self,
        execution_key: ExecutionKey,
        command_spec_hash: CommandSpecHash,
    ) -> ExecutionLaunch:
        """Persist UNKNOWN before entering the external process-launch boundary."""
        connection = self._require_usable_connection()
        self._validate_execution_key(execution_key)
        self._validate_command_spec_hash(command_spec_hash)
        commit_started = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_store(connection)
            row = self._read_launch_row(connection, execution_key)
            if row is None:
                raise ExecutionLaunchStateError("launch intent does not exist")
            launch = self._execution_launch_from_row(row)
            if launch.command_spec_hash != command_spec_hash:
                raise CommandSpecHashMismatchError(
                    "launch state does not match concrete CommandSpecHash"
                )
            if launch.state is not ExecutionLaunchState.INTENT:
                raise ExecutionLaunchStateError(
                    "only a fresh durable launch intent can transition to UNKNOWN"
                )
            cursor = connection.execute(
                "UPDATE execution_launches SET launch_state = 'unknown' "
                "WHERE execution_key = ? AND command_spec_hash = ? "
                "AND launch_state = 'intent' AND exit_code IS NULL",
                (execution_key, command_spec_hash),
            )
            if cursor.rowcount != 1:
                raise AuthorityStoreMalformedError(
                    "UNKNOWN transition did not affect exactly one launch row"
                )
            result = ExecutionLaunch(
                execution_key=launch.execution_key,
                command_spec_hash=launch.command_spec_hash,
                authority_scope=launch.authority_scope,
                controller_generation=launch.controller_generation,
                state=ExecutionLaunchState.UNKNOWN,
                exit_code=None,
            )
            commit_started = True
            connection.execute("COMMIT")
            return result
        except AuthorityStoreError as exc:
            self._handle_consequential_failure(
                connection,
                commit_started=commit_started,
                operation="execution launch UNKNOWN transition",
                cause=exc,
            )
            raise AssertionError("unreachable")
        except sqlite3.DatabaseError as exc:
            self._handle_consequential_failure(
                connection,
                commit_started=commit_started,
                operation="execution launch UNKNOWN transition",
                cause=exc,
            )
            raise AssertionError("unreachable")

    def record_execution_terminal_result(
        self,
        execution_key: ExecutionKey,
        command_spec_hash: CommandSpecHash,
        exit_code: object,
    ) -> ExecutionLaunch:
        """Record one known process exit exactly once without restoring authority."""
        connection = self._require_usable_connection()
        self._validate_execution_key(execution_key)
        self._validate_command_spec_hash(command_spec_hash)
        terminal_exit_code = self._validate_process_exit_code(exit_code)
        commit_started = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_store(connection)
            row = self._read_launch_row(connection, execution_key)
            if row is None:
                raise ExecutionLaunchStateError("launch claim does not exist")
            launch = self._execution_launch_from_row(row)
            if launch.command_spec_hash != command_spec_hash:
                raise CommandSpecHashMismatchError(
                    "terminal result does not match launch CommandSpecHash"
                )
            if launch.state is not ExecutionLaunchState.UNKNOWN:
                raise ExecutionLaunchStateError(
                    "terminal result requires a durable UNKNOWN launch state"
                )
            cursor = connection.execute(
                "UPDATE execution_launches SET launch_state = 'terminal', exit_code = ? "
                "WHERE execution_key = ? AND command_spec_hash = ? "
                "AND launch_state = 'unknown' AND exit_code IS NULL",
                (terminal_exit_code, execution_key, command_spec_hash),
            )
            if cursor.rowcount != 1:
                raise AuthorityStoreMalformedError(
                    "terminal transition did not affect exactly one launch row"
                )
            result = ExecutionLaunch(
                execution_key=launch.execution_key,
                command_spec_hash=launch.command_spec_hash,
                authority_scope=launch.authority_scope,
                controller_generation=launch.controller_generation,
                state=ExecutionLaunchState.TERMINAL,
                exit_code=terminal_exit_code,
            )
            commit_started = True
            connection.execute("COMMIT")
            return result
        except AuthorityStoreError as exc:
            self._handle_consequential_failure(
                connection,
                commit_started=commit_started,
                operation="execution terminal-result transition",
                cause=exc,
            )
            raise AssertionError("unreachable")
        except sqlite3.DatabaseError as exc:
            self._handle_consequential_failure(
                connection,
                commit_started=commit_started,
                operation="execution terminal-result transition",
                cause=exc,
            )
            raise AssertionError("unreachable")

    def read_execution_launch(
        self, execution_key: ExecutionKey
    ) -> Optional[ExecutionLaunch]:
        """Observe durable launch history; every returned state has consumed authority."""
        connection = self._require_usable_connection()
        self._validate_execution_key(execution_key)
        try:
            connection.execute("BEGIN")
            self._validate_store(connection)
            registered = connection.execute(
                "SELECT execution_key, typeof(execution_key) "
                "FROM execution_keys WHERE execution_key = ?",
                (execution_key,),
            ).fetchone()
            if registered is None:
                raise ExecutionKeyNotRegisteredError(
                    "execution launch read requires a registered ExecutionKey"
                )
            persisted_key = self._validate_persisted_execution_key(
                registered[0], registered[1]
            )
            if persisted_key != execution_key:
                raise AuthorityStoreMalformedError(
                    "ExecutionKey lookup violated exact identity semantics"
                )
            row = self._read_launch_row(connection, execution_key)
            launch = None if row is None else self._execution_launch_from_row(row)
            connection.execute("COMMIT")
            return launch
        except AuthorityStoreError:
            self._rollback_after_failure(connection)
            raise
        except sqlite3.DatabaseError as exc:
            self._rollback_after_failure(connection)
            raise AuthorityStoreError("execution launch read failed") from exc

    @staticmethod
    def _read_launch_row(
        connection: sqlite3.Connection, execution_key: ExecutionKey
    ) -> Optional[tuple]:
        return connection.execute(
            "SELECT execution_key, typeof(execution_key), "
            "command_spec_hash, typeof(command_spec_hash), "
            "authority_scope, typeof(authority_scope), "
            "controller_generation, typeof(controller_generation), "
            "launch_state, typeof(launch_state), exit_code, typeof(exit_code) "
            "FROM execution_launches WHERE execution_key = ?",
            (execution_key,),
        ).fetchone()

    @classmethod
    def _execution_launch_from_row(cls, row: tuple) -> ExecutionLaunch:
        execution_key = cls._validate_persisted_execution_key(row[0], row[1])
        command_spec_hash = cls._validate_persisted_command_spec_hash(row[2], row[3])
        authority_scope = cls._validate_persisted_scope(row[4], row[5])
        controller_generation = cls._validate_persisted_generation(row[6], row[7])
        state = cls._validate_persisted_launch_state(row[8], row[9])
        exit_code = cls._validate_persisted_exit_code(row[10], row[11], state)
        return ExecutionLaunch(
            execution_key=execution_key,
            command_spec_hash=command_spec_hash,
            authority_scope=authority_scope,
            controller_generation=controller_generation,
            state=state,
            exit_code=exit_code,
        )

    def close(self) -> None:
        connection = self._connection
        self._connection = None
        if connection is not None:
            connection.close()

    def __enter__(self) -> "AuthorityStore":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()
