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
from enum import Enum
from pathlib import Path
from typing import Optional
from typing import Union

AuthorityScope = str
ExecutionKey = str
PathLike = Union[str, os.PathLike[str]]

_V1_SCHEMA_VERSION = 1
_SCHEMA_VERSION = 2
_MAX_GENERATION = (1 << 63) - 1
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


class InvalidAuthorityScopeError(ValueError):
    """Raised when a caller supplies an invalid opaque authority scope."""


class InvalidExecutionKeyError(ValueError):
    """Raised when a caller supplies an invalid opaque ExecutionKey."""


class ExecutionKeyRegistration(Enum):
    """Durable ExecutionKey registration result, without execution authority."""

    NEW = "new"
    DUPLICATE = "duplicate"


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
        """Create a new current-schema authority store, failing if it exists."""
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
            # A zero-byte, obsolete, or wrong-version store must not be turned
            # into freshly configured current authority state by opening it.
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
        """Explicitly migrate one exact valid U1A v1 store to U1B v2 in place."""
        store_path = cls._normalize_path(path)
        if not store_path.exists():
            raise AuthorityStoreMissingError(f"authority store is missing: {store_path}")

        connection: Optional[sqlite3.Connection] = None
        commit_started = False
        try:
            connection = cls._connect_rw(store_path)
            # A read-only version preflight avoids changing WAL configuration on
            # known non-v1 stores while leaving full v1 validation inside the
            # writer transaction that protects the migration itself.
            version = cls._read_schema_version(connection)
            if version != _V1_SCHEMA_VERSION:
                raise AuthorityStoreVersionError(
                    f"v1-to-v2 migration requires schema version 1, found {version}"
                )

            cls._configure_durability(connection)
            connection.execute("BEGIN IMMEDIATE")
            cls._validate_v1_store(connection)
            connection.execute(_CREATE_EXECUTION_KEYS_SQL)
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            cls._validate_store(connection)
            commit_started = True
            connection.execute("COMMIT")
        except AuthorityStoreError:
            if connection is not None:
                if commit_started:
                    # Once COMMIT has been attempted, the caller must not be told
                    # which schema version won. Discarding the connection avoids
                    # any silent retry/reset path; explicit inspection can decide.
                    connection.close()
                else:
                    try:
                        cls._rollback_migration_if_needed(connection)
                    finally:
                        connection.close()
            raise
        except sqlite3.DatabaseError as exc:
            if connection is not None:
                if commit_started:
                    connection.close()
                    raise AuthorityStoreError(
                        "v1-to-v2 migration COMMIT outcome is uncertain; "
                        "inspect the durable store explicitly"
                    ) from exc
                try:
                    cls._rollback_migration_if_needed(connection)
                finally:
                    connection.close()
            raise AuthorityStoreError("v1-to-v2 authority migration failed") from exc
        finally:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.DatabaseError:
                    pass

    @staticmethod
    def _normalize_path(path: PathLike) -> Path:
        # Do not resolve symlinks. O_CREAT|O_EXCL must observe an existing
        # symlink itself (including a broken one) rather than following it and
        # treating its absent target as permission to initialize new authority.
        expanded = os.path.expanduser(os.fspath(path))
        return Path(os.path.abspath(expanded))

    @staticmethod
    def _connect_rw(path: Path) -> sqlite3.Connection:
        # mode=rw is the critical no-create boundary for open/migration. It also
        # prevents TOCTOU disappearance from becoming a fresh empty database.
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
    def _normalized_sql(sql: str) -> str:
        return " ".join(sql.lower().split())

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
        cls._validate_versioned_store(connection, _SCHEMA_VERSION)

    @classmethod
    def _validate_v1_store(cls, connection: sqlite3.Connection) -> None:
        cls._validate_versioned_store(connection, _V1_SCHEMA_VERSION)

    @classmethod
    def _validate_versioned_store(
        cls, connection: sqlite3.Connection, expected_version: int
    ) -> None:
        try:
            integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
            if integrity_rows != [("ok",)]:
                raise AuthorityStoreMalformedError("SQLite integrity_check failed")

            version = cls._read_schema_version(connection)
            if version != expected_version:
                if expected_version == _SCHEMA_VERSION and version == _V1_SCHEMA_VERSION:
                    raise AuthorityStoreMigrationRequiredError(
                        "authority schema version 1 requires explicit v1-to-v2 migration"
                    )
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
                if not (
                    isinstance(row[1], str)
                    and row[1].startswith("sqlite_")
                )
            ]

            expected_objects = {
                "controller_generations": _CREATE_GENERATIONS_SQL,
            }
            if expected_version == _SCHEMA_VERSION:
                expected_objects["execution_keys"] = _CREATE_EXECUTION_KEYS_SQL

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
                if cls._normalized_sql(table_sql) != cls._normalized_sql(
                    expected_objects[name]
                ):
                    raise AuthorityStoreMalformedError(
                        f"{name} definition does not match authority schema"
                    )
                seen_names.add(name)
            if seen_names != set(expected_objects):
                raise AuthorityStoreMalformedError(
                    "authority schema is missing required persisted objects"
                )

            cls._validate_controller_generations_table(connection)
            if expected_version == _SCHEMA_VERSION:
                cls._validate_execution_keys_table(connection)
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
            if scope_type != "text" or not isinstance(scope, str) or scope == "":
                raise AuthorityStoreMalformedError("persisted authority scope is malformed")
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

    @staticmethod
    def _validate_scope(scope: AuthorityScope) -> None:
        if not isinstance(scope, str) or scope == "":
            raise InvalidAuthorityScopeError("AuthorityScope must be a non-empty string")

    @staticmethod
    def _validate_execution_key(execution_key: ExecutionKey) -> None:
        if type(execution_key) is not str or execution_key == "":
            raise InvalidExecutionKeyError(
                "ExecutionKey must be an exact non-empty string"
            )

    @staticmethod
    def _validate_persisted_execution_key(
        execution_key: object, sqlite_type: object
    ) -> str:
        if (
            sqlite_type != "text"
            or type(execution_key) is not str
            or execution_key == ""
        ):
            raise AuthorityStoreMalformedError(
                "persisted ExecutionKey must be a non-empty TEXT value"
            )
        return execution_key

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
    def _rollback_if_needed(connection: sqlite3.Connection) -> None:
        # Initialization has no reusable AuthorityStore instance to poison.
        # Best-effort rollback is followed by closing/discarding the connection.
        if connection.in_transaction:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.DatabaseError:
                pass

    @staticmethod
    def _rollback_migration_if_needed(connection: sqlite3.Connection) -> None:
        if connection.in_transaction:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.DatabaseError as exc:
                raise AuthorityStoreError(
                    "v1-to-v2 migration rollback failed; durable outcome requires inspection"
                ) from exc
            if connection.in_transaction:
                raise AuthorityStoreError(
                    "v1-to-v2 migration remained active after rollback; "
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
                # The store has already discarded the connection and remains
                # permanently unusable even if SQLite cannot confirm close.
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

    def acquire_generation(self, scope: AuthorityScope) -> int:
        """Atomically acquire the next durable generation for *scope*."""
        connection = self._require_usable_connection()
        self._validate_scope(scope)
        try:
            # BEGIN IMMEDIATE serializes ordinary SQLite writers before the
            # final schema/state validation. No accepted persistent schema
            # mutation can then interpose before this acquisition commits.
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
            # A deferred read transaction is enough here: the first validation
            # read establishes the WAL snapshot, and full validation plus the
            # generation lookup then observe that same snapshot. This is an
            # observation, not a writer-excluding consequential authority fence.
            connection.execute("BEGIN")
            self._validate_store(connection)
            row = connection.execute(
                "SELECT generation, typeof(generation) "
                "FROM controller_generations WHERE scope = ?",
                (scope,),
            ).fetchone()
            if row is None:
                generation = None
            else:
                generation = self._validate_persisted_generation(row[0], row[1])
            # Do not return observed evidence unless the read transaction has
            # finished normally. A failed COMMIT enters the common cleanup path.
            connection.execute("COMMIT")
            return generation
        except AuthorityStoreError:
            self._rollback_after_failure(connection)
            raise
        except sqlite3.DatabaseError as exc:
            self._rollback_after_failure(connection)
            raise AuthorityStoreError("generation read failed") from exc

    def is_current_generation(self, scope: AuthorityScope, generation: object) -> bool:
        """Compare *generation* with a validated durable snapshot observation.

        This is not an atomic consequential fence. Future consequential durable
        mutation must combine its expected generation check and mutation in one
        transaction/CAS-equivalent authority boundary.
        """
        self._require_usable_connection()
        self._validate_scope(scope)
        if type(generation) is not int or generation <= 0:
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

    def close(self) -> None:
        connection = self._connection
        self._connection = None
        if connection is not None:
            connection.close()

    def __enter__(self) -> "AuthorityStore":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()
