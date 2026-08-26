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
from pathlib import Path
from typing import Optional
from typing import Union

AuthorityScope = str
PathLike = Union[str, os.PathLike[str]]

_SCHEMA_VERSION = 1
_MAX_GENERATION = (1 << 63) - 1
_CREATE_GENERATIONS_SQL = """
CREATE TABLE controller_generations (
    scope TEXT NOT NULL PRIMARY KEY
        CHECK(typeof(scope) = 'text' AND scope <> ''),
    generation INTEGER NOT NULL
        CHECK(typeof(generation) = 'integer' AND generation > 0)
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


class GenerationOverflowError(AuthorityStoreError):
    """Raised rather than reusing a ControllerGeneration after integer exhaustion."""


class InvalidAuthorityScopeError(ValueError):
    """Raised when a caller supplies an invalid opaque authority scope."""


class AuthorityStore:
    """SQLite-backed durable ControllerGeneration authority state.

    Callers must choose explicitly between :meth:`initialize_new` and
    :meth:`open_existing`.  No API in this class silently creates a missing
    existing store.
    """

    def __init__(self, path: Path, connection: sqlite3.Connection) -> None:
        self._path = path
        self._connection: Optional[sqlite3.Connection] = connection
        self._poisoned = False

    @classmethod
    def initialize_new(cls, path: PathLike) -> "AuthorityStore":
        """Create a new authority store, failing if *path* already exists."""
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
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            connection.execute("COMMIT")
            cls._validate_store(connection)
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
        """Open and validate existing authority state without creating it."""
        store_path = cls._normalize_path(path)
        if not store_path.exists():
            raise AuthorityStoreMissingError(f"authority store is missing: {store_path}")

        connection: Optional[sqlite3.Connection] = None
        try:
            connection = cls._connect_rw(store_path)
            # Validate before any PRAGMA that could modify a valid SQLite file.
            # A zero-byte or wrong-version store must fail without being turned
            # into a freshly configured authority database.
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

    @staticmethod
    def _normalize_path(path: PathLike) -> Path:
        # Do not resolve symlinks. O_CREAT|O_EXCL must observe an existing
        # symlink itself (including a broken one) rather than following it and
        # treating its absent target as permission to initialize new authority.
        expanded = os.path.expanduser(os.fspath(path))
        return Path(os.path.abspath(expanded))

    @staticmethod
    def _connect_rw(path: Path) -> sqlite3.Connection:
        # mode=rw is the critical no-create boundary for open_existing. It also
        # prevents a TOCTOU disappearance after the existence check from being
        # converted into a fresh empty database.
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

    @classmethod
    def _validate_store(cls, connection: sqlite3.Connection) -> None:
        try:
            integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
            if integrity_rows != [("ok",)]:
                raise AuthorityStoreMalformedError("SQLite integrity_check failed")

            version_row = connection.execute("PRAGMA user_version").fetchone()
            if version_row is None or type(version_row[0]) is not int:
                raise AuthorityStoreMalformedError("missing or malformed schema version")
            if version_row[0] != _SCHEMA_VERSION:
                raise AuthorityStoreVersionError(
                    f"unsupported authority schema version: {version_row[0]}"
                )

            schema_rows = connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_schema "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            ).fetchall()
            if len(schema_rows) != 1:
                raise AuthorityStoreMalformedError(
                    "authority schema contains unexpected persisted objects"
                )

            object_type, name, table_name, table_sql = schema_rows[0]
            if (
                object_type != "table"
                or name != "controller_generations"
                or table_name != "controller_generations"
                or not isinstance(table_sql, str)
            ):
                raise AuthorityStoreMalformedError(
                    "authority schema does not match the U1A persisted-object allowlist"
                )
            if cls._normalized_sql(table_sql) != cls._normalized_sql(
                _CREATE_GENERATIONS_SQL
            ):
                raise AuthorityStoreMalformedError(
                    "controller_generations definition does not match U1A schema"
                )

            columns = connection.execute(
                "PRAGMA table_info(controller_generations)"
            ).fetchall()
            expected = [
                (0, "scope", "TEXT", 1, None, 1),
                (1, "generation", "INTEGER", 1, None, 0),
            ]
            if columns != expected:
                raise AuthorityStoreMalformedError(
                    "controller_generations columns do not match U1A schema"
                )

            rows = connection.execute(
                "SELECT scope, typeof(scope), generation, typeof(generation) "
                "FROM controller_generations"
            ).fetchall()
            for scope, scope_type, generation, generation_type in rows:
                if scope_type != "text" or not isinstance(scope, str) or scope == "":
                    raise AuthorityStoreMalformedError(
                        "persisted authority scope is malformed"
                    )
                cls._validate_persisted_generation(generation, generation_type)
        except AuthorityStoreError:
            raise
        except sqlite3.DatabaseError as exc:
            raise AuthorityStoreMalformedError(
                "authority store validation failed"
            ) from exc

    @staticmethod
    def _validate_scope(scope: AuthorityScope) -> None:
        if not isinstance(scope, str) or scope == "":
            raise InvalidAuthorityScopeError("AuthorityScope must be a non-empty string")

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
        """Read the persisted current generation, or None if never acquired."""
        connection = self._require_usable_connection()
        self._validate_scope(scope)
        try:
            row = connection.execute(
                "SELECT generation, typeof(generation) "
                "FROM controller_generations WHERE scope = ?",
                (scope,),
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise AuthorityStoreError("generation read failed") from exc
        if row is None:
            return None
        return self._validate_persisted_generation(row[0], row[1])

    def is_current_generation(self, scope: AuthorityScope, generation: object) -> bool:
        """Observe whether *generation* matches persisted current state.

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

    def close(self) -> None:
        connection = self._connection
        self._connection = None
        if connection is not None:
            connection.close()

    def __enter__(self) -> "AuthorityStore":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()
