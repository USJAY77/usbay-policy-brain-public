from __future__ import annotations

import hashlib
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from gateway.request_identity import VerifiedRequestIdentity, is_authenticated_request_identity
from governance.hashing import is_sha256_reference


RESERVED = "RESERVED"
REPLAY = "REPLAY"
CONFLICT = "CONFLICT"


class RequestIdentityReplayStoreError(RuntimeError):
    def __init__(self, code: str = "REQUEST_IDENTITY_REPLAY_STORE_UNAVAILABLE") -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ReplayReservation:
    status: str
    reason_code: str


class RequestIdentityReplayStore:
    """Durable, process-safe replay reservations for authenticated HTTP callers."""

    def __init__(self, path: str | Path, *, timeout_seconds: float = 0.0) -> None:
        self.path = Path(path)
        self.timeout_seconds = timeout_seconds

    def reserve(
        self,
        authenticated_identity: object,
        *,
        reserved_at: str,
    ) -> ReplayReservation:
        if not is_authenticated_request_identity(authenticated_identity):
            raise RequestIdentityReplayStoreError("REQUEST_IDENTITY_REPLAY_CONTEXT_UNVERIFIED")
        context = cast(VerifiedRequestIdentity, authenticated_identity)
        if not isinstance(reserved_at, str) or not reserved_at:
            raise RequestIdentityReplayStoreError("REQUEST_IDENTITY_REPLAY_INPUT_INVALID")
        if not all(
            is_sha256_reference(value)
            for value in (
                context.caller_scope,
                context.nonce_hash,
                context.authenticated_request_digest,
            )
        ) or not context.request_id:
            raise RequestIdentityReplayStoreError("REQUEST_IDENTITY_REPLAY_INPUT_INVALID")

        caller_scope = context.caller_scope
        authenticated_request_digest = context.authenticated_request_digest
        nonce_hash = _scoped_value_hash(caller_scope, "nonce", context.nonce_hash)
        request_id_hash = _scoped_value_hash(caller_scope, "request_id", context.request_id)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.path, timeout=self.timeout_seconds, isolation_level=None)
            try:
                self._configure_connection(connection)
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS request_identity_replay (
                        caller_scope TEXT NOT NULL,
                        scope TEXT NOT NULL CHECK (scope IN ('nonce', 'request_id')),
                        value_hash TEXT NOT NULL,
                        authenticated_request_digest TEXT NOT NULL,
                        reserved_at TEXT NOT NULL,
                        PRIMARY KEY (caller_scope, scope, value_hash)
                    )
                    """
                )
                connection.execute("BEGIN IMMEDIATE")
                existing = {
                    row[0]: row[1]
                    for row in connection.execute(
                        """
                        SELECT scope, authenticated_request_digest
                        FROM request_identity_replay
                        WHERE caller_scope = ?
                          AND ((scope = 'nonce' AND value_hash = ?)
                            OR (scope = 'request_id' AND value_hash = ?))
                        """,
                        (caller_scope, nonce_hash, request_id_hash),
                    )
                }
                if existing:
                    connection.rollback()
                    if len(existing) == 2 and all(
                        digest == authenticated_request_digest for digest in existing.values()
                    ):
                        return ReplayReservation(REPLAY, "REQUEST_IDENTITY_REPLAY")
                    return ReplayReservation(CONFLICT, "REQUEST_IDENTITY_REUSE_CONFLICT")
                self._insert_reservations(
                    connection,
                    (
                        (caller_scope, "nonce", nonce_hash, authenticated_request_digest, reserved_at),
                        (caller_scope, "request_id", request_id_hash, authenticated_request_digest, reserved_at),
                    ),
                )
                connection.commit()
                return ReplayReservation(RESERVED, "REQUEST_IDENTITY_REPLAY_RESERVED")
            finally:
                connection.close()
        except (sqlite3.Error, OSError) as exc:
            raise RequestIdentityReplayStoreError() from exc

    def _configure_connection(self, connection: sqlite3.Connection) -> None:
        timeout_ms = max(0, int(self.timeout_seconds * 1000))
        connection.execute(f"PRAGMA busy_timeout={timeout_ms}")
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                connection.execute("PRAGMA journal_mode=WAL")
                return
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() or time.monotonic() >= deadline:
                    raise
                time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))

    def _insert_reservations(
        self,
        connection: sqlite3.Connection,
        rows: tuple[tuple[str, str, str, str, str], tuple[str, str, str, str, str]],
    ) -> None:
        statement = """
            INSERT INTO request_identity_replay
                (caller_scope, scope, value_hash, authenticated_request_digest, reserved_at)
            VALUES (?, ?, ?, ?, ?)
        """
        connection.execute(statement, rows[0])
        self._after_first_insert(connection)
        connection.execute(statement, rows[1])

    def _after_first_insert(self, _connection: sqlite3.Connection) -> None:
        """Test seam for proving transaction rollback; production is a no-op."""


def _scoped_value_hash(caller_scope: str, scope: str, value: str) -> str:
    material = f"usbay.gateway.request_identity.replay.v1\x00{caller_scope}\x00{scope}\x00{value}"
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


__all__ = [
    "CONFLICT",
    "REPLAY",
    "RESERVED",
    "ReplayReservation",
    "RequestIdentityReplayStore",
    "RequestIdentityReplayStoreError",
]
