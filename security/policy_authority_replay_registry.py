from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Callable, Protocol, Sequence


CONSUMED = "CONSUMED"
ALREADY_CONSUMED = "ALREADY_CONSUMED"
UNAVAILABLE = "UNAVAILABLE"
TIMEOUT = "TIMEOUT"
INVALID_STATE = "INVALID_STATE"
STALE_STATE = "STALE_STATE"
INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
PARTIAL_WRITE = "PARTIAL_WRITE"
MALFORMED_RESPONSE = "MALFORMED_RESPONSE"

SCHEMA_VERSION = "usbay.policy_authority_replay_registry.v1"
STORE_TYPE_SQLITE = "sqlite-local"
STORE_TYPE_UNAVAILABLE = "unavailable"
SUPPORTED_STATES = frozenset(
    {
        CONSUMED,
        ALREADY_CONSUMED,
        UNAVAILABLE,
        TIMEOUT,
        INVALID_STATE,
        STALE_STATE,
        INTEGRITY_FAILURE,
        PARTIAL_WRITE,
        MALFORMED_RESPONSE,
    }
)


@dataclass(frozen=True)
class ReplayConsumptionResult:
    state: str
    evidence_hash: str
    store_type: str


class PolicyAuthorityReplayRegistry(Protocol):
    store_type: str

    def consume_if_unused(
        self,
        nonce_hashes: Sequence[str],
        *,
        registry_evidence_hash: str,
        consumed_at: str,
    ) -> ReplayConsumptionResult:
        """Atomically consume every nonce hash, or consume none of them."""


def _is_sha256_hex(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _is_sha256_reference(value: object) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and _is_sha256_hex(value.removeprefix("sha256:"))


def _sha256_reference(payload: object) -> str:
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(rendered).hexdigest()


def _result(
    state: str,
    *,
    store_type: str,
    nonce_hashes: Sequence[str],
    registry_evidence_hash: str,
) -> ReplayConsumptionResult:
    safe_hashes = sorted(value for value in nonce_hashes if _is_sha256_hex(value))
    return ReplayConsumptionResult(
        state=state,
        evidence_hash=_sha256_reference(
            {
                "schema_version": SCHEMA_VERSION,
                "state": state,
                "store_type": store_type,
                "nonce_hashes": safe_hashes,
                "registry_evidence_hash": registry_evidence_hash if _is_sha256_reference(registry_evidence_hash) else "INVALID",
            }
        ),
        store_type=store_type,
    )


class UnavailablePolicyAuthorityReplayRegistry:
    store_type = STORE_TYPE_UNAVAILABLE

    def consume_if_unused(
        self,
        nonce_hashes: Sequence[str],
        *,
        registry_evidence_hash: str,
        consumed_at: str,
    ) -> ReplayConsumptionResult:
        return _result(
            UNAVAILABLE,
            store_type=self.store_type,
            nonce_hashes=nonce_hashes,
            registry_evidence_hash=registry_evidence_hash,
        )


class SQLitePolicyAuthorityReplayRegistry:
    """Deterministic local/test adapter; this is not a provisioned production backend."""

    store_type = STORE_TYPE_SQLITE
    _schema_locks_guard = threading.Lock()
    _schema_locks: dict[str, threading.Lock] = {}

    def __init__(
        self,
        db_path: str | Path,
        *,
        max_state_age_seconds: int = 300,
        timeout_seconds: float = 30.0,
        now_fn: Callable[[], float] = time.time,
        after_insert: Callable[[int, str], None] | None = None,
    ) -> None:
        self._db_path = Path(db_path)
        self._max_state_age_seconds = int(max_state_age_seconds)
        self._timeout_seconds = float(timeout_seconds)
        self._now_fn = now_fn
        self._after_insert = after_insert

    @classmethod
    def _schema_lock(cls, db_path: Path) -> threading.Lock:
        key = str(db_path)
        with cls._schema_locks_guard:
            lock = cls._schema_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                cls._schema_locks[key] = lock
            return lock

    def _connect(self) -> sqlite3.Connection:
        if self._max_state_age_seconds <= 0 or self._timeout_seconds <= 0:
            raise ValueError("invalid replay registry configuration")
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        resolved_path = self._db_path.resolve()
        connection = sqlite3.connect(self._db_path, timeout=self._timeout_seconds)
        connection.execute(f"PRAGMA busy_timeout={int(self._timeout_seconds * 1000)}")
        with self._schema_lock(resolved_path):
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS policy_authority_replay_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version TEXT NOT NULL,
                    registry_evidence_hash TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    state_hash TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS policy_authority_consumed_nonces (
                    nonce_hash TEXT PRIMARY KEY,
                    transaction_hash TEXT NOT NULL,
                    consumed_at TEXT NOT NULL
                )
                """
            )
            connection.commit()
        return connection

    @staticmethod
    def _records(connection: sqlite3.Connection) -> list[tuple[str, str, str]]:
        rows = connection.execute(
            """
            SELECT nonce_hash, transaction_hash, consumed_at
            FROM policy_authority_consumed_nonces
            ORDER BY nonce_hash
            """
        ).fetchall()
        return [(str(nonce_hash), str(transaction_hash), str(consumed_at)) for nonce_hash, transaction_hash, consumed_at in rows]

    @staticmethod
    def _state_hash(
        *,
        registry_evidence_hash: str,
        updated_at: float,
        records: Sequence[tuple[str, str, str]],
    ) -> str:
        return _sha256_reference(
            {
                "schema_version": SCHEMA_VERSION,
                "registry_evidence_hash": registry_evidence_hash,
                "updated_at": updated_at,
                "records": [list(record) for record in records],
            }
        )

    def _validate_or_initialize_metadata(
        self,
        connection: sqlite3.Connection,
        *,
        registry_evidence_hash: str,
        now: float,
    ) -> str | None:
        row = connection.execute(
            """
            SELECT schema_version, registry_evidence_hash, updated_at, state_hash
            FROM policy_authority_replay_metadata
            WHERE singleton = 1
            """
        ).fetchone()
        records = self._records(connection)
        if row is None:
            if records:
                return INVALID_STATE
            state_hash = self._state_hash(
                registry_evidence_hash=registry_evidence_hash,
                updated_at=now,
                records=records,
            )
            connection.execute(
                """
                INSERT INTO policy_authority_replay_metadata (
                    singleton, schema_version, registry_evidence_hash, updated_at, state_hash
                ) VALUES (1, ?, ?, ?, ?)
                """,
                (SCHEMA_VERSION, registry_evidence_hash, now, state_hash),
            )
            return None

        schema_version, stored_registry_hash, updated_at, state_hash = row
        if schema_version != SCHEMA_VERSION or stored_registry_hash != registry_evidence_hash:
            return INVALID_STATE
        try:
            stored_updated_at = float(updated_at)
        except (TypeError, ValueError):
            return INVALID_STATE
        if now < stored_updated_at:
            return INVALID_STATE
        if now - stored_updated_at > self._max_state_age_seconds:
            return STALE_STATE
        expected_hash = self._state_hash(
            registry_evidence_hash=registry_evidence_hash,
            updated_at=stored_updated_at,
            records=records,
        )
        if state_hash != expected_hash:
            return INTEGRITY_FAILURE
        return None

    def consume_if_unused(
        self,
        nonce_hashes: Sequence[str],
        *,
        registry_evidence_hash: str,
        consumed_at: str,
    ) -> ReplayConsumptionResult:
        hashes = tuple(str(value).strip().lower() for value in nonce_hashes)
        if (
            len(hashes) != 2
            or len(set(hashes)) != 2
            or not all(_is_sha256_hex(value) for value in hashes)
            or not _is_sha256_reference(registry_evidence_hash)
            or not isinstance(consumed_at, str)
            or not consumed_at.strip()
        ):
            return _result(
                INVALID_STATE,
                store_type=self.store_type,
                nonce_hashes=hashes,
                registry_evidence_hash=registry_evidence_hash,
            )

        connection: sqlite3.Connection | None = None
        inserted_count = 0
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            now = float(self._now_fn())
            invalid_state = self._validate_or_initialize_metadata(
                connection,
                registry_evidence_hash=registry_evidence_hash,
                now=now,
            )
            if invalid_state is not None:
                connection.rollback()
                return _result(
                    invalid_state,
                    store_type=self.store_type,
                    nonce_hashes=hashes,
                    registry_evidence_hash=registry_evidence_hash,
                )

            placeholders = ",".join("?" for _ in hashes)
            existing = connection.execute(
                f"SELECT nonce_hash FROM policy_authority_consumed_nonces WHERE nonce_hash IN ({placeholders})",
                hashes,
            ).fetchone()
            if existing is not None:
                connection.rollback()
                return _result(
                    ALREADY_CONSUMED,
                    store_type=self.store_type,
                    nonce_hashes=hashes,
                    registry_evidence_hash=registry_evidence_hash,
                )

            transaction_hash = _sha256_reference(
                {
                    "registry_evidence_hash": registry_evidence_hash,
                    "nonce_hashes": sorted(hashes),
                    "consumed_at": consumed_at,
                }
            )
            for position, nonce_hash in enumerate(hashes, start=1):
                connection.execute(
                    """
                    INSERT INTO policy_authority_consumed_nonces (
                        nonce_hash, transaction_hash, consumed_at
                    ) VALUES (?, ?, ?)
                    """,
                    (nonce_hash, transaction_hash, consumed_at),
                )
                inserted_count += 1
                if self._after_insert is not None:
                    self._after_insert(position, nonce_hash)

            records = self._records(connection)
            state_hash = self._state_hash(
                registry_evidence_hash=registry_evidence_hash,
                updated_at=now,
                records=records,
            )
            updated = connection.execute(
                """
                UPDATE policy_authority_replay_metadata
                SET updated_at = ?, state_hash = ?
                WHERE singleton = 1
                """,
                (now, state_hash),
            )
            if updated.rowcount != 1:
                raise RuntimeError("replay metadata update failed")
            connection.commit()
            return _result(
                CONSUMED,
                store_type=self.store_type,
                nonce_hashes=hashes,
                registry_evidence_hash=registry_evidence_hash,
            )
        except sqlite3.IntegrityError:
            if connection is not None:
                connection.rollback()
            state = PARTIAL_WRITE if inserted_count else ALREADY_CONSUMED
            return _result(
                state,
                store_type=self.store_type,
                nonce_hashes=hashes,
                registry_evidence_hash=registry_evidence_hash,
            )
        except sqlite3.OperationalError as exc:
            if connection is not None:
                connection.rollback()
            message = str(exc).lower()
            state = PARTIAL_WRITE if inserted_count else TIMEOUT if "locked" in message or "timeout" in message else UNAVAILABLE
            return _result(
                state,
                store_type=self.store_type,
                nonce_hashes=hashes,
                registry_evidence_hash=registry_evidence_hash,
            )
        except Exception:
            if connection is not None:
                connection.rollback()
            return _result(
                PARTIAL_WRITE if inserted_count else UNAVAILABLE,
                store_type=self.store_type,
                nonce_hashes=hashes,
                registry_evidence_hash=registry_evidence_hash,
            )
        finally:
            if connection is not None:
                connection.close()


def default_policy_authority_replay_registry() -> PolicyAuthorityReplayRegistry:
    backend = os.getenv("USBAY_POLICY_AUTHORITY_REPLAY_BACKEND", "unavailable").strip().lower()
    if backend != "sqlite":
        return UnavailablePolicyAuthorityReplayRegistry()
    db_path = os.getenv("USBAY_POLICY_AUTHORITY_REPLAY_SQLITE_PATH")
    if not db_path:
        return UnavailablePolicyAuthorityReplayRegistry()
    try:
        max_state_age_seconds = int(os.getenv("USBAY_POLICY_AUTHORITY_REPLAY_MAX_STATE_AGE_SECONDS", "300"))
        timeout_seconds = float(os.getenv("USBAY_POLICY_AUTHORITY_REPLAY_TIMEOUT_SECONDS", "30"))
    except ValueError:
        return UnavailablePolicyAuthorityReplayRegistry()
    return SQLitePolicyAuthorityReplayRegistry(
        db_path,
        max_state_age_seconds=max_state_age_seconds,
        timeout_seconds=timeout_seconds,
    )
