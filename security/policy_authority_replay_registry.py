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
ADOPTED = "ADOPTED"
ALREADY_ADOPTED = "ALREADY_ADOPTED"
ADOPTION_CONFLICT = "ADOPTION_CONFLICT"

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


@dataclass(frozen=True)
class PolicyAuthorityAdoptionResult:
    state: str
    evidence_hash: str
    store_type: str
    adoption_id: str = ""
    record_json: str = ""


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
        after_commit: Callable[[], None] | None = None,
    ) -> None:
        self._db_path = Path(db_path)
        self._max_state_age_seconds = int(max_state_age_seconds)
        self._timeout_seconds = float(timeout_seconds)
        self._now_fn = now_fn
        self._after_insert = after_insert
        self._after_commit = after_commit

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

    def adopt_if_unused(
        self,
        nonce_hashes: Sequence[str],
        *,
        registry_evidence_hash: str,
        consumed_at: str,
        adoption_id: str,
        scope_key: str,
        record_hash: str,
        record_json: str,
    ) -> PolicyAuthorityAdoptionResult:
        """Atomically reserve both legacy nonces and persist one adoption.

        This deliberately uses the same nonce table and transaction boundary as
        ``consume_if_unused``.  Exact committed retries return the original
        record; nonce or scope reuse for different content is a conflict.
        """
        hashes = tuple(str(value).strip().lower() for value in nonce_hashes)
        if (
            len(hashes) != 2
            or len(set(hashes)) != 2
            or not all(_is_sha256_hex(value) for value in hashes)
            or not _is_sha256_reference(registry_evidence_hash)
            or not _is_sha256_reference(adoption_id)
            or not _is_sha256_reference(scope_key)
            or not _is_sha256_reference(record_hash)
            or not isinstance(consumed_at, str)
            or not consumed_at.strip()
            or not isinstance(record_json, str)
            or not record_json
        ):
            return PolicyAuthorityAdoptionResult(INVALID_STATE, _sha256_reference({"state": INVALID_STATE}), self.store_type)

        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS policy_authority_adoptions (
                    adoption_id TEXT PRIMARY KEY,
                    scope_key TEXT NOT NULL UNIQUE,
                    record_hash TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    adopted_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS policy_authority_adoption_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    state_hash TEXT NOT NULL
                )
                """
            )
            connection.execute("BEGIN IMMEDIATE")
            now = float(self._now_fn())
            invalid_state = self._validate_or_initialize_metadata(
                connection,
                registry_evidence_hash=registry_evidence_hash,
                now=now,
            )
            if invalid_state is not None:
                connection.rollback()
                return PolicyAuthorityAdoptionResult(invalid_state, _sha256_reference({"state": invalid_state}), self.store_type)
            adoption_rows = connection.execute(
                "SELECT adoption_id, scope_key, record_hash FROM policy_authority_adoptions ORDER BY adoption_id"
            ).fetchall()
            adoption_metadata = connection.execute(
                "SELECT state_hash FROM policy_authority_adoption_metadata WHERE singleton = 1"
            ).fetchone()
            expected_adoption_state = self._adoption_state_hash(adoption_rows)
            if (adoption_rows and adoption_metadata is None) or (
                adoption_metadata is not None and adoption_metadata[0] != expected_adoption_state
            ):
                connection.rollback()
                return PolicyAuthorityAdoptionResult(INTEGRITY_FAILURE, _sha256_reference({"state": INTEGRITY_FAILURE}), self.store_type)

            existing = connection.execute(
                "SELECT record_hash, record_json FROM policy_authority_adoptions WHERE adoption_id = ?",
                (adoption_id,),
            ).fetchone()
            if existing is not None:
                connection.rollback()
                return PolicyAuthorityAdoptionResult(
                    ALREADY_ADOPTED,
                    _sha256_reference({"state": ALREADY_ADOPTED, "adoption_id": adoption_id, "record_hash": existing[0]}),
                    self.store_type,
                    adoption_id,
                    str(existing[1]),
                )

            scope_record = connection.execute(
                "SELECT adoption_id, record_hash FROM policy_authority_adoptions WHERE scope_key = ?",
                (scope_key,),
            ).fetchone()
            if scope_record is not None:
                connection.rollback()
                return PolicyAuthorityAdoptionResult(ADOPTION_CONFLICT, _sha256_reference({"state": ADOPTION_CONFLICT}), self.store_type)

            placeholders = ",".join("?" for _ in hashes)
            if connection.execute(
                f"SELECT 1 FROM policy_authority_consumed_nonces WHERE nonce_hash IN ({placeholders}) LIMIT 1",
                hashes,
            ).fetchone() is not None:
                connection.rollback()
                return PolicyAuthorityAdoptionResult(ADOPTION_CONFLICT, _sha256_reference({"state": ADOPTION_CONFLICT}), self.store_type)

            transaction_hash = _sha256_reference(
                {
                    "operation": "policy_authority_adoption",
                    "registry_evidence_hash": registry_evidence_hash,
                    "nonce_hashes": sorted(hashes),
                    "adoption_id": adoption_id,
                    "record_hash": record_hash,
                    "consumed_at": consumed_at,
                }
            )
            rows = tuple(
                (nonce_hash, transaction_hash, consumed_at)
                for nonce_hash in hashes
            )
            for position, row in enumerate(rows, start=1):
                connection.execute(
                    "INSERT INTO policy_authority_consumed_nonces (nonce_hash, transaction_hash, consumed_at) VALUES (?, ?, ?)",
                    row,
                )
                if self._after_insert is not None:
                    self._after_insert(position, row[0])
            connection.execute(
                "INSERT INTO policy_authority_adoptions (adoption_id, scope_key, record_hash, record_json, adopted_at) VALUES (?, ?, ?, ?, ?)",
                (adoption_id, scope_key, record_hash, record_json, consumed_at),
            )
            adoption_rows = connection.execute(
                "SELECT adoption_id, scope_key, record_hash FROM policy_authority_adoptions ORDER BY adoption_id"
            ).fetchall()
            connection.execute(
                """
                INSERT INTO policy_authority_adoption_metadata (singleton, state_hash)
                VALUES (1, ?)
                ON CONFLICT(singleton) DO UPDATE SET state_hash=excluded.state_hash
                """,
                (self._adoption_state_hash(adoption_rows),),
            )
            records = self._records(connection)
            state_hash = self._state_hash(
                registry_evidence_hash=registry_evidence_hash,
                updated_at=now,
                records=records,
            )
            connection.execute(
                "UPDATE policy_authority_replay_metadata SET updated_at = ?, state_hash = ? WHERE singleton = 1",
                (now, state_hash),
            )
            connection.commit()
            if self._after_commit is not None:
                self._after_commit()
            return PolicyAuthorityAdoptionResult(
                ADOPTED,
                _sha256_reference({"state": ADOPTED, "adoption_id": adoption_id, "record_hash": record_hash, "transaction_hash": transaction_hash}),
                self.store_type,
                adoption_id,
                record_json,
            )
        except sqlite3.IntegrityError:
            if connection is not None:
                connection.rollback()
            return PolicyAuthorityAdoptionResult(ADOPTION_CONFLICT, _sha256_reference({"state": ADOPTION_CONFLICT}), self.store_type)
        except sqlite3.OperationalError as exc:
            if connection is not None:
                connection.rollback()
                connection.close()
                connection = None
            reconciled = self._reconcile_adoption(adoption_id, record_hash)
            if reconciled is not None:
                return reconciled
            state = TIMEOUT if "locked" in str(exc).lower() or "timeout" in str(exc).lower() else UNAVAILABLE
            return PolicyAuthorityAdoptionResult(state, _sha256_reference({"state": state}), self.store_type)
        except Exception:
            if connection is not None:
                connection.rollback()
                connection.close()
                connection = None
            reconciled = self._reconcile_adoption(adoption_id, record_hash)
            if reconciled is not None:
                return reconciled
            return PolicyAuthorityAdoptionResult(PARTIAL_WRITE, _sha256_reference({"state": PARTIAL_WRITE}), self.store_type)
        finally:
            if connection is not None:
                connection.close()

    def _reconcile_adoption(self, adoption_id: str, record_hash: str) -> PolicyAuthorityAdoptionResult | None:
        try:
            raw = self.load_adoption(adoption_id)
            if raw is None:
                return None
            parsed = json.loads(raw)
            if not isinstance(parsed, dict) or parsed.get("record_hash") != record_hash:
                return None
            return PolicyAuthorityAdoptionResult(
                ALREADY_ADOPTED,
                _sha256_reference({"state": ALREADY_ADOPTED, "adoption_id": adoption_id, "record_hash": record_hash}),
                self.store_type,
                adoption_id,
                raw,
            )
        except Exception:
            return None

    @staticmethod
    def _adoption_state_hash(rows: Sequence[Sequence[object]]) -> str:
        return _sha256_reference(
            {
                "schema_version": "usbay.policy_authority_adoption_store.v1",
                "records": [[str(value) for value in row] for row in rows],
            }
        )

    def load_adoption(self, adoption_id: str) -> str | None:
        if not _is_sha256_reference(adoption_id):
            raise ValueError("invalid adoption id")
        if not self._db_path.is_file():
            return None
        connection = sqlite3.connect(f"file:{self._db_path.resolve()}?mode=ro", uri=True)
        try:
            metadata = connection.execute(
                "SELECT schema_version, registry_evidence_hash, updated_at, state_hash FROM policy_authority_replay_metadata WHERE singleton = 1"
            ).fetchone()
            if metadata is None or metadata[0] != SCHEMA_VERSION:
                raise RuntimeError("policy authority adoption store invalid")
            records = self._records(connection)
            if metadata[3] != self._state_hash(
                registry_evidence_hash=str(metadata[1]),
                updated_at=float(metadata[2]),
                records=records,
            ):
                raise RuntimeError("policy authority adoption store integrity failure")
            adoption_rows = connection.execute(
                "SELECT adoption_id, scope_key, record_hash FROM policy_authority_adoptions ORDER BY adoption_id"
            ).fetchall()
            adoption_metadata = connection.execute(
                "SELECT state_hash FROM policy_authority_adoption_metadata WHERE singleton = 1"
            ).fetchone()
            if adoption_metadata is None or adoption_metadata[0] != self._adoption_state_hash(adoption_rows):
                raise RuntimeError("policy authority adoption store integrity failure")
            row = connection.execute(
                "SELECT record_json FROM policy_authority_adoptions WHERE adoption_id = ?",
                (adoption_id,),
            ).fetchone()
            return None if row is None else str(row[0])
        except sqlite3.OperationalError as exc:
            raise RuntimeError("policy authority adoption store unavailable") from exc
        finally:
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
