from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
import sqlite3
from pathlib import Path
from typing import Any, Protocol

from governance.hashing import is_sha256_reference

try:
    import redis
except ImportError:  # pragma: no cover - exercised only when redis-py is absent.
    redis = None


FIRST_CONSUMPTION = "FIRST_CONSUMPTION"
REPLAY_BLOCKED = "REPLAY_BLOCKED"
STORE_UNAVAILABLE = "STORE_UNAVAILABLE"
STORE_TIMEOUT = "STORE_TIMEOUT"
ATOMIC_CONSUMPTION_FAILED = "ATOMIC_CONSUMPTION_FAILED"
INVALID_REPLAY_KEY = "INVALID_REPLAY_KEY"
UNSUPPORTED_STORE = "UNSUPPORTED_STORE"

DEFAULT_SQLITE_PATH = Path("tmp/decision_evidence_consumption.db")
DEFAULT_REDIS_URL = os.getenv("USBAY_REDIS_URL") or os.getenv("REDIS_URL")
SUPPORTED_RESULTS = frozenset(
    {
        FIRST_CONSUMPTION,
        REPLAY_BLOCKED,
        STORE_UNAVAILABLE,
        STORE_TIMEOUT,
        ATOMIC_CONSUMPTION_FAILED,
        INVALID_REPLAY_KEY,
        UNSUPPORTED_STORE,
    }
)


@dataclass(frozen=True)
class ConsumptionResult:
    result: str
    reason_code: str
    store_type: str


class DecisionEvidenceConsumptionStore(Protocol):
    store_type: str

    def consume_if_unused(
        self,
        replay_key: str,
        *,
        replay_key_hash: str,
        consumed_decision_evidence_hash: str,
        retention_seconds: int | None,
        consumed_at: str,
    ) -> ConsumptionResult:
        ...


def validate_replay_key(replay_key: str) -> bool:
    return is_sha256_reference(replay_key)


def _invalid_result(store_type: str) -> ConsumptionResult:
    return ConsumptionResult(INVALID_REPLAY_KEY, INVALID_REPLAY_KEY, store_type)


def _store_unavailable(store_type: str) -> ConsumptionResult:
    return ConsumptionResult(STORE_UNAVAILABLE, STORE_UNAVAILABLE, store_type)


class SQLiteDecisionEvidenceConsumptionStore:
    """Durable local/test store using a transactional unique-key insert."""

    store_type = "sqlite"

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = Path(db_path or DEFAULT_SQLITE_PATH)

    def _connect(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS decision_evidence_consumption (
                replay_key TEXT PRIMARY KEY,
                replay_key_hash TEXT NOT NULL,
                consumed_decision_evidence_hash TEXT NOT NULL,
                consumed_at TEXT NOT NULL,
                retention_seconds INTEGER
            )
            """
        )
        return conn

    def consume_if_unused(
        self,
        replay_key: str,
        *,
        replay_key_hash: str,
        consumed_decision_evidence_hash: str,
        retention_seconds: int | None,
        consumed_at: str,
    ) -> ConsumptionResult:
        if not validate_replay_key(replay_key):
            return _invalid_result(self.store_type)
        try:
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO decision_evidence_consumption (
                            replay_key,
                            replay_key_hash,
                            consumed_decision_evidence_hash,
                            consumed_at,
                            retention_seconds
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            replay_key,
                            replay_key_hash,
                            consumed_decision_evidence_hash,
                            consumed_at,
                            retention_seconds,
                        ),
                    )
                return ConsumptionResult(FIRST_CONSUMPTION, FIRST_CONSUMPTION, self.store_type)
            finally:
                conn.close()
        except sqlite3.IntegrityError:
            return ConsumptionResult(REPLAY_BLOCKED, REPLAY_BLOCKED, self.store_type)
        except sqlite3.OperationalError as exc:
            message = str(exc).lower()
            if "timeout" in message or "locked" in message:
                return ConsumptionResult(STORE_TIMEOUT, STORE_TIMEOUT, self.store_type)
            return _store_unavailable(self.store_type)
        except Exception:
            return ConsumptionResult(ATOMIC_CONSUMPTION_FAILED, ATOMIC_CONSUMPTION_FAILED, self.store_type)


class RedisDecisionEvidenceConsumptionStore:
    """Distributed production store using Redis SET NX EX as one atomic operation."""

    store_type = "redis"

    def __init__(self, redis_url: str | None = None, *, client: Any | None = None) -> None:
        self._redis_url = redis_url or DEFAULT_REDIS_URL
        self._client = client

    def _get_client(self) -> Any | None:
        if self._client is not None:
            return self._client
        if redis is None or not self._redis_url:
            return None
        self._client = redis.Redis.from_url(self._redis_url, decode_responses=True)
        return self._client

    def consume_if_unused(
        self,
        replay_key: str,
        *,
        replay_key_hash: str,
        consumed_decision_evidence_hash: str,
        retention_seconds: int | None,
        consumed_at: str,
    ) -> ConsumptionResult:
        if not validate_replay_key(replay_key):
            return _invalid_result(self.store_type)
        if retention_seconds is None or retention_seconds <= 0:
            return ConsumptionResult(ATOMIC_CONSUMPTION_FAILED, ATOMIC_CONSUMPTION_FAILED, self.store_type)
        client = self._get_client()
        if client is None:
            return _store_unavailable(self.store_type)
        value = (
            f"consumed_at={consumed_at};"
            f"replay_key_hash={replay_key_hash};"
            f"decision_evidence_hash={consumed_decision_evidence_hash}"
        )
        try:
            stored = client.set(
                f"ai-act-decision-consumption:{replay_key.removeprefix('sha256:')}",
                value,
                nx=True,
                ex=retention_seconds,
            )
        except TimeoutError:
            return ConsumptionResult(STORE_TIMEOUT, STORE_TIMEOUT, self.store_type)
        except Exception:
            return _store_unavailable(self.store_type)
        if stored is True:
            return ConsumptionResult(FIRST_CONSUMPTION, FIRST_CONSUMPTION, self.store_type)
        if stored in {False, None}:
            return ConsumptionResult(REPLAY_BLOCKED, REPLAY_BLOCKED, self.store_type)
        return ConsumptionResult(ATOMIC_CONSUMPTION_FAILED, ATOMIC_CONSUMPTION_FAILED, self.store_type)


class UnsupportedDecisionEvidenceConsumptionStore:
    store_type = "unsupported"

    def consume_if_unused(
        self,
        replay_key: str,
        *,
        replay_key_hash: str,
        consumed_decision_evidence_hash: str,
        retention_seconds: int | None,
        consumed_at: str,
    ) -> ConsumptionResult:
        return ConsumptionResult(UNSUPPORTED_STORE, UNSUPPORTED_STORE, self.store_type)


def default_consumption_store() -> DecisionEvidenceConsumptionStore:
    backend = os.getenv("USBAY_DECISION_CONSUMPTION_STORE", "unsupported").strip().lower()
    if backend == "redis":
        return RedisDecisionEvidenceConsumptionStore()
    if backend == "sqlite":
        return SQLiteDecisionEvidenceConsumptionStore(os.getenv("USBAY_DECISION_CONSUMPTION_SQLITE_PATH") or DEFAULT_SQLITE_PATH)
    return UnsupportedDecisionEvidenceConsumptionStore()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
