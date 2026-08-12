from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import sqlite3
from typing import Any

from governance.hashing import sha256_reference
from security.decision_evidence_consumption_store import (
    ATOMIC_CONSUMPTION_FAILED,
    FIRST_CONSUMPTION,
    INVALID_REPLAY_KEY,
    REPLAY_BLOCKED,
    STORE_TIMEOUT,
    STORE_UNAVAILABLE,
    UNSUPPORTED_STORE,
    RedisDecisionEvidenceConsumptionStore,
    SQLiteDecisionEvidenceConsumptionStore,
    UnsupportedDecisionEvidenceConsumptionStore,
    default_consumption_store,
)


CONSUMED_AT = "2026-08-11T12:00:00Z"
RETENTION_SECONDS = 86_400


def _key(label: str = "authorization") -> str:
    return sha256_reference({"replay": label})


def _consume(store: Any, replay_key: str | None = None):
    key = replay_key or _key()
    return store.consume_if_unused(
        key,
        replay_key_hash=sha256_reference({"replay_key": key}),
        consumed_decision_evidence_hash=sha256_reference({"decision": "evidence"}),
        retention_seconds=RETENTION_SECONDS,
        consumed_at=CONSUMED_AT,
    )


def test_sqlite_first_second_and_repeated_consumption(tmp_path) -> None:
    store = SQLiteDecisionEvidenceConsumptionStore(tmp_path / "consume.db")

    assert _consume(store).result == FIRST_CONSUMPTION
    assert _consume(store).result == REPLAY_BLOCKED
    assert _consume(store).result == REPLAY_BLOCKED


def test_sqlite_rejects_invalid_replay_key(tmp_path) -> None:
    store = SQLiteDecisionEvidenceConsumptionStore(tmp_path / "consume.db")

    result = _consume(store, "caller-supplied-raw-key")

    assert result.result == INVALID_REPLAY_KEY


def test_sqlite_consumed_state_survives_store_restart(tmp_path) -> None:
    path = tmp_path / "consume.db"

    assert _consume(SQLiteDecisionEvidenceConsumptionStore(path)).result == FIRST_CONSUMPTION
    assert _consume(SQLiteDecisionEvidenceConsumptionStore(path)).result == REPLAY_BLOCKED


def test_sqlite_independent_workers_cannot_both_consume(tmp_path) -> None:
    path = tmp_path / "consume.db"
    worker_a = SQLiteDecisionEvidenceConsumptionStore(path)
    worker_b = SQLiteDecisionEvidenceConsumptionStore(path)

    results = {_consume(worker_a).result, _consume(worker_b).result}

    assert results == {FIRST_CONSUMPTION, REPLAY_BLOCKED}


def test_sqlite_concurrent_consumers_have_exactly_one_winner(tmp_path) -> None:
    path = tmp_path / "consume.db"
    key = _key("race")

    def attempt() -> str:
        return _consume(SQLiteDecisionEvidenceConsumptionStore(path), key).result

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(lambda _: attempt(), range(32)))

    assert results.count(FIRST_CONSUMPTION) == 1
    assert results.count(REPLAY_BLOCKED) == 31


def test_sqlite_store_timeout_fails_closed(monkeypatch, tmp_path) -> None:
    store = SQLiteDecisionEvidenceConsumptionStore(tmp_path / "consume.db")

    def raise_locked(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "_connect", raise_locked)

    assert _consume(store).result == STORE_TIMEOUT


def test_sqlite_atomic_exception_fails_closed(monkeypatch, tmp_path) -> None:
    store = SQLiteDecisionEvidenceConsumptionStore(tmp_path / "consume.db")

    def raise_unexpected(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        raise RuntimeError("atomic operation failed")

    monkeypatch.setattr(store, "_connect", raise_unexpected)

    assert _consume(store).result == ATOMIC_CONSUMPTION_FAILED


def test_unsupported_store_fails_closed() -> None:
    result = _consume(UnsupportedDecisionEvidenceConsumptionStore())

    assert result.result == UNSUPPORTED_STORE


def test_default_store_fails_closed_without_explicit_backend(monkeypatch) -> None:
    monkeypatch.delenv("USBAY_DECISION_CONSUMPTION_STORE", raising=False)

    result = _consume(default_consumption_store())

    assert result.result == UNSUPPORTED_STORE


class _FakeRedis:
    def __init__(self, *, mode: str = "normal") -> None:
        self.mode = mode
        self.values: dict[str, str] = {}
        self.expirations: dict[str, int] = {}

    def set(self, key: str, value: str, *, nx: bool, ex: int):
        if self.mode == "timeout":
            raise TimeoutError("redis timed out")
        if self.mode == "error":
            raise RuntimeError("redis unavailable")
        if self.mode == "unknown":
            return "OK"
        if nx and key in self.values:
            return None
        self.values[key] = value
        self.expirations[key] = ex
        return True


def test_redis_first_second_consumption_uses_set_nx_ex() -> None:
    client = _FakeRedis()
    store = RedisDecisionEvidenceConsumptionStore(client=client)

    assert _consume(store).result == FIRST_CONSUMPTION
    assert _consume(store).result == REPLAY_BLOCKED
    assert list(client.expirations.values()) == [RETENTION_SECONDS]


def test_redis_unavailable_timeout_and_unknown_response_fail_closed() -> None:
    assert _consume(RedisDecisionEvidenceConsumptionStore(client=None, redis_url=None)).result == STORE_UNAVAILABLE
    assert _consume(RedisDecisionEvidenceConsumptionStore(client=_FakeRedis(mode="timeout"))).result == STORE_TIMEOUT
    assert _consume(RedisDecisionEvidenceConsumptionStore(client=_FakeRedis(mode="error"))).result == STORE_UNAVAILABLE
    assert _consume(RedisDecisionEvidenceConsumptionStore(client=_FakeRedis(mode="unknown"))).result == ATOMIC_CONSUMPTION_FAILED


def test_redis_requires_positive_retention() -> None:
    store = RedisDecisionEvidenceConsumptionStore(client=_FakeRedis())
    key = _key("retention")

    result = store.consume_if_unused(
        key,
        replay_key_hash=sha256_reference({"replay_key": key}),
        consumed_decision_evidence_hash=sha256_reference({"decision": "evidence"}),
        retention_seconds=None,
        consumed_at=CONSUMED_AT,
    )

    assert result.result == ATOMIC_CONSUMPTION_FAILED


def test_store_records_no_raw_sensitive_data(tmp_path) -> None:
    path = tmp_path / "consume.db"
    raw_secret = "SECRET_SHOULD_NOT_APPEAR"
    store = SQLiteDecisionEvidenceConsumptionStore(path)

    assert _consume(store, _key(raw_secret)).result == FIRST_CONSUMPTION

    rendered = path.read_bytes().decode("latin1", errors="ignore")
    assert raw_secret not in rendered
    assert "token" not in rendered.lower()
    assert "password" not in rendered.lower()
