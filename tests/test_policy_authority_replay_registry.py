from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import sqlite3

from security.policy_authority_replay_registry import (
    ALREADY_CONSUMED,
    CONSUMED,
    INTEGRITY_FAILURE,
    INVALID_STATE,
    PARTIAL_WRITE,
    STALE_STATE,
    TIMEOUT,
    UNAVAILABLE,
    SQLitePolicyAuthorityReplayRegistry,
    UnavailablePolicyAuthorityReplayRegistry,
    default_policy_authority_replay_registry,
)


REGISTRY_EVIDENCE_HASH = "sha256:" + hashlib.sha256(b"signed-replay-registry").hexdigest()
CONSUMED_AT = "2026-09-02T20:00:00Z"


def _nonce_hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _pair(label: str = "approval") -> tuple[str, str]:
    return _nonce_hash(f"{label}-1"), _nonce_hash(f"{label}-2")


def _consume(registry, nonce_hashes=None):
    return registry.consume_if_unused(
        nonce_hashes or _pair(),
        registry_evidence_hash=REGISTRY_EVIDENCE_HASH,
        consumed_at=CONSUMED_AT,
    )


def test_first_transaction_consumes_both_nonces_and_replay_is_blocked(tmp_path) -> None:
    path = tmp_path / "authority-replay.db"
    registry = SQLitePolicyAuthorityReplayRegistry(path, now_fn=lambda: 1_000)

    assert _consume(registry).state == CONSUMED
    assert _consume(registry).state == ALREADY_CONSUMED

    with sqlite3.connect(path) as connection:
        stored_hashes = {
            row[0]
            for row in connection.execute(
                "SELECT nonce_hash FROM policy_authority_consumed_nonces"
            ).fetchall()
        }
    assert stored_hashes == set(_pair())


def test_concurrent_two_nonce_consumption_has_exactly_one_winner(tmp_path) -> None:
    path = tmp_path / "authority-replay.db"
    pair = _pair("concurrent")

    def attempt() -> str:
        registry = SQLitePolicyAuthorityReplayRegistry(path, now_fn=lambda: 1_000)
        return _consume(registry, pair).state

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(lambda _: attempt(), range(32)))

    assert results.count(CONSUMED) == 1
    assert results.count(ALREADY_CONSUMED) == 31


def test_second_nonce_failure_rolls_back_entire_transaction(tmp_path) -> None:
    path = tmp_path / "authority-replay.db"

    def fail_second_insert(position: int, nonce_hash: str) -> None:
        if position == 2:
            raise RuntimeError("forced second insert failure")

    failing = SQLitePolicyAuthorityReplayRegistry(
        path,
        now_fn=lambda: 1_000,
        after_insert=fail_second_insert,
    )

    assert _consume(failing).state == PARTIAL_WRITE

    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM policy_authority_consumed_nonces").fetchone()[0] == 0

    recovered = SQLitePolicyAuthorityReplayRegistry(path, now_fn=lambda: 1_000)
    assert _consume(recovered).state == CONSUMED


def test_two_instances_share_state_and_state_survives_instance_restart(tmp_path) -> None:
    path = tmp_path / "authority-replay.db"
    first_instance = SQLitePolicyAuthorityReplayRegistry(path, now_fn=lambda: 1_000)
    second_instance = SQLitePolicyAuthorityReplayRegistry(path, now_fn=lambda: 1_001)

    assert _consume(first_instance).state == CONSUMED
    assert _consume(second_instance).state == ALREADY_CONSUMED

    restarted_instance = SQLitePolicyAuthorityReplayRegistry(path, now_fn=lambda: 1_002)
    assert _consume(restarted_instance).state == ALREADY_CONSUMED


def test_locked_sqlite_backend_returns_timeout(monkeypatch, tmp_path) -> None:
    registry = SQLitePolicyAuthorityReplayRegistry(tmp_path / "authority-replay.db")

    def locked_connection():
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(registry, "_connect", locked_connection)

    assert _consume(registry).state == TIMEOUT


def test_stale_registry_state_fails_closed(tmp_path) -> None:
    path = tmp_path / "authority-replay.db"
    current = SQLitePolicyAuthorityReplayRegistry(path, max_state_age_seconds=10, now_fn=lambda: 1_000)
    assert _consume(current, _pair("initial")).state == CONSUMED

    stale = SQLitePolicyAuthorityReplayRegistry(path, max_state_age_seconds=10, now_fn=lambda: 1_011)
    assert _consume(stale, _pair("later")).state == STALE_STATE


def test_tampered_durable_state_fails_integrity_validation(tmp_path) -> None:
    path = tmp_path / "authority-replay.db"
    registry = SQLitePolicyAuthorityReplayRegistry(path, now_fn=lambda: 1_000)
    assert _consume(registry, _pair("initial")).state == CONSUMED

    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE policy_authority_consumed_nonces SET transaction_hash = ?",
            ("sha256:" + "0" * 64,),
        )

    assert _consume(registry, _pair("later")).state == INTEGRITY_FAILURE


def test_unavailable_and_invalid_configuration_fail_closed(monkeypatch, tmp_path) -> None:
    assert _consume(UnavailablePolicyAuthorityReplayRegistry()).state == UNAVAILABLE

    monkeypatch.delenv("USBAY_POLICY_AUTHORITY_REPLAY_BACKEND", raising=False)
    assert _consume(default_policy_authority_replay_registry()).state == UNAVAILABLE

    invalid = SQLitePolicyAuthorityReplayRegistry(tmp_path / "authority-replay.db", max_state_age_seconds=0)
    assert _consume(invalid).state == UNAVAILABLE


def test_invalid_nonce_bundle_is_rejected_without_writing(tmp_path) -> None:
    path = tmp_path / "authority-replay.db"
    registry = SQLitePolicyAuthorityReplayRegistry(path)

    result = _consume(registry, (_nonce_hash("same"), _nonce_hash("same")))

    assert result.state == INVALID_STATE
    assert not path.exists()


def test_store_contains_hashes_only_not_raw_approval_nonces(tmp_path) -> None:
    path = tmp_path / "authority-replay.db"
    raw_nonce_1 = "raw-human-approval-nonce-one"
    raw_nonce_2 = "raw-human-approval-nonce-two"
    registry = SQLitePolicyAuthorityReplayRegistry(path, now_fn=lambda: 1_000)

    result = _consume(registry, (_nonce_hash(raw_nonce_1), _nonce_hash(raw_nonce_2)))
    rendered = path.read_bytes().decode("latin1", errors="ignore")

    assert result.state == CONSUMED
    assert raw_nonce_1 not in rendered
    assert raw_nonce_2 not in rendered
