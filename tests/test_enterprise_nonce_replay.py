from __future__ import annotations

import threading
import time
from pathlib import Path

import gateway.app as gateway_app
from security.decision_store import RedisDecisionStore, UnavailableDecisionStore
from tests.test_decide_first import build_payload, configure_gateway


class FakeRedisNonceClient:
    def __init__(self) -> None:
        self.now = 1_700_000_000
        self.values: dict[str, tuple[str, int | None]] = {}
        self.lock = threading.Lock()
        self.fail = False

    def set(self, key, value, nx=False, ex=None):
        if self.fail:
            raise ConnectionError("redis unavailable")
        with self.lock:
            self._expire()
            if nx and key in self.values:
                return None
            expires_at = self.now + int(ex) if ex else None
            self.values[str(key)] = (str(value), expires_at)
            return True

    def _expire(self) -> None:
        expired = [
            key
            for key, (_value, expires_at) in self.values.items()
            if expires_at is not None and expires_at <= self.now
        ]
        for key in expired:
            self.values.pop(key, None)


def _latest_replay_security_event(tmp_path: Path):
    chain = gateway_app.audit_chain.load()
    events = [
        entry["decision"]
        for entry in chain
        if entry.get("action") == "replay_security_event"
    ]
    assert events
    return events[-1]


def test_replay_policy_configuration_matches_governance_defaults() -> None:
    config = gateway_app.replay_policy_config()

    assert config == {
        "nonce_ttl_seconds": 300,
        "max_clock_skew_seconds": 30,
        "max_request_age_seconds": 60,
    }


def test_redis_nonce_reservation_is_atomic_and_replay_resistant(monkeypatch) -> None:
    client = FakeRedisNonceClient()
    store = RedisDecisionStore(redis_client=client)
    results: list[bool] = []

    def reserve() -> None:
        results.append(store.reserve_nonce("nonce-hash", ttl=300))

    threads = [threading.Thread(target=reserve) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results.count(True) == 1
    assert results.count(False) == 7


def test_redis_nonce_reservation_survives_store_recreation() -> None:
    client = FakeRedisNonceClient()

    assert RedisDecisionStore(redis_client=client).reserve_nonce("nonce-hash", ttl=300) is True
    assert RedisDecisionStore(redis_client=client).reserve_nonce("nonce-hash", ttl=300) is False


def test_redis_nonce_ttl_expiry_allows_new_nonce_window() -> None:
    client = FakeRedisNonceClient()
    store = RedisDecisionStore(redis_client=client)

    assert store.reserve_nonce("nonce-hash", ttl=5) is True
    assert store.reserve_nonce("nonce-hash", ttl=5) is False
    client.now += 6

    assert store.reserve_nonce("nonce-hash", ttl=5) is True


def test_redis_nonce_outage_fails_closed() -> None:
    client = FakeRedisNonceClient()
    client.fail = True
    store = RedisDecisionStore(redis_client=client)

    try:
        store.reserve_nonce("nonce-hash", ttl=300)
    except Exception as exc:
        assert "decision_store_unavailable" in str(exc)
    else:
        raise AssertionError("Redis outage must fail closed")


def test_gateway_replay_generates_structured_audit_event(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()

    first = client.post("/decide", json=payload)
    second = client.post("/decide", json=payload)

    assert first.status_code == 200
    assert second.status_code == 403
    assert second.json()["reason"] == "replay_detected"
    event = _latest_replay_security_event(tmp_path)
    assert event["reason_code"] == "replay_detected"
    assert event["decision"] == "DENY"
    assert event["request_hash"]
    assert event["nonce_hash"]
    assert event["timestamp"]
    assert event["policy_hash"]
    assert event["node_id"] == gateway_app.gateway_id()
    assert payload["nonce"] not in str(event)


def test_gateway_old_timestamp_is_nonce_expired_and_audited(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload["timestamp"] = int(time.time()) - 120
    from tests.request_signing_helpers import sign_payload_ed25519

    payload = sign_payload_ed25519({key: value for key, value in payload.items() if key not in {"signature", "signature_alg", "pubkey_id"}})

    response = client.post("/decide", json=payload)

    assert response.status_code == 403
    assert response.json()["reason"] == "nonce_expired"
    event = _latest_replay_security_event(tmp_path)
    assert event["reason_code"] == "nonce_expired"
    assert event["decision"] == "DENY"


def test_gateway_future_timestamp_skew_is_timestamp_invalid_and_audited(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload["timestamp"] = int(time.time()) + 120
    from tests.request_signing_helpers import sign_payload_ed25519

    payload = sign_payload_ed25519({key: value for key, value in payload.items() if key not in {"signature", "signature_alg", "pubkey_id"}})

    response = client.post("/decide", json=payload)

    assert response.status_code == 403
    assert response.json()["reason"] == "timestamp_invalid"
    event = _latest_replay_security_event(tmp_path)
    assert event["reason_code"] == "timestamp_invalid"
    assert event["decision"] == "DENY"


def test_gateway_redis_outage_audits_nonce_store_unavailable(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(
        tmp_path,
        monkeypatch,
        UnavailableDecisionStore("redis_unavailable"),
    )
    payload = build_payload()

    response = client.post("/decide", json=payload)

    assert response.status_code == 403
    assert response.json()["reason"] == "redis_unavailable"
    event = _latest_replay_security_event(tmp_path)
    assert event["reason_code"] == "nonce_store_unavailable"
    assert event["decision"] == "DENY"
    assert event["request_hash"]
    assert event["nonce_hash"]
    assert event["timestamp"]
    assert event["policy_hash"]
    assert event["node_id"] == gateway_app.gateway_id()
    assert payload["nonce"] not in str(event)
