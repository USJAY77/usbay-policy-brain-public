import json

import gateway.app as gateway_app
from security.persistent_nonce_store import (
    LocalPersistentNonceStore,
    PersistentNonceStoreError,
    initialize_persistent_nonce_store,
)


FIXED_TIMESTAMP = "2026-06-12T00:00:00Z"


def _record(nonce_value="nonce-pb295"):
    return {
        "decision_id": "decision-pb295",
        "nonce_hash": gateway_app.nonce_hash(nonce_value),
        "request_hash": "r" * 64,
        "policy_hash": "p" * 64,
        "policy_version": "policy-v1",
    }


def _payload(nonce_value="nonce-pb295"):
    return {
        "decision_id": "decision-pb295",
        "nonce": nonce_value,
        "policy_version": "policy-v1",
    }


def test_persistent_nonce_first_request_reserves_hash_and_replay_denies(tmp_path):
    path = tmp_path / "runtime_nonce_store.json"
    initialize_persistent_nonce_store(path)
    store = LocalPersistentNonceStore(path, ttl_seconds=300, now_fn=lambda: 1000)

    first = gateway_app.validate_nonce_replay_for_runtime(
        _payload(),
        _record(),
        persistent_nonce_store_adapter=store,
        timestamp=FIXED_TIMESTAMP,
    )
    replay = gateway_app.validate_nonce_replay_for_runtime(
        _payload(),
        _record(),
        persistent_nonce_store_adapter=store,
        timestamp=FIXED_TIMESTAMP,
    )
    stored = json.loads(path.read_text(encoding="utf-8"))

    assert first["decision"] == gateway_app.RUNTIME_ENFORCEMENT_NEXT_CHECK
    assert replay["decision"] == gateway_app.RUNTIME_ENFORCEMENT_DENY
    assert replay["reason_code"] == gateway_app.RUNTIME_DENY_REPLAY_DETECTED
    assert gateway_app.nonce_hash("nonce-pb295") in stored["records"]
    assert "nonce-pb295" not in path.read_text(encoding="utf-8")


def test_persistent_nonce_expired_record_denies(tmp_path):
    path = tmp_path / "runtime_nonce_store.json"
    initialize_persistent_nonce_store(path)
    old_store = LocalPersistentNonceStore(path, ttl_seconds=10, now_fn=lambda: 1000)
    old_store.reserve(gateway_app.nonce_hash("expired-nonce"), decision_id="old-decision", timestamp=FIXED_TIMESTAMP)
    new_store = LocalPersistentNonceStore(path, ttl_seconds=10, now_fn=lambda: 1011)

    result = gateway_app.validate_nonce_replay_for_runtime(
        _payload("expired-nonce"),
        _record("expired-nonce"),
        persistent_nonce_store_adapter=new_store,
        timestamp=FIXED_TIMESTAMP,
    )

    assert result["decision"] == gateway_app.RUNTIME_ENFORCEMENT_DENY
    assert result["reason_code"] == gateway_app.RUNTIME_DENY_NONCE_EXPIRED
    assert result["audit_evidence"]["nonce_hash"] == gateway_app.nonce_hash("expired-nonce")
    assert result["audit_evidence"]["decision_id"] == "decision-pb295"
    assert result["audit_evidence"]["timestamp"] == FIXED_TIMESTAMP


def test_persistent_nonce_history_survives_store_recreation(tmp_path):
    path = tmp_path / "runtime_nonce_store.json"
    initialize_persistent_nonce_store(path)
    first_store = LocalPersistentNonceStore(path, ttl_seconds=300, now_fn=lambda: 1000)
    second_store = LocalPersistentNonceStore(path, ttl_seconds=300, now_fn=lambda: 1001)

    first = gateway_app.validate_nonce_replay_for_runtime(
        _payload("restart-nonce"),
        _record("restart-nonce"),
        persistent_nonce_store_adapter=first_store,
        timestamp=FIXED_TIMESTAMP,
    )
    after_restart = gateway_app.validate_nonce_replay_for_runtime(
        _payload("restart-nonce"),
        _record("restart-nonce"),
        persistent_nonce_store_adapter=second_store,
        timestamp=FIXED_TIMESTAMP,
    )

    assert first["decision"] == gateway_app.RUNTIME_ENFORCEMENT_NEXT_CHECK
    assert after_restart["decision"] == gateway_app.RUNTIME_ENFORCEMENT_DENY
    assert after_restart["reason_code"] == gateway_app.RUNTIME_DENY_REPLAY_DETECTED


def test_missing_and_corrupted_persistent_nonce_store_deny(tmp_path):
    missing_store = LocalPersistentNonceStore(tmp_path / "missing.json", ttl_seconds=300)
    missing = gateway_app.validate_nonce_replay_for_runtime(
        _payload("missing-store-nonce"),
        _record("missing-store-nonce"),
        persistent_nonce_store_adapter=missing_store,
        timestamp=FIXED_TIMESTAMP,
    )
    corrupted_path = tmp_path / "corrupted.json"
    corrupted_path.write_text("not-json", encoding="utf-8")
    corrupted_store = LocalPersistentNonceStore(corrupted_path, ttl_seconds=300)
    corrupted = gateway_app.validate_nonce_replay_for_runtime(
        _payload("corrupted-store-nonce"),
        _record("corrupted-store-nonce"),
        persistent_nonce_store_adapter=corrupted_store,
        timestamp=FIXED_TIMESTAMP,
    )

    assert missing["decision"] == gateway_app.RUNTIME_ENFORCEMENT_DENY
    assert missing["reason_code"] == gateway_app.RUNTIME_DENY_NONCE_STORE_UNAVAILABLE
    assert corrupted["decision"] == gateway_app.RUNTIME_ENFORCEMENT_DENY
    assert corrupted["reason_code"] == gateway_app.RUNTIME_DENY_NONCE_STORE_CORRUPTED


def test_persistent_nonce_cleanup_removes_only_retention_expired_records(tmp_path):
    path = tmp_path / "runtime_nonce_store.json"
    initialize_persistent_nonce_store(path)
    store = LocalPersistentNonceStore(path, ttl_seconds=10, now_fn=lambda: 1000)
    store.reserve(gateway_app.nonce_hash("cleanup-nonce"), decision_id="cleanup-decision", timestamp=FIXED_TIMESTAMP)
    keeper = LocalPersistentNonceStore(path, ttl_seconds=10, now_fn=lambda: 1005)
    assert keeper.cleanup(retention_seconds=100) == 0

    cleaner = LocalPersistentNonceStore(path, ttl_seconds=10, now_fn=lambda: 1200)
    assert cleaner.cleanup(retention_seconds=100) == 1


def test_persistent_nonce_invalid_ttl_fails_closed(tmp_path):
    path = tmp_path / "runtime_nonce_store.json"
    initialize_persistent_nonce_store(path)

    try:
        LocalPersistentNonceStore(path, ttl_seconds=0)
    except PersistentNonceStoreError as exc:
        assert str(exc) == "nonce_store_unavailable"
    else:
        raise AssertionError("invalid nonce ttl did not fail closed")
