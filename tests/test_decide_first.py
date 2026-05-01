from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

import gateway.app as gateway_app
from audit.hash_chain import AuditHashChain
from security.decision_store import (
    DecisionStoreTestDouble,
    RedisDecisionStore,
    create_decision_store,
    decision_signature_payload,
    decision_record_hash,
    sign_decision,
    sign_decision_hybrid,
    verify_decision_signatures,
)
from security.hydra_consensus import HydraNodeDecision
from security.hydra_nodes import sign_hydra_node_decision
from security.nonce_store import NonceStore
from tests.request_signing_helpers import configure_request_signing, sign_payload_ed25519


class AllowClient:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id

    def evaluate(self, request_hash: str, policy_version: str) -> HydraNodeDecision:
        return sign_hydra_node_decision(
            HydraNodeDecision(
                node_id=self.node_id,
                request_hash=request_hash,
                policy_version=policy_version,
                decision="allow",
                reason=f"{self.node_id}_allow",
                timestamp=time.time(),
            )
        )


def configure_gateway(tmp_path: Path, monkeypatch, store: DecisionStoreTestDouble | None = None) -> TestClient:
    store = store or DecisionStoreTestDouble()
    configure_request_signing(tmp_path, monkeypatch, gateway_app)
    monkeypatch.setattr(
        gateway_app,
        "nonce_store",
        NonceStore(tmp_path / "used_nonces.json"),
    )
    monkeypatch.setattr(
        gateway_app,
        "audit_chain",
        AuditHashChain(tmp_path / "audit_chain.json"),
    )
    monkeypatch.setattr(
        gateway_app,
        "hydra_node_clients",
        [AllowClient("node-1"), AllowClient("node-2"), AllowClient("node-3")],
    )
    monkeypatch.setattr(gateway_app, "decision_store", store)
    client = TestClient(gateway_app.app, raise_server_exceptions=False)
    client.decision_store = store
    return client


def build_payload(command: str = "python3 -m pytest tests/test_hydra_consensus.py") -> dict:
    payload = {
        "type": "execution",
        "action": "execute_command",
        "actor_id": "actor-alice",
        "command": command,
        "device": "laptop-1",
        "nonce": f"nonce-{time.time_ns()}",
        "tenant_id": "t1",
        "timestamp": int(time.time()),
        "user_id": "alice",
        "policy_version": "policy-v1",
        "compute_target": "cpu",
        "compute_risk_level": "low",
        "data_sensitivity": "low",
        "execution_location": "local",
    }
    return sign_payload_ed25519(payload)


def resign_payload(payload: dict) -> dict:
    signed = payload.copy()
    signed.pop("signature", None)
    return sign_payload_ed25519(signed)


def approve(client: TestClient, payload: dict) -> dict:
    response = client.post("/decide", json=payload)
    assert response.status_code == 200
    approved = payload.copy()
    approved["decision_id"] = response.json()["decision_id"]
    approved["decision_signature"] = response.json()["decision_signature"]
    approved["decision_signature_classic"] = response.json()["decision_signature_classic"]
    approved["decision_signature_pqc"] = response.json()["decision_signature_pqc"]
    return approved


def test_execute_without_decision_id_is_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    response = client.post("/execute", json=build_payload())

    assert response.status_code == 403
    assert response.json() == {"error": "missing_decision_id"}


def test_execute_without_decision_signature_is_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload["decision_id"] = "decision-without-signature"

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "invalid_signature"}


def test_decide_missing_actor_id_is_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload.pop("actor_id")
    payload = resign_payload(payload)

    response = client.post("/decide", json=payload)

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "missing_actor"


def test_execute_with_deny_decision_is_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(command="bash -lc 'echo blocked'")
    decision = client.post("/decide", json=payload)
    assert decision.status_code == 200
    assert decision.json()["decision"] == "DENY"

    payload["decision_id"] = decision.json()["decision_id"]
    payload["decision_signature"] = decision.json()["decision_signature"]
    payload["decision_signature_classic"] = decision.json()["decision_signature_classic"]
    payload["decision_signature_pqc"] = decision.json()["decision_signature_pqc"]
    response = client.post("/execute", json=payload)
    replay = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "policy_denied"}
    assert replay.status_code == 403
    assert replay.json() == {"error": "replay_detected"}


def test_redis_unavailable_decide_fails_closed(tmp_path: Path, monkeypatch) -> None:
    store = DecisionStoreTestDouble()
    store.fail_create = True
    client = configure_gateway(tmp_path, monkeypatch, store)

    response = client.post("/decide", json=build_payload())

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "redis_unavailable"


def test_required_redis_down_denies_with_dependency_reason(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REQUIRE_REDIS", "true")
    monkeypatch.setattr(gateway_app, "redis_available", lambda: False)
    client = configure_gateway(tmp_path, monkeypatch)

    response = client.post("/decide", json=build_payload())

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "redis_unavailable"
    deny_events = [
        entry["decision"]
        for entry in gateway_app.audit_chain.load()
        if entry.get("action") == "decision_created"
    ]
    assert deny_events
    latest = deny_events[-1]
    assert latest["reason_code"] == "redis_unavailable"
    assert latest["policy_version"]
    assert "policy_pubkey_id" in latest
    assert latest["timestamp"]


def test_required_redis_up_allows_decision_flow(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REQUIRE_REDIS", "true")
    monkeypatch.setattr(gateway_app, "redis_available", lambda: True)
    client = configure_gateway(tmp_path, monkeypatch)

    response = client.post("/decide", json=build_payload())

    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"


def test_health_reflects_redis_dependency_state(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REQUIRE_REDIS", "true")
    monkeypatch.setattr(gateway_app, "redis_available", lambda: False)
    client = configure_gateway(tmp_path, monkeypatch)

    degraded = client.get("/health")
    assert degraded.status_code == 200
    assert degraded.json()["redis_available"] is False
    assert degraded.json()["nonce_store_available"] is False
    assert degraded.json()["replay_protection_active"] is False
    assert degraded.json()["mode"] == "DEGRADED"
    assert degraded.json()["reason"] == "redis_unavailable"

    monkeypatch.setattr(gateway_app, "redis_available", lambda: True)
    normal = client.get("/health")
    assert normal.status_code == 200
    assert normal.json()["redis_available"] is True
    assert normal.json()["nonce_store_available"] is True
    assert normal.json()["replay_protection_active"] is True
    assert normal.json()["mode"] == "NORMAL"


def test_required_redis_down_all_decide_paths_deny_without_allow(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REQUIRE_REDIS", "true")
    monkeypatch.setattr(gateway_app, "redis_available", lambda: False)
    client = configure_gateway(tmp_path, monkeypatch)

    payloads = [
        build_payload(),
        build_payload(command="bash -lc 'echo blocked'"),
        resign_payload({**build_payload(), "nonce": f"nonce-{time.time_ns()}"}),
    ]

    for payload in payloads:
        response = client.post("/decide", json=payload)
        assert response.status_code == 403
        assert response.json()["decision"] == "DENY"
        assert response.json()["reason"] == "redis_unavailable"


def test_required_redis_down_execute_and_replay_attempts_deny(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REQUIRE_REDIS", "true")
    monkeypatch.setattr(gateway_app, "redis_available", lambda: True)
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())

    monkeypatch.setattr(gateway_app, "redis_available", lambda: False)
    first = client.post("/execute", json=payload)
    second = client.post("/execute", json=payload)

    assert first.status_code == 403
    assert first.json() == {"error": "redis_unavailable"}
    assert second.status_code == 403
    assert second.json() == {"error": "redis_unavailable"}


def test_redis_unavailable_execute_fails_closed(tmp_path: Path, monkeypatch) -> None:
    store = DecisionStoreTestDouble()
    client = configure_gateway(tmp_path, monkeypatch, store)
    payload = approve(client, build_payload())
    store.fail_load = True

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "redis_unavailable"}


def test_missing_signing_key_fails_closed_in_redis_mode(tmp_path: Path, monkeypatch) -> None:
    class FakeRedis:
        def set(self, *args, **kwargs):
            raise AssertionError("signing must fail before Redis write")

    monkeypatch.setenv("REDIS_URL", "redis://redis.example.test:6379/0")
    monkeypatch.delenv("USBAY_DECISION_SIGNING_KEY", raising=False)
    client = configure_gateway(
        tmp_path,
        monkeypatch,
        RedisDecisionStore(redis_client=FakeRedis()),
    )

    response = client.post("/decide", json=build_payload())

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"


def test_redis_url_selects_redis_decision_store(monkeypatch) -> None:
    monkeypatch.setenv("REDIS_URL", "redis://redis.example.test:6379/0")
    monkeypatch.setenv("USBAY_DECISION_SIGNING_KEY", "enterprise-signing-key")

    assert isinstance(create_decision_store(), RedisDecisionStore)


def test_decision_signature_payload_is_pipe_delimited() -> None:
    payload = decision_signature_payload(
        {
            "decision_id": "decision-1",
            "decision": "ALLOW",
            "policy_hash": "policy-hash",
            "request_hash": "request-hash",
            "policy_version": "policy-v1",
            "policy_pubkey_id": "policy-key",
            "signature_valid": True,
            "expires_at_epoch": 123,
            "nonce_hash": "nonce-hash",
            "actor_hash": "actor-hash",
            "gateway_id": "gateway-1",
            "previous_hash": "previous-hash",
        }
    )

    assert (
        payload
        == "decision-1|ALLOW|policy-hash|request-hash|policy-v1|policy-key|True|123|nonce-hash|actor-hash|gateway-1|previous-hash"
    )


def test_enterprise_mode_requires_redis(monkeypatch) -> None:
    monkeypatch.setenv("USBAY_ENTERPRISE_MODE", "true")
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.setenv("USBAY_DECISION_SIGNING_KEY", "enterprise-signing-key")

    try:
        create_decision_store()
    except Exception as exc:
        assert "redis_required" in str(exc)
    else:
        raise AssertionError("enterprise mode must require Redis")


def test_default_gateway_decide_without_redis_fails_closed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("USBAY_ALLOW_IN_MEMORY_DECISION_STORE", raising=False)
    client = configure_gateway(
        tmp_path,
        monkeypatch,
        gateway_app.UnavailableDecisionStore("redis_required"),
    )

    response = client.post("/decide", json=build_payload())

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "redis_unavailable"


def test_execute_with_invalid_decision_id_is_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload["decision_id"] = str(uuid.uuid4())
    payload["decision_signature"] = "missing-signature"
    payload["decision_signature_classic"] = "missing-signature"
    payload["decision_signature_pqc"] = "missing-signature-pqc"

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "unknown_decision"}


def test_expired_decision_is_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())
    record = client.decision_store.records[payload["decision_id"]]
    expired = int(time.time()) - 1
    record["expires_at_epoch"] = expired
    record["expires_at"] = "2000-01-01T00:00:00Z"
    record.update(sign_decision_hybrid(record))
    record["decision_signature"] = sign_decision(record)
    payload["decision_signature"] = record["decision_signature"]
    payload["decision_signature_classic"] = record["decision_signature_classic"]
    payload["decision_signature_pqc"] = record["decision_signature_pqc"]

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "decision_time_invalid"}


def test_ttl_too_far_in_future_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())
    record = client.decision_store.records[payload["decision_id"]]
    record["expires_at_epoch"] = int(time.time()) + 10000
    record["expires_at"] = "2999-01-01T00:00:00Z"
    record.update(sign_decision_hybrid(record))
    record["decision_signature"] = sign_decision(record)
    payload["decision_signature"] = record["decision_signature"]
    payload["decision_signature_classic"] = record["decision_signature_classic"]
    payload["decision_signature_pqc"] = record["decision_signature_pqc"]

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "decision_time_invalid"}


def test_malformed_expires_at_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())
    record = client.decision_store.records[payload["decision_id"]]
    record["expires_at"] = "not-a-date"
    record.update(sign_decision_hybrid(record))
    record["decision_signature"] = sign_decision(record)
    payload["decision_signature_classic"] = record["decision_signature_classic"]
    payload["decision_signature_pqc"] = record["decision_signature_pqc"]

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "decision_time_invalid"}


def test_request_hash_mismatch_is_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())
    payload["command"] = "python3 -m pytest tests/test_gateway_app.py"

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "decision_request_mismatch"}


def test_invalid_decision_signature_is_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())
    client.decision_store.records[payload["decision_id"]]["decision_signature_classic"] = "bad"

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "invalid_signature"}


def test_submitted_classic_decision_signature_mismatch_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())
    replacement = "0" if payload["decision_signature_classic"][-1] != "0" else "1"
    payload["decision_signature_classic"] = f"{payload['decision_signature_classic'][:-1]}{replacement}"

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "invalid_signature"}


def test_missing_classic_decision_signature_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())
    payload.pop("decision_signature_classic")
    payload.pop("decision_signature")

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "invalid_signature"}


def test_submitted_pqc_decision_signature_mismatch_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())
    replacement = "0" if payload["decision_signature_pqc"][-1] != "0" else "1"
    payload["decision_signature_pqc"] = f"{payload['decision_signature_pqc'][:-1]}{replacement}"

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "invalid_signature"}


def test_missing_pqc_decision_signature_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())
    payload.pop("decision_signature_pqc")

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "invalid_signature"}


def test_nonce_mismatch_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())
    payload["nonce"] = f"other-{time.time_ns()}"

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "decision_nonce_mismatch"}


def test_decide_reused_nonce_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    first = client.post("/decide", json=payload)
    second = client.post("/decide", json=payload)

    assert first.status_code == 200
    assert second.status_code == 403
    assert second.json()["reason"] == "replay_detected"


def test_execute_with_reused_decision_id_is_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())

    first = client.post("/execute", json=payload)
    second = client.post("/execute", json=payload)

    assert first.status_code == 200
    assert second.status_code == 403
    assert second.json() == {"error": "replay_detected"}


def test_execute_with_valid_allow_decision_succeeds(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    response = client.post("/execute", json=approve(client, build_payload()))

    assert response.status_code == 200
    assert response.json() == {"status": "EXECUTED"}


def test_execute_actor_mismatch_is_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())
    payload["actor_id"] = "actor-mallory"
    payload = resign_payload(payload)

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "actor_mismatch"}


def test_execute_missing_actor_id_is_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())
    payload.pop("actor_id")
    payload = resign_payload(payload)

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "missing_actor"}


def test_unknown_algorithm_version_is_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())
    record = client.decision_store.records[payload["decision_id"]]
    record["alg_version"] = "unknown-hybrid-v0"

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "unknown_algorithm"}


def test_missing_algorithm_version_is_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())
    record = client.decision_store.records[payload["decision_id"]]
    record.pop("alg_version")

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "unknown_algorithm"}


def test_tampered_decision_chain_fails_verification(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    first = client.post("/decide", json=build_payload())
    second = client.post("/decide", json=build_payload())
    assert first.status_code == 200
    assert second.status_code == 200

    assert client.decision_store.verify_chain() is True
    second_record = client.decision_store.records[second.json()["decision_id"]]
    original_audit_hash = second_record["audit_hash"]
    second_record["request_hash"] = "tampered-request-hash"

    assert second_record["current_hash"] != decision_record_hash(second_record)
    assert original_audit_hash != decision_record_hash(second_record)
    assert client.decision_store.verify_chain() is False


def test_decision_chain_hash_ignores_used_but_detects_decision_change(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    response = client.post("/decide", json=build_payload())
    assert response.status_code == 200

    record = client.decision_store.records[response.json()["decision_id"]]
    original_hash = decision_record_hash(record)
    record["used"] = True
    record["replay_detected"] = True
    record["runtime_state"] = "execution_started"

    assert decision_record_hash(record) == original_hash
    assert client.decision_store.verify_chain() is True

    record["decision"] = "DENY"

    assert decision_record_hash(record) != original_hash
    assert client.decision_store.verify_chain() is False


def test_decision_chain_requires_algorithm_version(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    response = client.post("/decide", json=build_payload())
    assert response.status_code == 200

    record = client.decision_store.records[response.json()["decision_id"]]
    record.pop("alg_version")

    assert client.decision_store.verify_chain() is False


def test_decision_chain_detects_algorithm_version_change(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    response = client.post("/decide", json=build_payload())
    assert response.status_code == 200

    record = client.decision_store.records[response.json()["decision_id"]]
    original_hash = decision_record_hash(record)
    record["alg_version"] = "hmac-sha256-v2"

    assert decision_record_hash(record) != original_hash
    assert client.decision_store.verify_chain() is False


def _write_export(path: Path, export: dict) -> None:
    path.write_text(json.dumps(export, sort_keys=True), encoding="utf-8")


def _verify_export(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "scripts/verify_audit_chain.py",
            str(path),
            "governance/policy_public.key",
        ],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=False,
    )


def _verify_decision(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "scripts/verify_decision.py",
            str(path),
            "governance/policy_public.key",
        ],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=False,
    )


def test_decision_audit_export_redacts_and_verifies_valid_chain(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    first = client.post("/decide", json=build_payload())
    second = client.post("/decide", json=build_payload())
    assert first.status_code == 200
    assert second.status_code == 200

    response = client.get(f"/audit/export/{second.json()['decision_id']}")

    assert response.status_code == 200
    export = response.json()
    export_text = json.dumps(export)
    assert export["type"] == "decision_audit_export"
    assert export["decision_id"] == second.json()["decision_id"]
    assert export["decision"] == "ALLOW"
    assert export["policy_hash"]
    assert export["policy_pubkey_id"]
    assert export["request_hash"]
    assert export["signature_valid"] is True
    assert export["decision_signature"]
    assert export["decision_record"]["actor_hash"]
    assert export["previous_hash"]
    assert export["audit_hash"]
    assert export["alg_version"] == "hmac-sha256-v1"
    assert export["policy_version"] == "policy-v1"
    assert "actor_id" not in export_text
    assert "actor-alice" not in export_text
    assert "command" not in export_text

    export_file = tmp_path / "decision-export.json"
    _write_export(export_file, export)
    result = _verify_export(export_file)

    assert result.returncode == 0
    assert result.stdout.strip() == "VALID"


def test_decision_external_verifier_valid_export(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    response = client.post("/decide", json=build_payload())
    assert response.status_code == 200
    export = client.get(f"/audit/export/{response.json()['decision_id']}").json()

    export_file = tmp_path / "decision-valid-export.json"
    _write_export(export_file, export)
    result = _verify_decision(export_file)

    assert result.returncode == 0
    assert result.stdout.strip() == "VALID"


def test_decision_external_verifier_detects_modified_field(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    response = client.post("/decide", json=build_payload())
    assert response.status_code == 200
    export = client.get(f"/audit/export/{response.json()['decision_id']}").json()
    export["decision_record"]["policy_hash"] = "0" * 64
    export["records"][0]["policy_hash"] = "0" * 64
    export["policy_hash"] = "0" * 64

    export_file = tmp_path / "decision-modified-export.json"
    _write_export(export_file, export)
    result = _verify_decision(export_file)

    assert result.returncode == 1
    assert result.stdout.strip() == "INVALID"


def test_decision_external_verifier_detects_broken_chain(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    first = client.post("/decide", json=build_payload())
    second = client.post("/decide", json=build_payload())
    assert first.status_code == 200
    assert second.status_code == 200
    export = client.get(f"/audit/export/{second.json()['decision_id']}").json()
    export["records"][1]["previous_hash"] = "broken"
    export["decision_record"]["previous_hash"] = "broken"
    export["previous_hash"] = "broken"

    export_file = tmp_path / "decision-broken-chain-export.json"
    _write_export(export_file, export)
    result = _verify_decision(export_file)

    assert result.returncode == 1
    assert result.stdout.strip() == "INVALID"


def test_decision_external_verifier_detects_expired_decision(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    response = client.post("/decide", json=build_payload())
    assert response.status_code == 200
    export = client.get(f"/audit/export/{response.json()['decision_id']}").json()
    export["decision_record"]["expires_at_epoch"] = 1
    export["records"][0]["expires_at_epoch"] = 1
    export["expires_at_epoch"] = 1

    export_file = tmp_path / "decision-expired-export.json"
    _write_export(export_file, export)
    result = _verify_decision(export_file)

    assert result.returncode == 1
    assert result.stdout.strip() == "INVALID"


def test_decision_external_verifier_detects_reused_nonce(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    first = client.post("/decide", json=build_payload())
    second = client.post("/decide", json=build_payload())
    assert first.status_code == 200
    assert second.status_code == 200
    export = client.get(f"/audit/export/{second.json()['decision_id']}").json()
    reused_nonce = export["records"][0]["nonce_hash"]
    export["records"][1]["nonce_hash"] = reused_nonce
    export["decision_record"]["nonce_hash"] = reused_nonce
    export["nonce_hash"] = reused_nonce

    export_file = tmp_path / "decision-reused-nonce-export.json"
    _write_export(export_file, export)
    result = _verify_decision(export_file)

    assert result.returncode == 1
    assert result.stdout.strip() == "INVALID"


def test_decision_external_verifier_detects_pqc_mismatch(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    response = client.post("/decide", json=build_payload())
    assert response.status_code == 200
    export = client.get(f"/audit/export/{response.json()['decision_id']}").json()
    export["decision_record"]["decision_signature_pqc"] = "bad-pqc"
    export["records"][0]["decision_signature_pqc"] = "bad-pqc"

    export_file = tmp_path / "decision-pqc-mismatch-export.json"
    _write_export(export_file, export)
    result = _verify_decision(export_file)

    assert result.returncode == 1
    assert result.stdout.strip() == "INVALID"


def test_decision_external_verifier_pqc_mismatch_valid_in_compat_mode(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    response = client.post("/decide", json=build_payload())
    assert response.status_code == 200
    export = client.get(f"/audit/export/{response.json()['decision_id']}").json()
    record = export["decision_record"]
    record["decision_signature_pqc"] = "bad-pqc"

    assert verify_decision_signatures(record, mode="COMPAT") is True


def test_decision_external_verifier_pqc_mismatch_invalid_in_strict_mode(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_SIGNATURE_POLICY_MODE", "STRICT")
    client = configure_gateway(tmp_path, monkeypatch)
    response = client.post("/decide", json=build_payload())
    assert response.status_code == 200
    export = client.get(f"/audit/export/{response.json()['decision_id']}").json()
    export["decision_record"]["decision_signature_pqc"] = "bad-pqc"
    export["records"][0]["decision_signature_pqc"] = "bad-pqc"

    export_file = tmp_path / "decision-pqc-mismatch-strict-export.json"
    _write_export(export_file, export)
    result = _verify_decision(export_file)

    assert result.returncode == 1
    assert result.stdout.strip() == "INVALID"


def test_decision_external_verifier_detects_fake_genesis(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    response = client.post("/decide", json=build_payload())
    assert response.status_code == 200
    export = client.get(f"/audit/export/{response.json()['decision_id']}").json()
    export["decision_record"]["genesis_hash"] = "fake-genesis"
    export["records"][0]["genesis_hash"] = "fake-genesis"
    export["genesis_hash"] = "fake-genesis"

    export_file = tmp_path / "decision-fake-genesis-export.json"
    _write_export(export_file, export)
    result = _verify_decision(export_file)

    assert result.returncode == 1
    assert result.stdout.strip() == "INVALID"


def test_external_verifier_detects_tampered_decision(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    response = client.post("/decide", json=build_payload())
    assert response.status_code == 200
    export = client.get(f"/audit/export/{response.json()['decision_id']}").json()
    export["decision_record"]["decision"] = "DENY"
    export["records"][0]["decision"] = "DENY"

    export_file = tmp_path / "tampered-export.json"
    _write_export(export_file, export)
    result = _verify_export(export_file)

    assert result.returncode == 1
    assert result.stdout.strip() == "INVALID"


def test_external_verifier_detects_broken_previous_hash(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    first = client.post("/decide", json=build_payload())
    second = client.post("/decide", json=build_payload())
    assert first.status_code == 200
    assert second.status_code == 200
    export = client.get(f"/audit/export/{second.json()['decision_id']}").json()
    export["records"][1]["previous_hash"] = "broken"

    export_file = tmp_path / "broken-previous-hash-export.json"
    _write_export(export_file, export)
    result = _verify_export(export_file)

    assert result.returncode == 1
    assert result.stdout.strip() == "INVALID"


def test_external_verifier_requires_policy_release_evidence(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    response = client.post("/decide", json=build_payload())
    assert response.status_code == 200
    export = client.get(f"/audit/export/{response.json()['decision_id']}").json()
    export["decision_record"].pop("policy_pubkey_id")
    export["records"][0].pop("policy_pubkey_id")

    export_file = tmp_path / "missing-policy-evidence-export.json"
    _write_export(export_file, export)
    result = _verify_export(export_file)

    assert result.returncode == 1
    assert result.stdout.strip() == "INVALID"


def test_policy_hash_mismatch_degrades_node_and_denies_execute(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_EXPECTED_POLICY_HASH", "0" * 64)
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())

    health = client.get("/health")
    response = client.post("/execute", json=payload)

    assert health.status_code == 200
    assert health.json()["mode"] == "DEGRADED"
    assert health.json()["reason"] == "policy_hash_mismatch"
    assert response.status_code == 403
    assert response.json() == {"error": "degraded:policy_hash_mismatch"}


def test_audit_evidence_bundle_verifies_and_tamper_fails(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    response = client.post("/decide", json=build_payload())
    assert response.status_code == 200

    bundle = client.get(f"/audit/bundle/{response.json()['decision_id']}")
    assert bundle.status_code == 200
    bundle_body = bundle.json()
    assert bundle_body["type"] == "audit_evidence_bundle"
    assert bundle_body["policy_registry.json"]
    assert bundle_body["policy_registry.sig"]
    assert bundle_body["policy_log"]
    assert bundle_body["manifest.json"]

    bundle_file = tmp_path / "audit-bundle.json"
    _write_export(bundle_file, bundle_body)
    result = _verify_export(bundle_file)
    assert result.returncode == 0
    assert result.stdout.strip() == "VALID"

    bundle_body["decision_record"]["decision"] = "DENY"
    tampered_file = tmp_path / "tampered-audit-bundle.json"
    _write_export(tampered_file, bundle_body)
    tampered = _verify_export(tampered_file)
    assert tampered.returncode == 1
    assert tampered.stdout.strip() == "INVALID"


def test_decide_malformed_input_fails_closed(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload.pop("policy_version")
    payload = resign_payload(payload)

    response = client.post("/decide", json=payload)

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "missing_policy"


def test_decide_unknown_pubkey_id_fails_closed(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload["pubkey_id"] = "unknown_request_key"

    response = client.post("/decide", json=payload)

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "unknown_key"


def test_decide_wrong_signature_algorithm_fails_closed(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload["signature_alg"] = "hmac-sha256"

    response = client.post("/decide", json=payload)

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "invalid_signature"


def test_decide_denies_raw_ip_metadata(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload["metadata"] = {"raw_ip": "203.0.113.10"}
    payload = resign_payload(payload)

    response = client.post("/decide", json=payload)

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "metadata_forbidden:raw_ip"


def test_decide_denies_raw_payment_metadata(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload["payment_id"] = "payment-token-example"
    payload = resign_payload(payload)

    response = client.post("/decide", json=payload)

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "metadata_forbidden:payment_id"


def test_decide_denies_raw_location_metadata(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload["metadata"] = {"location": "precise-location-example"}
    payload = resign_payload(payload)

    response = client.post("/decide", json=payload)

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "metadata_forbidden:location"


def test_decide_allows_hashed_actor_metadata(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload["metadata"] = {
        "actor_hash": hashlib.sha256(b"actor").hexdigest(),
        "request_hash": hashlib.sha256(b"request").hexdigest(),
    }
    payload = resign_payload(payload)

    response = client.post("/decide", json=payload)

    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"


def test_decide_unknown_metadata_fails_closed(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload["metadata"] = {"session_behavior_hint": "unclassified"}
    payload = resign_payload(payload)

    response = client.post("/decide", json=payload)

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "metadata_unknown:session_behavior_hint"


def test_metadata_denial_does_not_log_raw_metadata(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload["metadata"] = {"raw_ip": "203.0.113.99"}
    payload = resign_payload(payload)

    response = client.post("/decide", json=payload)

    assert response.status_code == 403
    audit_text = (tmp_path / "audit_chain.json").read_text(encoding="utf-8")
    assert "203.0.113.99" not in audit_text
    assert "metadata_forbidden:raw_ip" in audit_text


def test_decide_returns_signed_decision_fields(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)

    response = client.post("/decide", json=build_payload())

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ALLOW"
    assert str(uuid.UUID(body["decision_id"])) == body["decision_id"]
    assert body["request_hash"]
    assert body["policy_version"] == "policy-v1"
    assert body["policy_hash"]
    assert body["policy_pubkey_id"]
    assert body["signature_valid"] is True
    assert body["expires_at"].endswith("Z")
    assert body["expires_at_epoch"] > int(time.time())
    assert body["decision_signature"]
    assert body["decision_signature_classic"]
    assert body["decision_signature_pqc"]
    assert body["alg_version"] == "hmac-sha256-v1"
    assert body["actor_hash"]
    assert body["actor_hash"] == hashlib.sha256(b"actor-alice").hexdigest()
    assert body["previous_hash"]
    assert body["audit_hash"]
    assert "actor_hash" in client.decision_store.records[body["decision_id"]]
    assert client.decision_store.records[body["decision_id"]]["signature_valid"] is True
    audit_entries = gateway_app.audit_chain.load()
    decision_events = [entry["decision"] for entry in audit_entries if entry.get("action") == "decision_created"]
    assert decision_events[-1]["policy_version"] == body["policy_version"]
    assert decision_events[-1]["policy_hash"] == body["policy_hash"]
    assert decision_events[-1]["policy_pubkey_id"] == body["policy_pubkey_id"]
    assert decision_events[-1]["signature_valid"] is True
    assert "actor_id" not in client.decision_store.records[body["decision_id"]]
    assert "actor-alice" not in json.dumps(client.decision_store.records[body["decision_id"]])
    assert body["decision_signature"] == body["decision_signature_classic"]
    assert body["used"] is False
    assert body["decision_id"] != "stub-1"
    assert body["request_hash"] != "stub"
    assert body["decision_signature"] != "stub"


def test_missing_allow_audit_field_fails_closed(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = approve(client, build_payload())
    record = client.decision_store.records[payload["decision_id"]]
    record.pop("signature_valid")

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "invalid_signature"}


def test_modifying_allow_audit_fields_invalidates_decision_signature(tmp_path: Path, monkeypatch) -> None:
    signed_fields = (
        ("policy_version", "other-policy"),
        ("policy_hash", "0" * 64),
        ("policy_pubkey_id", "other-key"),
        ("request_hash", "1" * 64),
        ("signature_valid", False),
    )
    for field, value in signed_fields:
        client = configure_gateway(tmp_path, monkeypatch)
        payload = approve(client, build_payload())
        client.decision_store.records[payload["decision_id"]][field] = value

        response = client.post("/execute", json=payload)

        assert response.status_code == 403
        assert response.json() == {"error": "invalid_signature"}


def test_gateway_openapi_exposes_governance_routes_without_stub_descriptions() -> None:
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.get("/openapi.json")

    assert response.status_code == 200
    spec = response.json()
    assert "/decide" in spec["paths"]
    assert "/execute" in spec["paths"]
    assert "/audit/export/{audit_id}" in spec["paths"]
    assert "temporary stub" not in json.dumps(spec).lower()


def test_no_raw_payload_is_stored_in_audit_logs(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    secret_command = "python3 -m pytest tests/test_hydra_consensus.py"
    payload = approve(client, build_payload(command=secret_command))

    response = client.post("/execute", json=payload)

    assert response.status_code == 200
    audit_text = (tmp_path / "audit_chain.json").read_text(encoding="utf-8")
    assert secret_command not in audit_text
    assert payload["nonce"] not in audit_text
    assert "request_hash" in audit_text
    assert "decision_id" in audit_text
