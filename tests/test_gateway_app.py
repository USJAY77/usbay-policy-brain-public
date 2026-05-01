import hashlib
import json
import time

from fastapi.testclient import TestClient

import gateway.app as gateway_app
from audit.hash_chain import AuditHashChain
from security.decision_store import DecisionStoreTestDouble
from security.nonce_store import NonceStore
from tests.request_signing_helpers import configure_request_signing, sign_payload_ed25519


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sign_payload(payload, secret):
    return sign_payload_ed25519(payload)["signature"]

def build_payload(data=None, nonce=None, timestamp=None):
    payload = {
        "action": "read",
        "actor_id": "actor-alice",
        "device": "laptop-1",
        "tenant_id": "t1",
        "timestamp": str(int(time.time())),
        "user_id": "alice",
        "nonce": "test-nonce-default",
        "policy_version": "policy-v1",
        "compute_target": "cpu",
        "compute_risk_level": "low",
        "data_sensitivity": "low",
        "execution_location": "local",
    }
    if data:
        payload.update(data.copy())
    if nonce is not None:
        payload["nonce"] = nonce
    if timestamp is not None:
        payload["timestamp"] = timestamp
    return payload


def configure_gateway(tmp_path, monkeypatch):
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
    monkeypatch.setattr(gateway_app, "decision_store", DecisionStoreTestDouble())
    return TestClient(gateway_app.app, raise_server_exceptions=False)


def decide_then_execute(client, payload):
    decision = client.post("/decide", json=payload)
    assert decision.status_code == 200
    payload = payload.copy()
    payload["decision_id"] = decision.json()["decision_id"]
    payload["decision_signature"] = decision.json()["decision_signature"]
    payload["decision_signature_classic"] = decision.json()["decision_signature_classic"]
    payload["decision_signature_pqc"] = decision.json()["decision_signature_pqc"]
    return client.post("/execute", json=payload)


def test_execute_success(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload.update(sign_payload_ed25519(payload))

    res = decide_then_execute(client, payload)

    assert res.status_code == 200
    assert res.json()["status"] == "EXECUTED"


def test_replay_fails(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="test-nonce-123")
    payload.update(sign_payload_ed25519(payload))

    decision = client.post("/decide", json=payload)
    assert decision.status_code == 200
    payload["decision_id"] = decision.json()["decision_id"]
    payload["decision_signature"] = decision.json()["decision_signature"]
    payload["decision_signature_classic"] = decision.json()["decision_signature_classic"]
    payload["decision_signature_pqc"] = decision.json()["decision_signature_pqc"]
    res1 = client.post("/execute", json=payload)
    res2 = client.post("/execute", json=payload)

    assert res1.status_code == 200
    assert res2.status_code == 403
    assert res2.json()["error"] == "replay_detected"


def test_missing_nonce_fails(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    del payload["nonce"]
    payload.update(sign_payload_ed25519(payload))

    res = client.post("/execute", json=payload)

    assert res.status_code == 403
    assert res.json()["error"] == "missing_decision_id"


def test_old_timestamp_fails(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(timestamp=str(int(time.time()) - 1000))
    payload.update(sign_payload_ed25519(payload))

    res = client.post("/execute", json=payload)

    assert res.status_code == 403
    assert res.json()["error"] == "missing_decision_id"
