from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

import gateway.app as gateway_app
from audit.hash_chain import AuditHashChain
from security.decision_store import DecisionStoreTestDouble
from security.nonce_store import NonceStore
from tests.request_signing_helpers import configure_request_signing, sign_payload_ed25519


def signed_payload(*, nonce: str = "nonce-1", timestamp: int | None = None) -> dict:
    payload = {
        "action": "read",
        "actor_id": "actor-alice",
        "device": "laptop-1",
        "nonce": nonce,
        "tenant_id": "t1",
        "timestamp": int(time.time()) if timestamp is None else timestamp,
        "user_id": "alice",
        "policy_version": "policy-v1",
        "compute_target": "cpu",
        "compute_risk_level": "low",
        "data_sensitivity": "low",
        "execution_location": "local",
    }
    return sign_payload_ed25519(payload)


def configure_gateway(tmp_path: Path, monkeypatch) -> None:
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


def decide_then_execute(client: TestClient, payload: dict) -> object:
    approved = approve_payload(client, payload)
    return client.post("/execute", json=approved)


def approve_payload(client: TestClient, payload: dict) -> dict:
    decision = client.post("/decide", json=payload)
    assert decision.status_code == 200
    approved = payload.copy()
    approved["decision_id"] = decision.json()["decision_id"]
    approved["decision_signature"] = decision.json()["decision_signature"]
    approved["decision_signature_classic"] = decision.json()["decision_signature_classic"]
    approved["decision_signature_pqc"] = decision.json()["decision_signature_pqc"]
    return approved


def test_valid_request_executes_once_and_replay_fails(tmp_path: Path, monkeypatch) -> None:
    configure_gateway(tmp_path, monkeypatch)
    client = TestClient(gateway_app.app)
    payload = signed_payload()
    approved = approve_payload(client, payload)

    first = client.post("/execute", json=approved)
    second = client.post("/execute", json=approved)

    assert first.status_code == 200
    assert first.json() == {"status": "EXECUTED"}
    assert second.status_code == 403
    assert second.json() == {"error": "replay_detected"}


def test_new_nonce_executes_after_prior_request(tmp_path: Path, monkeypatch) -> None:
    configure_gateway(tmp_path, monkeypatch)
    client = TestClient(gateway_app.app)

    first = decide_then_execute(client, signed_payload(nonce="nonce-1"))
    second = decide_then_execute(client, signed_payload(nonce="nonce-2"))

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json() == {"status": "EXECUTED"}


def test_missing_nonce_fails_closed(tmp_path: Path, monkeypatch) -> None:
    configure_gateway(tmp_path, monkeypatch)
    client = TestClient(gateway_app.app)
    payload = signed_payload()
    payload.pop("nonce")

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"error": "missing_decision_id"}


def test_old_timestamp_fails_closed(tmp_path: Path, monkeypatch) -> None:
    configure_gateway(tmp_path, monkeypatch)
    client = TestClient(gateway_app.app)

    response = client.post(
        "/execute",
        json=signed_payload(timestamp=int(time.time()) - 301),
    )

    assert response.status_code == 403
    assert response.json() == {"error": "missing_decision_id"}
