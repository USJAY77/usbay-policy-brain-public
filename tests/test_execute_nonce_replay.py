from __future__ import annotations

import hashlib
import hmac
import time
from pathlib import Path

from fastapi.testclient import TestClient

import gateway.app as gateway_app
from audit.hash_chain import AuditHashChain
from security.nonce_store import NonceStore


class FakeKeyStore:
    def __init__(self, key: bytes = b"device-test-key"):
        self.key = key

    def load_device_key(self, tenant_id: str, device: str) -> dict:
        return {"key": self.key.decode("utf-8")}


def signed_payload(*, nonce: str = "nonce-1", timestamp: int | None = None) -> dict:
    payload = {
        "action": "read",
        "device": "laptop-1",
        "nonce": nonce,
        "tenant_id": "t1",
        "timestamp": int(time.time()) if timestamp is None else timestamp,
        "user_id": "alice",
    }
    payload["signature"] = hmac.new(
        b"device-test-key",
        gateway_app.request_signature_message(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return payload


def configure_gateway(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(gateway_app, "keystore", FakeKeyStore())
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


def test_valid_request_executes_once_and_replay_fails(tmp_path: Path, monkeypatch) -> None:
    configure_gateway(tmp_path, monkeypatch)
    client = TestClient(gateway_app.app)
    payload = signed_payload()

    first = client.post("/execute", json=payload)
    second = client.post("/execute", json=payload)

    assert first.status_code == 200
    assert first.json() == {"status": "EXECUTED"}
    assert second.status_code == 403
    assert second.json() == {"detail": "FAIL_CLOSED"}


def test_new_nonce_executes_after_prior_request(tmp_path: Path, monkeypatch) -> None:
    configure_gateway(tmp_path, monkeypatch)
    client = TestClient(gateway_app.app)

    first = client.post("/execute", json=signed_payload(nonce="nonce-1"))
    second = client.post("/execute", json=signed_payload(nonce="nonce-2"))

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
    assert response.json() == {"detail": "FAIL_CLOSED"}


def test_old_timestamp_fails_closed(tmp_path: Path, monkeypatch) -> None:
    configure_gateway(tmp_path, monkeypatch)
    client = TestClient(gateway_app.app)

    response = client.post(
        "/execute",
        json=signed_payload(timestamp=int(time.time()) - 301),
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "FAIL_CLOSED"}
