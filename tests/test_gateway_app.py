import hashlib
import hmac
import json
import time

from fastapi.testclient import TestClient

import gateway.app as gateway_app
from audit.hash_chain import AuditHashChain
from security.nonce_store import NonceStore


DEVICE_KEY = "device-test-key"


class FakeKeyStore:
    def load_device_key(self, tenant_id: str, device: str) -> dict:
        return {"key": DEVICE_KEY}


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sign_payload(payload, secret):
    body = canonical(payload)
    return hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()

def build_payload(data=None, nonce=None, timestamp=None):
    payload = {
        "action": "read",
        "device": "laptop-1",
        "tenant_id": "t1",
        "timestamp": str(int(time.time())),
        "user_id": "alice",
        "nonce": "test-nonce-default",
    }
    if data:
        payload.update(data.copy())
    if nonce is not None:
        payload["nonce"] = nonce
    if timestamp is not None:
        payload["timestamp"] = timestamp
    return payload


def configure_gateway(tmp_path, monkeypatch):
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
    return TestClient(gateway_app.app, raise_server_exceptions=False)


def test_execute_success(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload["signature"] = sign_payload(payload, DEVICE_KEY)

    res = client.post("/execute", json=payload)

    assert res.status_code == 200
    assert res.json()["status"] == "EXECUTED"


def test_replay_fails(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="test-nonce-123")
    payload["signature"] = sign_payload(payload, DEVICE_KEY)

    res1 = client.post("/execute", json=payload)
    res2 = client.post("/execute", json=payload)

    assert res1.status_code == 200
    assert res2.status_code == 403
    assert res2.json()["detail"] == "FAIL_CLOSED"


def test_missing_nonce_fails(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    del payload["nonce"]
    payload["signature"] = sign_payload(payload, DEVICE_KEY)

    res = client.post("/execute", json=payload)

    assert res.status_code == 403
    assert res.json()["detail"] == "FAIL_CLOSED"


def test_old_timestamp_fails(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(timestamp=str(int(time.time()) - 1000))
    payload["signature"] = sign_payload(payload, DEVICE_KEY)

    res = client.post("/execute", json=payload)

    assert res.status_code == 403
    assert res.json()["detail"] == "FAIL_CLOSED"
