from __future__ import annotations

import json
import hashlib
import hmac
import os
import time
from pathlib import Path
from typing import Optional

import pytest
from fastapi.testclient import TestClient

os.environ["USBAY_MODE"] = "PROD"

from gateway import app as gateway_app
from utils import secret_provider
from utils.canonical import canonical_json
from utils.keystore import KeyStore
from utils.secret_provider import LocalFileSecretProvider, SecretProvider


def _write_signed_policy(policy_path: Path, sig_path: Path, key_path: Path, policy: object) -> None:
    policy_bytes = canonical_json(policy)
    key = b"test-policy-key"

    policy_path.write_bytes(policy_bytes)
    key_path.write_bytes(key)

    digest = hashlib.sha256(policy_bytes).digest()
    sig_path.write_text(hmac.new(key, digest, hashlib.sha256).hexdigest(), encoding="utf-8")


def _signed_request(
    *,
    action: str = "read",
    user_id: str = "alice",
    device: str = "laptop-1",
    tenant_id: str = "t1",
    timestamp: int,
    key: bytes = b"device-test-key",
) -> dict:
    payload = {
        "action": action,
        "user_id": user_id,
        "device": device,
        "tenant_id": tenant_id,
        "timestamp": timestamp,
    }
    payload["signature"] = hmac.new(key, canonical_json(payload), hashlib.sha256).hexdigest()
    return payload


def _read_audit_records(audit_log: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in audit_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_request_signature_message_uses_stable_canonical_format() -> None:
    payload = {
        "action": "read",
        "user_id": "alice",
        "device": "laptop-1",
        "tenant_id": "t1",
        "timestamp": 1710000000,
        "signature": "ignored-by-message",
    }

    assert gateway_app.request_signature_message(payload).decode("utf-8") == (
        '{"action":"read","device":"laptop-1","tenant_id":"t1",'
        '"timestamp":1710000000,"user_id":"alice"}'
    )


class FakeSecretProvider(SecretProvider):
    def __init__(self, keys: dict[tuple[str, str], bytes]):
        self.keys = dict(keys)

    def get_device_key(self, tenant_id: str, device: str) -> bytearray:
        try:
            return bytearray(self.keys[(tenant_id, device)])
        except KeyError as exc:
            raise RuntimeError("FAIL_CLOSED") from exc

    def rotate_device_key(self, tenant_id: str, device: str, new_key: bytes) -> None:
        self.keys[(tenant_id, device)] = new_key


class FakeVaultResponse:
    def __init__(self, status_code: int, payload: Optional[dict] = None):
        self.status_code = status_code
        self.payload = payload or {}

    def json(self) -> dict:
        return self.payload


@pytest.fixture
def gateway_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    policy_dir = tmp_path / "policy" / "t1"
    policy_dir.mkdir(parents=True)
    policy_path = policy_dir / "policy.json"
    sig_path = policy_dir / "policy.sig"
    key_path = tmp_path / "secrets" / "policy.key"
    key_path.parent.mkdir(parents=True)
    min_policy_version_path = tmp_path / "policy" / "min_policy_version.txt"
    audit_root = tmp_path / "audit"
    min_policy_version_path.write_text("v1", encoding="utf-8")
    _write_signed_policy(
        policy_path,
        sig_path,
        key_path,
        {
            "policy_version": "v1",
            "rules": [
                {"action": "read", "effect": "ALLOW"},
                {"action": "*", "effect": "BLOCK"},
            ]
        },
    )
    monkeypatch.setattr(gateway_app, "POLICY_ROOT", tmp_path / "policy")
    monkeypatch.setattr(gateway_app, "SECRETS_ROOT", tmp_path / "secrets")
    monkeypatch.setattr(
        gateway_app,
        "keystore",
        KeyStore(LocalFileSecretProvider(tmp_path / "secrets")),
    )
    monkeypatch.setattr(gateway_app, "AUDIT_ROOT", audit_root)
    monkeypatch.setattr(gateway_app, "POLICY_SIGNING_KEY_PATH", key_path)
    monkeypatch.setattr(gateway_app, "MIN_POLICY_VERSION_PATH", min_policy_version_path)
    monkeypatch.setattr(gateway_app, "POLICY_VERSION", "v1")
    monkeypatch.setenv("USBAY_MODE", "PROD")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "secrets" / "t1" / "devices").mkdir(parents=True)
    (tmp_path / "secrets" / "t1" / "devices" / "laptop-1.key").write_bytes(b"device-test-key")
    return policy_path


@pytest.fixture
def audit_log(gateway_policy: Path) -> Path:
    return gateway_app.tenant_audit_log_path("t1")


def test_gateway_allows_signed_read_and_writes_audit(audit_log: Path) -> None:
    client = TestClient(gateway_app.app)

    response = client.post(
        "/execute",
        json=_signed_request(timestamp=int(time.time())),
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"
    assert len(response.json()["chain_hash"]) == 64

    record = json.loads(audit_log.read_text(encoding="utf-8").splitlines()[-1])
    assert record["actor"] == "alice"
    assert record["decision"] == "ALLOW"


def test_gateway_signed_read_and_delete_records_both_decisions(audit_log: Path) -> None:
    client = TestClient(gateway_app.app)

    allow_response = client.post(
        "/execute",
        json=_signed_request(timestamp=int(time.time())),
    )
    block_response = client.post(
        "/execute",
        json=_signed_request(action="delete", timestamp=int(time.time())),
    )

    assert allow_response.status_code == 200
    assert allow_response.json()["decision"] == "ALLOW"
    assert block_response.status_code == 403
    assert block_response.json()["detail"] == "Blocked by policy"

    records = _read_audit_records(audit_log)
    assert [record["decision"] for record in records] == ["ALLOW", "BLOCK"]


def test_gateway_blocks_signed_other_actions_and_writes_audit(audit_log: Path) -> None:
    client = TestClient(gateway_app.app)

    response = client.post(
        "/execute",
        json=_signed_request(action="write", timestamp=int(time.time())),
    )

    assert response.status_code == 403

    record = json.loads(audit_log.read_text(encoding="utf-8").splitlines()[-1])
    assert record["actor"] == "alice"
    assert record["decision"] == "BLOCK"


def test_gateway_fails_closed_for_non_list_rules(gateway_policy: Path, audit_log: Path) -> None:
    _write_signed_policy(
        gateway_app.tenant_policy_path("t1"),
        gateway_app.tenant_sig_path("t1"),
        gateway_app.POLICY_SIGNING_KEY_PATH,
        {"policy_version": "v1", "rules": {"action": "read", "effect": "ALLOW"}},
    )
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json=_signed_request(timestamp=int(time.time())),
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_fails_closed_for_missing_policy_version(gateway_policy: Path, audit_log: Path) -> None:
    _write_signed_policy(
        gateway_app.tenant_policy_path("t1"),
        gateway_app.tenant_sig_path("t1"),
        gateway_app.POLICY_SIGNING_KEY_PATH,
        {
            "rules": [
                {"action": "read", "effect": "ALLOW"},
                {"action": "*", "effect": "BLOCK"},
            ]
        },
    )
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json=_signed_request(timestamp=int(time.time())),
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_fails_closed_for_mismatched_policy_version(gateway_policy: Path, audit_log: Path) -> None:
    _write_signed_policy(
        gateway_app.tenant_policy_path("t1"),
        gateway_app.tenant_sig_path("t1"),
        gateway_app.POLICY_SIGNING_KEY_PATH,
        {
            "policy_version": "v2",
            "rules": [
                {"action": "read", "effect": "ALLOW"},
                {"action": "*", "effect": "BLOCK"},
            ],
        },
    )
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json=_signed_request(timestamp=int(time.time())),
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_fails_closed_for_policy_version_rollback(gateway_policy: Path, audit_log: Path) -> None:
    gateway_app.MIN_POLICY_VERSION_PATH.write_text("v2", encoding="utf-8")
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json=_signed_request(timestamp=int(time.time())),
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_fails_closed_for_signature_mismatch(gateway_policy: Path, audit_log: Path) -> None:
    gateway_policy.write_text(
        json.dumps(
            {
                "policy_version": "v1",
                "rules": [
                    {"action": "read", "effect": "BLOCK"},
                    {"action": "*", "effect": "BLOCK"},
                ]
            }
        ),
        encoding="utf-8",
    )
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json=_signed_request(timestamp=int(time.time())),
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_fails_closed_for_missing_policy_file(gateway_policy: Path, audit_log: Path) -> None:
    gateway_policy.unlink()
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json=_signed_request(timestamp=int(time.time())),
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_fails_closed_for_missing_signature_file(gateway_policy: Path, audit_log: Path) -> None:
    gateway_app.tenant_sig_path("t1").unlink()
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json=_signed_request(timestamp=int(time.time())),
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_prod_unsigned_request_fails_closed(audit_log: Path) -> None:
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json={"action": "read", "user_id": "alice", "device": "laptop-1"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_missing_tenant_fails_closed(audit_log: Path) -> None:
    payload = _signed_request(timestamp=int(time.time()))
    payload.pop("tenant_id")
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_tenant_mismatch_fails_closed(audit_log: Path) -> None:
    t2_policy_dir = gateway_app.POLICY_ROOT / "t2"
    t2_policy_dir.mkdir(parents=True)
    _write_signed_policy(
        t2_policy_dir / "policy.json",
        t2_policy_dir / "policy.sig",
        gateway_app.POLICY_SIGNING_KEY_PATH,
        {
            "policy_version": "v1",
            "rules": [
                {"action": "read", "effect": "ALLOW"},
                {"action": "*", "effect": "BLOCK"},
            ],
        },
    )
    t2_device_dir = gateway_app.SECRETS_ROOT / "t2" / "devices"
    t2_device_dir.mkdir(parents=True)
    (t2_device_dir / "laptop-1.key").write_bytes(b"tenant-two-device-key")

    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json=_signed_request(tenant_id="t2", timestamp=int(time.time())),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_prod_signed_request_succeeds(audit_log: Path) -> None:
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json=_signed_request(timestamp=int(time.time())),
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"
    assert len(response.json()["chain_hash"]) == 64

    record = json.loads(audit_log.read_text(encoding="utf-8").splitlines()[-1])
    assert record["actor"] == "alice"
    assert record["tenant_id"] == "t1"
    assert record["decision"] == "ALLOW"


def test_gateway_prod_signed_delete_blocks_and_writes_audit(audit_log: Path) -> None:
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json=_signed_request(action="delete", timestamp=int(time.time())),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Blocked by policy"

    record = _read_audit_records(audit_log)[-1]
    assert record["actor"] == "alice"
    assert record["decision"] == "BLOCK"


def test_gateway_prod_bad_signature_fails_closed(audit_log: Path) -> None:
    payload = _signed_request(timestamp=int(time.time()))
    payload["signature"] = "bad-signature"
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_prod_unknown_device_fails_closed(audit_log: Path) -> None:
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json=_signed_request(device="unknown-device", timestamp=int(time.time())),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_prod_missing_key_fails_closed(audit_log: Path) -> None:
    (gateway_app.SECRETS_ROOT / "t1" / "devices" / "laptop-1.key").unlink()
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json=_signed_request(timestamp=int(time.time())),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_rotated_key_mismatch_fails_closed(audit_log: Path) -> None:
    gateway_app.keystore.rotate_device_key("t1", "laptop-1", b"rotated-device-key")
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json=_signed_request(timestamp=int(time.time())),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_keystore_context_zeroes_loaded_key(audit_log: Path) -> None:
    with gateway_app.keystore.use_device_key("t1", "laptop-1") as key:
        assert isinstance(key, bytearray)
        assert bytes(key) == b"device-test-key"

    assert bytes(key) == b"\x00" * len(key)


def test_keystore_accepts_fake_provider() -> None:
    store = KeyStore(FakeSecretProvider({("t1", "laptop-1"): b"fake-device-key"}))

    with store.use_device_key("t1", "laptop-1") as key:
        assert bytes(key) == b"fake-device-key"

    assert bytes(key) == b"\x00" * len(key)


def test_keystore_missing_provider_key_fails_closed() -> None:
    store = KeyStore(FakeSecretProvider({}))

    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        with store.use_device_key("t1", "missing-device"):
            pass


def test_keystore_defaults_to_local_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("USBAY_SECRET_PROVIDER", raising=False)

    store = KeyStore()

    assert isinstance(store.provider, LocalFileSecretProvider)


def test_keystore_uses_mocked_vault_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {}

    def fake_get(url: str, headers: dict, timeout: int) -> FakeVaultResponse:
        calls["get"] = {"url": url, "headers": headers, "timeout": timeout}
        return FakeVaultResponse(200, {"data": {"data": {"key": "vault-device-key"}}})

    def fake_post(url: str, headers: dict, json: dict, timeout: int) -> FakeVaultResponse:
        calls["post"] = {"url": url, "headers": headers, "json": json, "timeout": timeout}
        return FakeVaultResponse(204)

    monkeypatch.setenv("USBAY_SECRET_PROVIDER", "vault")
    monkeypatch.setenv("VAULT_ADDR", "https://vault.example")
    monkeypatch.setenv("VAULT_TOKEN", "test-vault-token")
    monkeypatch.setattr(secret_provider.requests, "get", fake_get)
    monkeypatch.setattr(secret_provider.requests, "post", fake_post)

    store = KeyStore()

    with store.use_device_key("t1", "laptop-1") as key:
        assert bytes(key) == b"vault-device-key"

    assert bytes(key) == b"\x00" * len(key)

    store.rotate_device_key("t1", "laptop-1", b"rotated-vault-key")

    assert calls["get"] == {
        "url": "https://vault.example/v1/secret/data/t1/devices/laptop-1",
        "headers": {"X-Vault-Token": "test-vault-token"},
        "timeout": 3,
    }
    assert calls["post"] == {
        "url": "https://vault.example/v1/secret/data/t1/devices/laptop-1",
        "headers": {"X-Vault-Token": "test-vault-token"},
        "json": {"data": {"key": "rotated-vault-key"}},
        "timeout": 3,
    }


def test_keystore_vault_missing_configuration_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USBAY_SECRET_PROVIDER", "vault")
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)

    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        KeyStore()


def test_gateway_fails_closed_for_invalid_min_policy_version(gateway_policy: Path, audit_log: Path) -> None:
    gateway_app.MIN_POLICY_VERSION_PATH.write_text("not-a-version", encoding="utf-8")
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json=_signed_request(timestamp=int(time.time())),
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_audit_records_required_fields_and_chain_links(audit_log: Path) -> None:
    client = TestClient(gateway_app.app)

    first = client.post(
        "/execute",
        json=_signed_request(timestamp=int(time.time())),
    )
    second = client.post(
        "/execute",
        json=_signed_request(action="delete", timestamp=int(time.time())),
    )

    assert first.status_code == 200
    assert second.status_code == 403

    records = _read_audit_records(audit_log)
    assert len(records) == 2

    for record in records:
        for field in ("actor", "tenant_id", "decision", "policy_version", "execution_origin", "workspace", "chain_hash"):
            assert record[field]

    assert audit_log == gateway_app.AUDIT_ROOT / "t1.log"
    assert records[0]["previous_chain_hash"] == "GENESIS"
    assert records[1]["previous_chain_hash"] == records[0]["chain_hash"]


def test_gateway_prod_stale_timestamp_fails_closed(audit_log: Path) -> None:
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json=_signed_request(timestamp=int(time.time()) - 10),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_missing_mode_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("USBAY_MODE", raising=False)

    with pytest.raises(RuntimeError, match="FAIL_CLOSED:MODE_NOT_SET"):
        gateway_app.get_mode()


def test_gateway_non_prod_mode_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USBAY_MODE", "DEV")

    with pytest.raises(RuntimeError, match="FAIL_CLOSED:MODE_NOT_SET"):
        gateway_app.get_mode()
