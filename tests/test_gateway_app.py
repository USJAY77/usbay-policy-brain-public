from __future__ import annotations

import json
import hashlib
import hmac
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gateway import app as gateway_app


def _canonical_policy_bytes(policy: object) -> bytes:
    return json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _write_signed_policy(policy_path: Path, sig_path: Path, key_path: Path, policy: object) -> None:
    policy_bytes = _canonical_policy_bytes(policy)
    key = b"test-policy-key"

    policy_path.write_bytes(policy_bytes)
    key_path.write_bytes(key)

    digest = hashlib.sha256(policy_bytes).digest()
    sig_path.write_text(hmac.new(key, digest, hashlib.sha256).hexdigest(), encoding="utf-8")


@pytest.fixture
def gateway_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    policy_path = tmp_path / "policy.json"
    sig_path = tmp_path / "policy.sig"
    key_path = tmp_path / "policy.key"
    min_policy_version_path = tmp_path / "min_policy_version.txt"
    audit_log_path = tmp_path / "audit.jsonl"
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
    monkeypatch.setattr(gateway_app, "POLICY_PATH", policy_path)
    monkeypatch.setattr(gateway_app, "SIG_PATH", sig_path)
    monkeypatch.setattr(gateway_app, "KEY_PATH", key_path)
    monkeypatch.setattr(gateway_app, "MIN_POLICY_VERSION_PATH", min_policy_version_path)
    monkeypatch.setattr(gateway_app, "POLICY_VERSION", "v1")
    monkeypatch.setattr(gateway_app, "AUDIT_LOG_PATH", audit_log_path)
    return policy_path


@pytest.fixture
def audit_log(gateway_policy: Path) -> Path:
    return gateway_app.AUDIT_LOG_PATH


def test_gateway_allows_read_and_writes_audit(audit_log: Path) -> None:
    client = TestClient(gateway_app.app)

    response = client.post(
        "/execute",
        json={"action": "read", "user_id": "alice", "device": "laptop-1"},
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"
    assert len(response.json()["chain_hash"]) == 64

    record = json.loads(audit_log.read_text(encoding="utf-8").splitlines()[-1])
    assert record["actor"] == "alice"
    assert record["decision"] == "ALLOW"


def test_gateway_blocks_other_actions_and_writes_audit(audit_log: Path) -> None:
    client = TestClient(gateway_app.app)

    response = client.post(
        "/execute",
        json={"action": "write", "user_id": "alice", "device": "laptop-1"},
    )

    assert response.status_code == 403

    record = json.loads(audit_log.read_text(encoding="utf-8").splitlines()[-1])
    assert record["actor"] == "alice"
    assert record["decision"] == "BLOCK"


def test_gateway_fails_closed_for_non_list_rules(gateway_policy: Path, audit_log: Path) -> None:
    _write_signed_policy(
        gateway_app.POLICY_PATH,
        gateway_app.SIG_PATH,
        gateway_app.KEY_PATH,
        {"policy_version": "v1", "rules": {"action": "read", "effect": "ALLOW"}},
    )
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json={"action": "read", "user_id": "alice", "device": "laptop-1"},
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_fails_closed_for_missing_policy_version(gateway_policy: Path, audit_log: Path) -> None:
    _write_signed_policy(
        gateway_app.POLICY_PATH,
        gateway_app.SIG_PATH,
        gateway_app.KEY_PATH,
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
        json={"action": "read", "user_id": "alice", "device": "laptop-1"},
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_fails_closed_for_mismatched_policy_version(gateway_policy: Path, audit_log: Path) -> None:
    _write_signed_policy(
        gateway_app.POLICY_PATH,
        gateway_app.SIG_PATH,
        gateway_app.KEY_PATH,
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
        json={"action": "read", "user_id": "alice", "device": "laptop-1"},
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_fails_closed_for_policy_version_rollback(gateway_policy: Path, audit_log: Path) -> None:
    gateway_app.MIN_POLICY_VERSION_PATH.write_text("v2", encoding="utf-8")
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json={"action": "read", "user_id": "alice", "device": "laptop-1"},
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
        json={"action": "read", "user_id": "alice", "device": "laptop-1"},
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()


def test_gateway_fails_closed_for_missing_policy_file(gateway_policy: Path, audit_log: Path) -> None:
    gateway_policy.unlink()
    client = TestClient(gateway_app.app, raise_server_exceptions=False)

    response = client.post(
        "/execute",
        json={"action": "read", "user_id": "alice", "device": "laptop-1"},
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "FAIL_CLOSED"
    assert not audit_log.exists()
