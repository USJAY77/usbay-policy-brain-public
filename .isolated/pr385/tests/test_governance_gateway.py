from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from gateway.governance_gateway import app, evaluate_gateway_request


def _registry(path: Path, *, active: bool = True) -> str:
    policy_hash = "c" * 64
    path.write_text(
        json.dumps(
            {
                "policy_id": "usbay.governance_gateway.contract.v1",
                "policy_hash": policy_hash,
                "policy_version": "1.0.0",
                "active": active,
                "signature_metadata": {
                    "policy_hash": policy_hash,
                    "signature_id": "test-policy-signature",
                    "signed_at": "2026-06-11T00:00:00Z",
                    "signer": "test-signer",
                    "active": active,
                    "expires_at": "2030-01-01T00:00:00Z",
                },
            }
        ),
        encoding="utf-8",
    )
    return policy_hash


def _payload(policy_hash: str) -> dict:
    return {
        "diff": {"changed_files": ["gateway/governance_gateway.py"]},
        "pr_number": 212,
        "policy_hash": policy_hash,
        "actor": "local-governance-test",
        "source": "pytest",
    }


def test_gateway_evaluate_verifies_valid_request_and_writes_audit(tmp_path: Path) -> None:
    registry_path = tmp_path / "policy_registry.json"
    policy_hash = _registry(registry_path)
    audit_path = tmp_path / "gateway_audit.json"
    result = evaluate_gateway_request(_payload(policy_hash), policy_registry_path=registry_path, audit_path=audit_path)
    assert result["decision"] == "VERIFIED"
    assert result["audit"]["audit_hash"]
    audit_text = audit_path.read_text(encoding="utf-8")
    assert "raw_diff" not in audit_text
    assert "gateway/governance_gateway.py" not in audit_text


def test_gateway_fails_closed_on_malformed_request(tmp_path: Path) -> None:
    registry_path = tmp_path / "policy_registry.json"
    _registry(registry_path)
    result = evaluate_gateway_request({"actor": "alice"}, policy_registry_path=registry_path, audit_path=tmp_path / "audit.json")
    assert result["decision"] == "FAIL_CLOSED"
    assert "MISSING_DIFF" in result["gaps"]
    assert result["audit"] is None


def test_gateway_fails_closed_on_malformed_changed_files(tmp_path: Path) -> None:
    registry_path = tmp_path / "policy_registry.json"
    policy_hash = _registry(registry_path)
    payload = _payload(policy_hash)
    payload["diff"] = {"changed_files": "not-a-list"}
    result = evaluate_gateway_request(payload, policy_registry_path=registry_path, audit_path=tmp_path / "audit.json")
    assert result["decision"] == "FAIL_CLOSED"
    assert "MALFORMED_DIFF" in result["gaps"]
    assert result["audit"] is None


def test_gateway_fails_closed_on_unknown_policy_hash(tmp_path: Path) -> None:
    registry_path = tmp_path / "policy_registry.json"
    _registry(registry_path)
    result = evaluate_gateway_request(_payload("d" * 64), policy_registry_path=registry_path, audit_path=tmp_path / "audit.json")
    assert result["decision"] == "FAIL_CLOSED"
    assert "UNKNOWN_POLICY_HASH" in result["gaps"]
    assert result["audit"]["audit_hash"]


def test_gateway_fails_closed_on_missing_policy(tmp_path: Path) -> None:
    result = evaluate_gateway_request(
        _payload("c" * 64),
        policy_registry_path=tmp_path / "missing.json",
        audit_path=tmp_path / "audit.json",
    )
    assert result["decision"] == "FAIL_CLOSED"
    assert "MISSING_POLICY" in result["gaps"]


def test_fastapi_evaluate_endpoint_returns_fail_closed_for_bad_json() -> None:
    client = TestClient(app)
    response = client.post("/evaluate", content="not-json")
    assert response.status_code == 200
    assert response.json()["decision"] == "FAIL_CLOSED"
