from __future__ import annotations

import json
from pathlib import Path

from governance.policy_signature_registry import validate_policy_registry_file, validate_policy_signature_registry


def _registry(policy_hash: str = "a" * 64) -> dict:
    return {
        "active": True,
        "policy_hash": policy_hash,
        "policy_id": "usbay.governance_gateway.contract.v1",
        "policy_version": "1.0.0",
        "signature_metadata": {
            "active": True,
            "expires_at": "2030-01-01T00:00:00Z",
            "policy_hash": policy_hash,
            "signature_id": "policy-signature-test",
            "signed_at": "2026-06-11T00:00:00Z",
            "signer": "policy_signer_hash_test",
        },
    }


def test_policy_signature_registry_verifies_complete_active_metadata(tmp_path: Path) -> None:
    registry_path = tmp_path / "policy_registry.json"
    registry_path.write_text(json.dumps(_registry()), encoding="utf-8")
    result = validate_policy_registry_file(registry_path)
    assert result["decision"] == "VERIFIED"
    assert result["signature_id"] == "policy-signature-test"
    assert result["production_activation_allowed"] is False


def test_policy_signature_registry_fails_closed_when_signature_missing() -> None:
    registry = _registry()
    registry.pop("signature_metadata")
    result = validate_policy_signature_registry(registry)
    assert result["decision"] == "FAIL_CLOSED"
    assert "SIGNATURE_MISSING" in result["gaps"]


def test_policy_signature_registry_fails_closed_when_signature_expired() -> None:
    registry = _registry()
    registry["signature_metadata"]["expires_at"] = "2026-01-01T00:00:00Z"
    result = validate_policy_signature_registry(registry)
    assert result["decision"] == "FAIL_CLOSED"
    assert "SIGNATURE_EXPIRED" in result["gaps"]


def test_policy_signature_registry_fails_closed_when_inactive() -> None:
    registry = _registry()
    registry["signature_metadata"]["active"] = False
    result = validate_policy_signature_registry(registry)
    assert result["decision"] == "FAIL_CLOSED"
    assert "SIGNATURE_NOT_ACTIVE" in result["gaps"]


def test_policy_signature_registry_fails_closed_on_hash_mismatch() -> None:
    registry = _registry()
    registry["signature_metadata"]["policy_hash"] = "b" * 64
    result = validate_policy_signature_registry(registry)
    assert result["decision"] == "FAIL_CLOSED"
    assert "SIGNATURE_POLICY_HASH_MISMATCH" in result["gaps"]
