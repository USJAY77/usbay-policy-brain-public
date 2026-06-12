from __future__ import annotations

import json
from pathlib import Path

from gateway.failure_triage import GatewayFailureClassification, classify_gateway_failure, governed_fail_response
from gateway.governance_gateway import evaluate_gateway_request


def _registry(path: Path) -> str:
    policy_hash = "b" * 64
    path.write_text(
        json.dumps(
            {
                "active": True,
                "policy_hash": policy_hash,
                "policy_id": "usbay.governance_gateway.contract.v1",
                "policy_version": "1.0.0",
                "signature_metadata": {
                    "active": True,
                    "expires_at": "2030-01-01T00:00:00Z",
                    "policy_hash": policy_hash,
                    "signature_id": "test-signature",
                    "signed_at": "2026-06-11T00:00:00Z",
                    "signer": "test-signer",
                },
            }
        ),
        encoding="utf-8",
    )
    return policy_hash


def _payload(policy_hash: str) -> dict:
    return {
        "diff": {"changed_files": ["gateway/governance_gateway.py"]},
        "pr_number": 217,
        "policy_hash": policy_hash,
        "actor": "gateway-failure-test",
        "source": "pytest",
    }


def test_gateway_failure_triage_classifies_required_failures() -> None:
    cases = {
        "MALFORMED_REQUEST": GatewayFailureClassification.MALFORMED_REQUEST,
        "UNKNOWN_POLICY_HASH": GatewayFailureClassification.UNKNOWN_POLICY_HASH,
        "EVALUATOR_TIMEOUT": GatewayFailureClassification.EVALUATOR_TIMEOUT,
        "AUDIT_WRITE_FAILED": GatewayFailureClassification.AUDIT_WRITE_FAILED,
        "CONNECTOR_DISABLED": GatewayFailureClassification.CONNECTOR_DISABLED,
        "APPROVAL_REQUIRED": GatewayFailureClassification.APPROVAL_REQUIRED,
        "SIGNATURE_INVALID": GatewayFailureClassification.SIGNATURE_INVALID,
    }
    for gap, classification in cases.items():
        assert classify_gateway_failure([gap]) == classification


def test_governed_failure_response_never_raises_and_blocks() -> None:
    response = governed_fail_response(["APPROVAL_REQUIRED"], gateway_version="test-gateway")
    assert response["decision"] == "FAIL_CLOSED"
    assert response["status"] == "FAIL"
    assert response["approved"] is False
    assert response["failure_classification"] == "APPROVAL_REQUIRED"


def test_gateway_returns_governed_fail_for_signature_invalid(tmp_path: Path) -> None:
    registry_path = tmp_path / "policy_registry.json"
    policy_hash = _registry(registry_path)
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry["signature_metadata"]["active"] = False
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    result = evaluate_gateway_request(_payload(policy_hash), policy_registry_path=registry_path, audit_path=tmp_path / "audit.json")
    assert result["decision"] == "FAIL_CLOSED"
    assert result["failure_classification"] == "SIGNATURE_INVALID"


def test_gateway_returns_governed_fail_for_unknown_policy_hash(tmp_path: Path) -> None:
    registry_path = tmp_path / "policy_registry.json"
    _registry(registry_path)
    result = evaluate_gateway_request(_payload("c" * 64), policy_registry_path=registry_path, audit_path=tmp_path / "audit.json")
    assert result["decision"] == "FAIL_CLOSED"
    assert result["failure_classification"] == "UNKNOWN_POLICY_HASH"
    assert result["audit"]["audit_hash"]
