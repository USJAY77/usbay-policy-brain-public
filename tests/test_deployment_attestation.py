from __future__ import annotations

from deployment.deployment_attestation_contract import deployment_attestation_schema, validate_deployment_attestation


def _attestation(status: str = "BLOCKED") -> dict:
    return {
        "deployment_id": "deploy-pb219-test",
        "actor": "deployment-reviewer",
        "commit_sha": "abc123",
        "policy_hash": "e" * 64,
        "signature_id": "policy-signature-test",
        "environment": "controlled-live-pilot",
        "created_at": "2026-06-11T00:00:00Z",
        "status": status,
    }


def test_deployment_attestation_schema_defaults_to_blocked() -> None:
    schema = deployment_attestation_schema()
    assert schema["default_status"] == "BLOCKED"
    assert schema["deployment_allowed"] is False
    assert "deployment_id" in schema["required"]


def test_deployment_attestation_validation_blocks_unless_checks_pass() -> None:
    result = validate_deployment_attestation(_attestation("READY_FOR_REVIEW"), all_checks_passed=False)
    assert result["decision"] == "FAIL_CLOSED"
    assert result["status"] == "BLOCKED"
    assert "ATTESTATION_STATUS_MUST_DEFAULT_BLOCKED" in result["gaps"]


def test_deployment_attestation_can_be_ready_for_review_without_deploying_after_checks() -> None:
    result = validate_deployment_attestation(_attestation(), all_checks_passed=True)
    assert result["decision"] == "VERIFIED"
    assert result["status"] == "READY_FOR_REVIEW"
    assert result["deployment_allowed"] is False


def test_deployment_attestation_blocks_missing_fields() -> None:
    payload = _attestation()
    payload.pop("signature_id")
    result = validate_deployment_attestation(payload, all_checks_passed=True)
    assert result["decision"] == "FAIL_CLOSED"
    assert "MISSING_SIGNATURE_ID" in result["gaps"]
