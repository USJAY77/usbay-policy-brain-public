from __future__ import annotations

import pytest

from governance.operator_review_contracts import (
    OPERATOR_REVIEW_DECISION_SCHEMA,
    OPERATOR_REVIEW_POLICY_VERSION,
    OPERATOR_REVIEW_REQUEST_SCHEMA,
    build_operator_review_audit,
    review_hash,
    validate_review_decision,
    validate_review_request,
)


pytestmark = pytest.mark.governance


def review(**overrides):
    payload = {
        "schema": OPERATOR_REVIEW_DECISION_SCHEMA,
        "review_id": "review-1",
        "request_id": "request-1",
        "proposal_id": "proposal-1",
        "approval_id": "approval-1",
        "operator_id": "operator-1",
        "operator_role": "USBAY_OPERATOR",
        "review_state": "APPROVED",
        "decision": "APPROVED",
        "decision_reason": "Preview request may continue to final governed decision",
        "decision_timestamp": "2026-06-17T02:00:00Z",
        "audit_hash": "r" * 64,
        "previous_hash": "p" * 64,
        "fail_closed": False,
        "policy_version": OPERATOR_REVIEW_POLICY_VERSION,
    }
    payload.update(overrides)
    if overrides.get("audit_hash") == "derived":
        payload["audit_hash"] = review_hash(payload)
    return payload


def test_valid_review_request_contract():
    payload = review(
        schema=OPERATOR_REVIEW_REQUEST_SCHEMA,
        review_state="UNDER_REVIEW",
        decision="NEEDS_INFORMATION",
        fail_closed=True,
    )

    result = validate_review_request(payload)

    assert result.valid is True
    assert result.reason_codes == ()


def test_valid_review_decision_contract():
    result = validate_review_decision(review(audit_hash="derived"))

    assert result.valid is True
    assert result.reason_codes == ()


@pytest.mark.parametrize("decision", ["ALLOW", "BLOCK", "", "AUTO_APPROVED"])
def test_unknown_decision_blocks(decision):
    result = validate_review_decision(review(decision=decision))

    assert result.valid is False
    assert any(code.startswith("OPERATOR_REVIEW_DECISION_UNKNOWN") for code in result.reason_codes)


@pytest.mark.parametrize("state", ["READY", "EXECUTED", "", "AUTO_EXECUTED"])
def test_unknown_state_blocks(state):
    result = validate_review_decision(review(review_state=state))

    assert result.valid is False
    assert any(code.startswith("OPERATOR_REVIEW_STATE_UNKNOWN") for code in result.reason_codes)


@pytest.mark.parametrize("role", ["CODEX", "AI_AGENT", "AUTOMATION", "SYSTEM", "UNKNOWN"])
def test_ai_and_unknown_roles_block(role):
    result = validate_review_decision(review(operator_role=role))

    assert result.valid is False


def test_missing_audit_blocks():
    result = validate_review_decision(review(audit_hash=""))

    assert result.valid is False
    assert "OPERATOR_REVIEW_AUDIT_HASH_MISSING" in result.reason_codes


def test_missing_policy_blocks():
    result = validate_review_decision(review(policy_version=""))

    assert result.valid is False
    assert "OPERATOR_REVIEW_POLICY_VERSION_MISSING" in result.reason_codes


def test_review_audit_redacts_operator_identity_and_disables_auto_flags():
    audit = build_operator_review_audit(
        review=review(),
        decision="APPROVED",
        reason_codes=[],
        previous_hash="p" * 64,
        generated_at="2026-06-17T02:00:00Z",
    )

    assert audit["schema"] == "usbay.operator.review_audit.v1"
    assert audit["audit_hash"]
    assert audit["operator_id_hash"]
    assert "operator-1" not in str(audit)
    assert audit["auto_approved"] is False
    assert audit["auto_executed"] is False
    assert audit["secrets_logged"] is False
    assert audit["raw_payload_logged"] is False
