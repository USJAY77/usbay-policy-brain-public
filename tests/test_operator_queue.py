from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.operator_queue import (
    OPERATOR_DECISION_APPROVED,
    OPERATOR_DECISION_BLOCKED,
    OPERATOR_DECISION_NEEDS_INFORMATION,
    OPERATOR_DECISION_REJECTED,
    build_operator_audit_lineage,
    empty_operator_queue_dashboard_state,
    evaluate_operator_review,
)
from governance.operator_review_contracts import OPERATOR_REVIEW_DECISION_SCHEMA, OPERATOR_REVIEW_POLICY_VERSION, review_hash


pytestmark = pytest.mark.governance

NOW = datetime(2026, 6, 17, 2, 0, tzinfo=timezone.utc)
POLICY = OPERATOR_REVIEW_POLICY_VERSION


def observation(**overrides):
    payload = {
        "observation_id": "obs-1",
        "audit_hash": "o" * 64,
        "timestamp": "2026-06-17T01:00:00Z",
        "policy_version": POLICY,
    }
    payload.update(overrides)
    return payload


def proposal(**overrides):
    payload = {
        "proposal_id": "proposal-1",
        "audit_hash": "p" * 64,
        "created_at": "2026-06-17T01:05:00Z",
        "policy_version": POLICY,
    }
    payload.update(overrides)
    return payload


def request(**overrides):
    payload = {
        "request_id": "request-1",
        "proposal_id": "proposal-1",
        "requested_by": "vision-agent-1",
        "audit_hash": "q" * 64,
        "requested_at": "2026-06-17T01:10:00Z",
        "policy_version": POLICY,
    }
    payload.update(overrides)
    return payload


def approval(**overrides):
    payload = {
        "approval_id": "approval-1",
        "request_id": "request-1",
        "proposal_id": "proposal-1",
        "approver_id": "security-reviewer-1",
        "audit_hash": "a" * 64,
        "approved_at": "2026-06-17T01:15:00Z",
        "policy_version": POLICY,
    }
    payload.update(overrides)
    return payload


def execution_decision(**overrides):
    payload = {
        "decision_id": "decision-1",
        "decision": "EXECUTION_ALLOWED_PREVIEW",
        "audit_hash": "d" * 64,
        "generated_at": "2026-06-17T01:20:00Z",
        "policy_version": POLICY,
    }
    payload.update(overrides)
    return payload


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
        "decision_reason": "Human operator approved preview-only continuation",
        "decision_timestamp": "2026-06-17T02:00:00Z",
        "audit_hash": "r" * 64,
        "previous_hash": "x" * 64,
        "fail_closed": False,
        "policy_version": POLICY,
    }
    payload.update(overrides)
    if overrides.get("audit_hash") == "derived":
        payload["audit_hash"] = review_hash(payload)
    return payload


def evaluate(review_payload=None, **overrides):
    return evaluate_operator_review(
        review=review() if review_payload is None else review_payload,
        observation=overrides.get("observation", observation()),
        proposal=overrides.get("proposal", proposal()),
        request=overrides.get("request", request()),
        approval=overrides.get("approval", approval()),
        execution_decision=overrides.get("execution_decision", execution_decision()),
        previous_hash="x" * 64,
        now=NOW,
    )


def test_valid_approval_path():
    result = evaluate(review(audit_hash="derived"))

    assert result.decision == OPERATOR_DECISION_APPROVED
    assert result.review_state == "APPROVED"
    assert result.reason_codes == ()
    assert result.execution_engine_status == "DISABLED"
    assert result.adapter_status == "NOT_IMPLEMENTED"


def test_valid_rejection_path():
    result = evaluate(review(review_state="REJECTED", decision="REJECTED", fail_closed=True))

    assert result.decision == OPERATOR_DECISION_REJECTED
    assert result.review_state == "REJECTED"


def test_needs_information_path():
    result = evaluate(review(review_state="NEEDS_INFORMATION", decision="NEEDS_INFORMATION", fail_closed=True))

    assert result.decision == OPERATOR_DECISION_NEEDS_INFORMATION
    assert result.review_state == "NEEDS_INFORMATION"


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (review(operator_id=""), "OP_OPERATOR_ID_MISSING"),
        (review(audit_hash=""), "OP_AUDIT_HASH_MISSING"),
        (review(policy_version=""), "OP_POLICY_VERSION_MISSING"),
        (review(operator_role="AI_AGENT"), "OP_AI_OPERATOR_BLOCKED"),
        (review(operator_role="CODEX"), "OP_AI_OPERATOR_BLOCKED"),
        (review(operator_id="vision-agent-1"), "OP_SELF_APPROVAL_BLOCKED"),
        (review(operator_role="UNKNOWN"), "OPERATOR_ROLE_UNKNOWN:UNKNOWN"),
        (review(review_state="AUTO_EXECUTED"), "OP_QUEUE_STATE_UNKNOWN:AUTO_EXECUTED"),
        (review(decision="AUTO_APPROVED"), "OP_DECISION_UNKNOWN:AUTO_APPROVED"),
    ],
)
def test_fail_closed_operator_blocks(payload, reason):
    result = evaluate(payload)

    assert result.decision == OPERATOR_DECISION_BLOCKED
    assert result.review_state == "BLOCKED"
    assert reason in result.reason_codes


def test_missing_review_blocks():
    result = evaluate_operator_review(review=None, now=NOW)

    assert result.decision == OPERATOR_DECISION_BLOCKED
    assert "OP_REVIEW_MISSING" in result.reason_codes


def test_approval_link_mismatch_blocks():
    result = evaluate(review(approval_id="different"))

    assert result.decision == OPERATOR_DECISION_BLOCKED
    assert "OP_APPROVAL_LINK_MISMATCH" in result.reason_codes


def test_audit_lineage_requires_every_link():
    lineage = build_operator_audit_lineage(
        observation=observation(),
        proposal=proposal(),
        request=request(audit_hash=""),
        approval=approval(),
        review=review(),
        execution_decision=execution_decision(policy_version=""),
        previous_hash="x" * 64,
        generated_at="2026-06-17T02:00:00Z",
    )

    assert lineage["fail_closed"] is True
    assert "OP_LINEAGE_REQUEST_AUDIT_HASH_MISSING" in lineage["reason_codes"]
    assert "OP_LINEAGE_DECISION_POLICY_VERSION_MISSING" in lineage["reason_codes"]
    assert lineage["lineage_hash"]
    assert lineage["secrets_logged"] is False
    assert lineage["raw_payload_logged"] is False


def test_empty_dashboard_state_is_fail_closed():
    state = empty_operator_queue_dashboard_state()

    assert state["review_state"] == "BLOCKED"
    assert state["decision"] == "BLOCKED"
    assert state["execution_engine_status"] == "DISABLED"
    assert state["adapter_status"] == "NOT_IMPLEMENTED"
    assert state["auto_approved"] is False
    assert state["auto_executed"] is False
    assert state["auto_released"] is False
