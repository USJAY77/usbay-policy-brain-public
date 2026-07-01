from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.work_item_contracts import WORK_ITEM_SCHEMA, WORK_POLICY_VERSION, work_hash
from governance.work_orchestrator import (
    WORK_STATUS_BLOCKED,
    build_work_audit_lineage,
    empty_work_orchestrator_dashboard_state,
    evaluate_work_transition,
)


pytestmark = pytest.mark.governance

NOW = datetime(2026, 6, 17, 3, 0, tzinfo=timezone.utc)
POLICY = WORK_POLICY_VERSION


def link(link_id, **overrides):
    payload = {
        f"{link_id}_id": f"{link_id}-1",
        "audit_hash": link_id[0] * 64,
        "timestamp": "2026-06-17T02:00:00Z",
        "policy_version": POLICY,
    }
    payload.update(overrides)
    return payload


def work_item(**overrides):
    payload = {
        "schema": WORK_ITEM_SCHEMA,
        "work_item_id": "work-1",
        "source_review_id": "review-1",
        "source_request_id": "request-1",
        "source_proposal_id": "proposal-1",
        "source_decision_id": "decision-1",
        "owner_id": "operator-1",
        "owner_role": "USBAY_OPERATOR",
        "priority": "P1",
        "severity": "HIGH",
        "created_at": "2026-06-17T03:00:00Z",
        "assigned_at": "2026-06-17T03:05:00Z",
        "resolved_at": "2026-06-17T03:30:00Z",
        "closed_at": "2026-06-17T03:45:00Z",
        "status": "NEW",
        "audit_hash": "w" * 64,
        "lineage_hash": "l" * 64,
        "policy_version": POLICY,
        "fail_closed": False,
    }
    payload.update(overrides)
    if overrides.get("audit_hash") == "derived":
        payload["audit_hash"] = work_hash(payload)
    return payload


def escalation(**overrides):
    payload = {
        "escalation_id": "esc-1",
        "work_item_id": "work-1",
        "reason": "Escalate to auditor",
        "requested_by": "operator-1",
        "timestamp": "2026-06-17T03:10:00Z",
        "target_role": "USBAY_AUDITOR",
        "audit_hash": "e" * 64,
        "policy_version": POLICY,
    }
    payload.update(overrides)
    return payload


def assignment(**overrides):
    return link("assignment", timestamp="2026-06-17T03:05:00Z", **overrides)


def resolution(**overrides):
    return link("resolution", timestamp="2026-06-17T03:30:00Z", **overrides)


def closure(**overrides):
    return link("closure", timestamp="2026-06-17T03:45:00Z", **overrides)


def context(**overrides):
    payload = {
        "observation": link("observation"),
        "proposal": link("proposal"),
        "request": link("request"),
        "approval": link("approval"),
        "review": link("review"),
        "decision": link("decision"),
        "assignment": assignment(),
        "resolution": resolution(),
        "closure": closure(),
    }
    payload.update(overrides)
    return payload


def evaluate(item=None, next_status="ASSIGNED", **overrides):
    ctx = context(**overrides)
    return evaluate_work_transition(
        work_item=work_item() if item is None else item,
        next_status=next_status,
        previous_hash="p" * 64,
        now=NOW,
        **ctx,
    )


def test_valid_work_creation():
    result = evaluate(next_status="NEW")

    assert result.status == "NEW"
    assert result.reason_codes == ()


def test_valid_assignment():
    result = evaluate(next_status="ASSIGNED")

    assert result.status == "ASSIGNED"
    assert result.audit_record["auto_assigned"] is False


def test_valid_escalation():
    result = evaluate(next_status="ESCALATED", escalation=escalation())

    assert result.status == "ESCALATED"
    assert result.audit_record["auto_escalated"] is False


def test_valid_resolution():
    result = evaluate(item=work_item(status="IN_PROGRESS"), next_status="RESOLVED")

    assert result.status == "RESOLVED"
    assert result.audit_record["auto_resolved"] is False


def test_valid_closure():
    result = evaluate(item=work_item(status="RESOLVED"), next_status="CLOSED")

    assert result.status == "CLOSED"
    assert result.audit_record["auto_closed"] is False


@pytest.mark.parametrize(
    ("item", "reason"),
    [
        (work_item(owner_id=""), "WORK_OWNER_MISSING"),
        (work_item(audit_hash=""), "WORK_AUDIT_HASH_MISSING"),
        (work_item(lineage_hash=""), "WORK_LINEAGE_HASH_MISSING"),
        (work_item(policy_version=""), "WORK_POLICY_VERSION_MISSING"),
        (work_item(owner_role="AI_AGENT"), "WORK_AI_OWNERSHIP_BLOCKED"),
        (work_item(owner_role="CODEX"), "WORK_AI_OWNERSHIP_BLOCKED"),
        (work_item(owner_role="AUTOMATION"), "WORK_AI_OWNERSHIP_BLOCKED"),
        (work_item(status="CLOSED"), "WORK_INVALID_TRANSITION:CLOSED->ASSIGNED"),
    ],
)
def test_fail_closed_controls(item, reason):
    result = evaluate(item=item)

    assert result.status == WORK_STATUS_BLOCKED
    assert reason in result.reason_codes


def test_invalid_transition_blocks():
    result = evaluate(item=work_item(status="NEW"), next_status="CLOSED")

    assert result.status == WORK_STATUS_BLOCKED
    assert "WORK_INVALID_TRANSITION:NEW->CLOSED" in result.reason_codes


def test_invalid_closure_blocks_without_resolved_status():
    result = evaluate(item=work_item(status="IN_PROGRESS"), next_status="CLOSED")

    assert result.status == WORK_STATUS_BLOCKED
    assert "WORK_CLOSURE_REQUIRES_RESOLVED_STATUS" in result.reason_codes


def test_missing_resolution_blocks():
    result = evaluate(item=work_item(status="IN_PROGRESS"), next_status="RESOLVED", resolution=None)

    assert result.status == WORK_STATUS_BLOCKED
    assert "WORK_RESOLUTION_MISSING" in result.reason_codes


def test_missing_decision_blocks_closure():
    result = evaluate(item=work_item(status="RESOLVED"), next_status="CLOSED", decision=None)

    assert result.status == WORK_STATUS_BLOCKED
    assert "WORK_DECISION_MISSING" in result.reason_codes


def test_escalation_missing_reason_requester_and_audit_blocks():
    result = evaluate(
        next_status="ESCALATED",
        escalation=escalation(reason="", requested_by="", audit_hash=""),
    )

    assert result.status == WORK_STATUS_BLOCKED
    assert "WORK_ESCALATION_REASON_MISSING" in result.reason_codes
    assert "WORK_ESCALATION_REQUESTED_BY_MISSING" in result.reason_codes
    assert "WORK_ESCALATION_AUDIT_HASH_MISSING" in result.reason_codes


def test_audit_lineage_requires_every_link():
    lineage = build_work_audit_lineage(
        observation=link("observation"),
        proposal=link("proposal"),
        request=link("request"),
        approval=link("approval"),
        review=link("review"),
        decision=link("decision", policy_version=""),
        work_item=work_item(),
        assignment=assignment(audit_hash=""),
        resolution=resolution(),
        closure=closure(),
        previous_hash="p" * 64,
        generated_at="2026-06-17T03:00:00Z",
    )

    assert lineage["fail_closed"] is True
    assert "WORK_LINEAGE_ASSIGNMENT_AUDIT_HASH_MISSING" in lineage["reason_codes"]
    assert "WORK_LINEAGE_DECISION_POLICY_VERSION_MISSING" in lineage["reason_codes"]
    assert lineage["lineage_hash"]
    assert lineage["secrets_logged"] is False
    assert lineage["raw_payload_logged"] is False


def test_empty_dashboard_state_is_fail_closed():
    state = empty_work_orchestrator_dashboard_state()

    assert state["status"] == "BLOCKED"
    assert state["queue_counts"]["new"] == 0
    assert state["auto_assigned"] is False
    assert state["auto_resolved"] is False
    assert state["auto_closed"] is False
    assert state["auto_escalated"] is False
