from __future__ import annotations

import pytest

from governance.work_item_contracts import (
    WORK_ASSIGNMENT_SCHEMA,
    WORK_CLOSURE_SCHEMA,
    WORK_ITEM_SCHEMA,
    WORK_POLICY_VERSION,
    WORK_RESOLUTION_SCHEMA,
    build_work_audit_record,
    validate_escalation,
    validate_work_assignment,
    validate_work_closure,
    validate_work_item,
    validate_work_resolution,
    work_hash,
)


pytestmark = pytest.mark.governance


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
        "policy_version": WORK_POLICY_VERSION,
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
        "reason": "Human operator needs auditor review",
        "requested_by": "operator-1",
        "timestamp": "2026-06-17T03:10:00Z",
        "target_role": "USBAY_AUDITOR",
        "audit_hash": "e" * 64,
        "policy_version": WORK_POLICY_VERSION,
    }
    payload.update(overrides)
    return payload


def test_valid_work_creation_contract():
    result = validate_work_item(work_item(audit_hash="derived"))

    assert result.valid is True
    assert result.reason_codes == ()


def test_valid_assignment_resolution_and_closure_contracts():
    assignment = validate_work_assignment(work_item(schema=WORK_ASSIGNMENT_SCHEMA, status="ASSIGNED"))
    resolution = validate_work_resolution(work_item(schema=WORK_RESOLUTION_SCHEMA, status="RESOLVED"))
    closure = validate_work_closure(work_item(schema=WORK_CLOSURE_SCHEMA, status="CLOSED"))

    assert assignment.valid is True
    assert resolution.valid is True
    assert closure.valid is True


@pytest.mark.parametrize("status", ["READY", "AUTO_CLOSED", "", "BLOCKED"])
def test_unknown_status_blocks(status):
    result = validate_work_item(work_item(status=status))

    assert result.valid is False
    assert any(code.startswith("WORK_STATUS_UNKNOWN") for code in result.reason_codes)


@pytest.mark.parametrize("role", ["AI_AGENT", "CODEX", "AUTOMATION", "SYSTEM", "UNKNOWN"])
def test_ai_and_unknown_owner_roles_block(role):
    result = validate_work_item(work_item(owner_role=role))

    assert result.valid is False


def test_missing_owner_blocks():
    result = validate_work_item(work_item(owner_id=""))

    assert result.valid is False
    assert "WORK_ITEM_OWNER_ID_MISSING" in result.reason_codes


def test_missing_audit_lineage_and_policy_block():
    result = validate_work_item(work_item(audit_hash="", lineage_hash="", policy_version=""))

    assert result.valid is False
    assert "WORK_AUDIT_HASH_MISSING" in result.reason_codes
    assert "WORK_LINEAGE_HASH_MISSING" in result.reason_codes
    assert "WORK_POLICY_VERSION_MISSING" in result.reason_codes


def test_valid_escalation_contract():
    result = validate_escalation(escalation())

    assert result.valid is True
    assert result.reason_codes == ()


def test_escalation_missing_reason_requester_and_audit_blocks():
    result = validate_escalation(escalation(reason="", requested_by="", audit_hash=""))

    assert result.valid is False
    assert "WORK_ESCALATION_REASON_MISSING" in result.reason_codes
    assert "WORK_ESCALATION_REQUESTED_BY_MISSING" in result.reason_codes
    assert "WORK_ESCALATION_AUDIT_HASH_MISSING" in result.reason_codes


def test_work_audit_redacts_owner_and_disables_auto_flags():
    audit = build_work_audit_record(
        work_item=work_item(),
        status="ASSIGNED",
        reason_codes=[],
        previous_hash="p" * 64,
        generated_at="2026-06-17T03:05:00Z",
    )

    assert audit["audit_hash"]
    assert audit["owner_id_hash"]
    assert "operator-1" not in str(audit)
    assert audit["auto_assigned"] is False
    assert audit["auto_resolved"] is False
    assert audit["auto_closed"] is False
    assert audit["auto_escalated"] is False
    assert audit["secrets_logged"] is False
    assert audit["raw_payload_logged"] is False
