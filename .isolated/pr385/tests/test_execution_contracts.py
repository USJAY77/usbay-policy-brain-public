from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.execution_contracts import (
    BLOCKED_CAPABILITIES,
    EXECUTION_APPROVAL_SCHEMA,
    EXECUTION_REQUEST_SCHEMA,
    build_execution_audit_record,
    validate_execution_approval,
    validate_execution_request,
)


pytestmark = pytest.mark.governance

NOW = datetime(2026, 6, 17, 1, 0, tzinfo=timezone.utc)


def execution_request(**overrides):
    payload = {
        "schema": EXECUTION_REQUEST_SCHEMA,
        "request_id": "exec-request-1",
        "proposal_id": "proposal-1",
        "capability": "DASHBOARD_PREVIEW",
        "target": "governance-dashboard",
        "parameters": {"view": "governance"},
        "requested_by": "vision-agent-1",
        "requested_at": "2026-06-17T00:00:00Z",
        "policy_version": "usbay.pb-exec.governed-execution-framework.v1",
        "runtime_state_hash": "r" * 64,
        "pbsec_state_hash": "p" * 64,
        "vision_audit_hash": "v" * 64,
        "requires_human_approval": False,
        "risk_level": "LOW",
    }
    payload.update(overrides)
    return payload


def approval(**overrides):
    payload = {
        "schema": EXECUTION_APPROVAL_SCHEMA,
        "approval_id": "exec-approval-1",
        "request_id": "exec-request-1",
        "approved_by_human": True,
        "approver_role": "security-reviewer",
        "approved_scope": "PREVIEW_ONLY",
        "approved_at": "2026-06-17T00:05:00Z",
        "approval_signature_or_hash": "a" * 64,
        "no_ai_auto_approval": True,
    }
    payload.update(overrides)
    return payload


def pbsec_state(**overrides):
    payload = {
        "status": "APPROVED",
        "production_release_approved": True,
        "gates": {"PB-SEC-005": {"decision": "VERIFIED", "fail_closed": False}},
    }
    payload.update(overrides)
    return payload


def test_missing_capability_blocks():
    result = validate_execution_request(execution_request(capability=""))

    assert result.valid is False
    assert "EXEC_REQUEST_CAPABILITY_MISSING" in result.reason_codes
    assert "EXEC_REQUEST_CAPABILITY_UNKNOWN:MISSING" in result.reason_codes


def test_unknown_capability_blocks():
    result = validate_execution_request(execution_request(capability="REMOTE_DESKTOP_CONTROL"))

    assert result.valid is False
    assert "EXEC_REQUEST_CAPABILITY_UNKNOWN:REMOTE_DESKTOP_CONTROL" in result.reason_codes


@pytest.mark.parametrize("capability", sorted(BLOCKED_CAPABILITIES))
def test_blocked_capabilities_block(capability):
    result = validate_execution_request(execution_request(capability=capability))

    assert result.valid is False
    assert f"EXEC_REQUEST_CAPABILITY_BLOCKED:{capability}" in result.reason_codes


def test_request_parameters_with_secret_markers_are_rejected():
    result = validate_execution_request(execution_request(parameters={"api_key": "not-logged"}))

    assert result.valid is False
    assert "EXEC_REQUEST_PARAMETERS_SECRET_MATERIAL_BLOCKED" in result.reason_codes


def test_codex_and_ai_approvals_are_rejected():
    codex = validate_execution_approval(approval(approver_role="codex"), request=execution_request(), now=NOW)
    ai = validate_execution_approval(approval(approver_role="ai-agent"), request=execution_request(), now=NOW)

    assert "EXEC_APPROVAL_AI_APPROVER_BLOCKED" in codex.reason_codes
    assert "EXEC_APPROVAL_AI_APPROVER_BLOCKED" in ai.reason_codes


def test_valid_human_approval_accepted_only_for_preview_scope():
    valid = validate_execution_approval(approval(), request=execution_request(), now=NOW)
    wrong_scope = validate_execution_approval(
        approval(approved_scope="PRODUCTION_EXECUTION"),
        request=execution_request(),
        now=NOW,
    )

    assert valid.valid is True
    assert wrong_scope.valid is False
    assert "EXEC_APPROVAL_SCOPE_MISMATCH" in wrong_scope.reason_codes
    assert "EXEC_APPROVAL_SCOPE_NOT_PREVIEW_ONLY" in wrong_scope.reason_codes


def test_production_approval_requires_pbsec005_verified_evidence():
    production_request = execution_request(target="production-release", risk_level="HIGH")

    result = validate_execution_approval(
        approval(),
        request=production_request,
        pbsec_state={"status": "BLOCKED"},
        now=NOW,
    )

    assert result.valid is False
    assert "EXEC_APPROVAL_PRODUCTION_PBSEC005_NOT_VERIFIED" in result.reason_codes


def test_audit_hash_chain_excludes_raw_parameters_and_secret_values():
    request = execution_request(parameters={"api_key": "must-not-log", "raw_payload": "must-not-log"})
    first = build_execution_audit_record(
        request=request,
        decision="EXECUTION_BLOCKED",
        reason_codes=["TEST"],
        previous_audit_hash="",
        generated_at="2026-06-17T00:10:00Z",
    )
    second = build_execution_audit_record(
        request=request,
        decision="EXECUTION_BLOCKED",
        reason_codes=["TEST"],
        previous_audit_hash=first["audit_hash"],
        generated_at="2026-06-17T00:11:00Z",
    )

    assert first["audit_hash"]
    assert second["previous_audit_hash"] == first["audit_hash"]
    assert second["audit_hash"] != first["audit_hash"]
    assert first["secrets_logged"] is False
    assert first["raw_payload_logged"] is False
    assert "must-not-log" not in str(first)
    assert "must-not-log" not in str(second)
