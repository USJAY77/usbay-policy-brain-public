from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.execution_contracts import EXECUTION_APPROVAL_SCHEMA, EXECUTION_REQUEST_SCHEMA
from governance.execution_governance import (
    DECISION_ALLOWED_PREVIEW,
    DECISION_BLOCKED,
    evaluate_execution_governance,
)


pytestmark = pytest.mark.governance

NOW = datetime(2026, 6, 17, 1, 0, tzinfo=timezone.utc)
DEFAULT = object()


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


def runtime_state(**overrides):
    payload = {
        "schema_version": "usbay.runtime_governance_state.v1",
        "status": "READY",
        "fail_closed": False,
        "evidence_hash": "e" * 64,
        "pb020_decision": "VERIFIED",
        "reason_codes": ["PB020_EVIDENCE_VERIFIED"],
    }
    payload.update(overrides)
    return payload


def pbsec_state(**overrides):
    payload = {
        "status": "APPROVED",
        "production_release_approved": True,
        "gates": {
            "PB-SEC-001": {"decision": "VERIFIED", "fail_closed": False},
            "PB-SEC-002": {"decision": "VERIFIED", "fail_closed": False},
            "PB-SEC-003": {"decision": "VERIFIED", "fail_closed": False},
            "PB-SEC-004": {"decision": "VERIFIED", "fail_closed": False},
            "PB-SEC-005": {"decision": "VERIFIED", "fail_closed": False},
        },
    }
    payload.update(overrides)
    return payload


def decide(request=DEFAULT, runtime=DEFAULT, pbsec=DEFAULT, approval_payload=None):
    return evaluate_execution_governance(
        request=execution_request() if request is DEFAULT else request,
        runtime_state=runtime_state() if runtime is DEFAULT else runtime,
        pbsec_state=pbsec_state() if pbsec is DEFAULT else pbsec,
        approval=approval_payload,
        now=NOW,
    )


def test_missing_capability_blocks():
    decision = decide(request=execution_request(capability=""))

    assert decision.decision == DECISION_BLOCKED
    assert "EXEC_REQUEST_CAPABILITY_MISSING" in decision.reason_codes


def test_unknown_capability_blocks():
    decision = decide(request=execution_request(capability="REMOTE_DESKTOP_CONTROL"))

    assert decision.decision == DECISION_BLOCKED
    assert "EXEC_UNKNOWN_CAPABILITY_BLOCKED:REMOTE_DESKTOP_CONTROL" in decision.reason_codes


@pytest.mark.parametrize("capability", ["FILE_WRITE", "SHELL_EXECUTION", "PUSH_CODE", "MERGE_PR", "BROWSER_CLICK"])
def test_real_execution_capabilities_block(capability):
    decision = decide(request=execution_request(capability=capability))

    assert decision.decision == DECISION_BLOCKED
    assert f"EXEC_REAL_CAPABILITY_BLOCKED:{capability}" in decision.reason_codes


def test_preview_capability_allowed_only_as_preview():
    decision = decide()

    assert decision.decision == DECISION_ALLOWED_PREVIEW
    assert "EXEC_ALLOWED_PREVIEW_ONLY" in decision.reason_codes
    assert decision.execution_engine_status == "DISABLED"
    assert decision.adapter_status == "NOT_IMPLEMENTED"


def test_missing_runtime_state_blocks():
    decision = decide(runtime=None)

    assert decision.decision == DECISION_BLOCKED
    assert "EXEC_RUNTIME_STATE_MISSING" in decision.reason_codes
    assert "EXEC_RUNTIME_GOVERNANCE_STATE_INVALID" in decision.reason_codes


def test_stale_pb020_blocks():
    decision = decide(runtime=runtime_state(status="BLOCKED", fail_closed=True, reason_codes=["PB020_RUNTIME_EVIDENCE_STALE"]))

    assert decision.decision == DECISION_BLOCKED
    assert "EXEC_PB020_EVIDENCE_STALE" in decision.reason_codes


def test_missing_pbsec_blocks_security_sensitive_action():
    decision = decide(request=execution_request(capability="FILE_READ"), pbsec={})

    assert decision.decision == DECISION_BLOCKED
    assert "EXEC_PBSEC_STATE_INVALID" in decision.reason_codes


def test_missing_human_approval_blocks_when_required():
    decision = decide(request=execution_request(requires_human_approval=True))

    assert decision.decision == DECISION_BLOCKED
    assert "EXEC_HUMAN_APPROVAL_MISSING" in decision.reason_codes


def test_valid_human_approval_allows_preview_scope_only():
    request = execution_request(requires_human_approval=True)

    decision = decide(request=request, approval_payload=approval())

    assert decision.decision == DECISION_ALLOWED_PREVIEW


def test_production_deploy_blocks():
    decision = decide(request=execution_request(capability="PRODUCTION_DEPLOY", target="production"))

    assert decision.decision == DECISION_BLOCKED
    assert "EXEC_PRODUCTION_TARGET_BLOCKED" in decision.reason_codes
    assert "EXEC_REAL_CAPABILITY_BLOCKED:PRODUCTION_DEPLOY" in decision.reason_codes


def test_unknown_target_blocks():
    decision = decide(request=execution_request(target="UNKNOWN"))

    assert decision.decision == DECISION_BLOCKED
    assert "EXEC_TARGET_UNKNOWN" in decision.reason_codes


def test_secrets_in_parameters_block_and_do_not_enter_audit():
    decision = decide(request=execution_request(parameters={"token": "must-not-log"}))

    assert decision.decision == DECISION_BLOCKED
    assert "EXEC_REQUEST_PARAMETERS_SECRET_MATERIAL_BLOCKED" in decision.reason_codes
    assert decision.audit_record["secrets_logged"] is False
    assert decision.audit_record["raw_payload_logged"] is False
    assert "must-not-log" not in str(decision.audit_record)


def test_audit_hash_chain_works():
    first = decide()
    second = evaluate_execution_governance(
        request=execution_request(),
        runtime_state=runtime_state(),
        pbsec_state=pbsec_state(),
        previous_audit_hash=first.audit_record["audit_hash"],
        now=NOW,
    )

    assert second.audit_record["previous_audit_hash"] == first.audit_record["audit_hash"]
    assert second.audit_record["audit_hash"]
