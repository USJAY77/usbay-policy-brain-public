from __future__ import annotations

from datetime import datetime, timezone

import pytest

from execution.adapters.shell_adapter import ShellExecutionAdapter
from governance.execution_contracts import EXECUTION_APPROVAL_SCHEMA
from governance.vision_agent_contracts import ACTION_PROPOSAL_SCHEMA
from governance.vision_execution_bridge import (
    BLOCKED_MAPPINGS,
    DECISION_ALLOWED_PREVIEW,
    DECISION_BLOCKED,
    DECISION_HUMAN_REVIEW_REQUIRED,
    VISION_TO_EXECUTION_CAPABILITY,
    build_audit_lineage,
    evaluate_vision_execution_bridge,
    map_proposal_to_execution_request,
)


pytestmark = pytest.mark.governance

NOW = datetime(2026, 6, 17, 1, 0, tzinfo=timezone.utc)
VISION_AUDIT_HASH = "v" * 64
DEFAULT = object()


def observation(**overrides):
    payload = {
        "observation_id": "obs-1",
        "screenshot_hash": "s" * 64,
        "device_id": "device-1",
    }
    payload.update(overrides)
    return payload


def proposal(**overrides):
    payload = {
        "schema": ACTION_PROPOSAL_SCHEMA,
        "proposal_id": "proposal-1",
        "observation_id": "obs-1",
        "requested_action": "Inspect dashboard",
        "action_type": "READ_ONLY_NAVIGATION",
        "target": "governance-dashboard",
        "parameters": {"view": "governance"},
        "reason": "Preview governed state",
        "confidence": 0.9,
        "requested_by_agent": "vision-agent-1",
        "device_id": "device-1",
        "policy_version": "usbay.pb-vx.vision-execution-bridge.v1",
        "requires_human_approval": False,
        "risk_level": "LOW",
        "created_at": "2026-06-17T00:00:00Z",
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


def approval(request, **overrides):
    payload = {
        "schema": EXECUTION_APPROVAL_SCHEMA,
        "approval_id": "approval-1",
        "proposal_id": request["proposal_id"],
        "request_id": request["request_id"],
        "approved_by_human": True,
        "approver_role": "security-reviewer",
        "approved_scope": "PREVIEW_ONLY",
        "approved_at": "2026-06-17T00:05:00Z",
        "approval_signature_or_hash": "a" * 64,
        "no_ai_auto_approval": True,
    }
    payload.update(overrides)
    return payload


def mapped_request(prop):
    request, reasons = map_proposal_to_execution_request(
        prop,
        observation_id="obs-1",
        vision_audit_hash=VISION_AUDIT_HASH,
        runtime_state_hash="r" * 64,
        pbsec_state_hash="p" * 64,
        created_at="2026-06-17T01:00:00Z",
    )
    assert reasons == ()
    return request


def decide(prop=None, approval_payload=None, runtime=DEFAULT, pbsec=DEFAULT, audit_hash=VISION_AUDIT_HASH):
    return evaluate_vision_execution_bridge(
        observation=observation(),
        proposal=proposal() if prop is None else prop,
        vision_audit_hash=audit_hash,
        runtime_state=runtime_state() if runtime is DEFAULT else runtime,
        pbsec_state=pbsec_state() if pbsec is DEFAULT else pbsec,
        approval=approval_payload,
        now=NOW,
    )


@pytest.mark.parametrize(
    ("action_type", "capability"),
    sorted(VISION_TO_EXECUTION_CAPABILITY.items()),
)
def test_valid_preview_proposal_maps_to_preview_execution_request(action_type, capability):
    request = mapped_request(proposal(action_type=action_type))

    assert request["capability"] == capability
    assert request["proposal_id"] == "proposal-1"
    assert request["risk_level"] == "LOW"
    assert request["policy_version"] == "usbay.pb-vx.vision-execution-bridge.v1"


@pytest.mark.parametrize("action_type", ["UNKNOWN_ACTION", "CLICK", "TYPE", "RUN_COMMAND", "PUSH_CODE", "MERGE_PR", "LOGIN", "SECRET_ACCESS", "PRODUCTION_DEPLOY"])
def test_unknown_and_blocked_proposal_actions_block(action_type):
    result = decide(prop=proposal(action_type=action_type))

    assert result.decision == DECISION_BLOCKED


def test_blocked_mapping_list_contains_required_actions():
    for action_type in ["CLICK", "TYPE", "RUN_COMMAND", "PUSH_CODE", "MERGE_PR", "LOGIN", "SECRET_ACCESS", "PRODUCTION_DEPLOY"]:
        assert action_type in BLOCKED_MAPPINGS


def test_raw_screenshot_not_copied_and_secrets_redacted_from_parameters():
    request = mapped_request(
        proposal(
            parameters={
                "raw_screenshot_payload": "must-not-copy",
                "api_key": "must-not-copy",
                "cookie": "must-not-copy",
                "safe": "value",
            }
        )
    )
    encoded = str(request["parameters"])

    assert "must-not-copy" not in encoded
    assert "raw_screenshot_payload" not in encoded
    assert "api_key" not in encoded
    assert "cookie" not in encoded
    assert request["parameters"]["safe"] == "value"
    assert request["parameters"]["redacted_field_hashes"]


def test_missing_proposal_id_blocks():
    result = decide(prop=proposal(proposal_id=""))

    assert result.decision == DECISION_BLOCKED
    assert "VX_PROPOSAL_ID_MISSING" in result.reason_codes


def test_missing_vision_audit_hash_blocks():
    result = decide(audit_hash="")

    assert result.decision == DECISION_BLOCKED
    assert "VX_VISION_AUDIT_HASH_MISSING" in result.reason_codes


def test_missing_runtime_state_hash_blocks():
    result = decide(runtime=None)

    assert result.decision == DECISION_BLOCKED
    assert "VX_RUNTIME_STATE_HASH_MISSING" in result.reason_codes


def test_missing_pbsec_state_blocks_security_sensitive_action():
    result = decide(prop=proposal(action_type="COPY_TEXT"), pbsec=None)

    assert result.decision == DECISION_BLOCKED
    assert "VX_PBSEC_STATE_HASH_MISSING" in result.reason_codes


def test_missing_human_approval_returns_human_review_required():
    result = decide(prop=proposal(action_type="PREPARE_COMMAND"))

    assert result.decision == DECISION_HUMAN_REVIEW_REQUIRED
    assert "VX_HUMAN_APPROVAL_MISSING" in result.reason_codes


@pytest.mark.parametrize("approver", ["codex", "ai-agent"])
def test_ai_approvals_are_rejected(approver):
    prop = proposal(action_type="PREPARE_GITHUB_COMMENT")
    request = mapped_request(prop)

    result = decide(prop=prop, approval_payload=approval(request, approver_role=approver))

    assert result.decision == DECISION_BLOCKED
    assert "EXEC_APPROVAL_AI_APPROVER_BLOCKED" in result.reason_codes


def test_scope_mismatch_approval_rejected():
    prop = proposal(action_type="PREPARE_PR_DESCRIPTION")
    request = mapped_request(prop)

    result = decide(prop=prop, approval_payload=approval(request, approved_scope="PRODUCTION_EXECUTION"))

    assert result.decision == DECISION_BLOCKED
    assert "EXEC_APPROVAL_SCOPE_MISMATCH" in result.reason_codes


def test_valid_human_approval_permits_preview_only_decision():
    prop = proposal(action_type="PREPARE_GITHUB_COMMENT")
    request = mapped_request(prop)

    result = decide(prop=prop, approval_payload=approval(request))

    assert result.decision == DECISION_ALLOWED_PREVIEW
    assert result.execution_engine_status == "DISABLED"
    assert result.adapter_status == "NOT_IMPLEMENTED"


def test_real_adapter_remains_execution_disabled():
    result = ShellExecutionAdapter().evaluate({"request_id": "exec-request-1"})

    assert result["status"] == "EXECUTION_DISABLED"
    assert result["decision"] == "EXECUTION_BLOCKED"


def test_audit_lineage_hash_is_generated_and_hash_only():
    result = decide()

    assert result.audit_lineage["lineage_hash"]
    assert result.audit_lineage["secrets_logged"] is False
    assert result.audit_lineage["raw_payload_logged"] is False
    assert result.audit_lineage["raw_screenshot_logged"] is False


def test_audit_lineage_fails_closed_when_hash_link_missing():
    lineage = build_audit_lineage(
        observation={},
        proposal=proposal(),
        execution_request=mapped_request(proposal()),
        approval=None,
        execution_decision={"decision": "EXECUTION_BLOCKED"},
        previous_audit_hash="",
        generated_at="2026-06-17T00:00:00Z",
    )

    assert lineage["fail_closed"] is True
    assert "VX_LINEAGE_OBSERVATION_HASH_MISSING" in lineage["reason_codes"]
