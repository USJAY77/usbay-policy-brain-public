from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.vision_agent_contracts import ACTION_PROPOSAL_SCHEMA, HUMAN_APPROVAL_SCHEMA, OBSERVATION_SCHEMA
from governance.vision_governance import (
    DECISION_ALLOWED_PREVIEW,
    DECISION_BLOCKED,
    DECISION_HUMAN_REVIEW_REQUIRED,
    EXECUTION_ADAPTER_STATUS,
    evaluate_vision_governance,
)


pytestmark = pytest.mark.governance

NOW = datetime(2026, 6, 17, 1, 0, tzinfo=timezone.utc)
DEFAULT = object()


def observation(**overrides):
    payload = {
        "schema": OBSERVATION_SCHEMA,
        "observation_id": "obs-1",
        "generated_at": "2026-06-17T00:00:00Z",
        "device_id": "device-1",
        "source": "sanitized_vision_provider",
        "screenshot_hash": "a" * 64,
        "redaction_applied": True,
        "raw_screenshot_logged": False,
        "detected_ui_elements": [],
        "detected_text_summary": "Summary only",
        "confidence": 0.91,
        "errors": [],
    }
    payload.update(overrides)
    return payload


def proposal(**overrides):
    payload = {
        "schema": ACTION_PROPOSAL_SCHEMA,
        "proposal_id": "proposal-1",
        "observation_id": "obs-1",
        "requested_action": "Open read-only settings view",
        "action_type": "READ_ONLY_NAVIGATION",
        "target": "settings",
        "parameters": {"path": "/settings"},
        "reason": "Inspect visible governance state",
        "confidence": 0.88,
        "requested_by_agent": "vision-agent-1",
        "device_id": "device-1",
        "policy_version": "usbay.pb-vision.governed-agent-control.v1",
        "requires_human_approval": False,
        "risk_level": "LOW",
        "created_at": "2026-06-17T00:01:00Z",
    }
    payload.update(overrides)
    return payload


def approval(**overrides):
    payload = {
        "schema": HUMAN_APPROVAL_SCHEMA,
        "approval_id": "approval-1",
        "proposal_id": "proposal-1",
        "approver_role": "security-reviewer",
        "approved_by_human": True,
        "approved_at": "2026-06-17T00:02:00Z",
        "approved_scope": "REVIEW_ONLY",
        "approval_signature_or_hash": "c" * 64,
        "no_ai_auto_approval": True,
    }
    payload.update(overrides)
    return payload


def runtime_state(**overrides):
    payload = {
        "schema_version": "usbay.runtime_governance_state.v1",
        "status": "READY",
        "fail_closed": False,
        "evidence_hash": "r" * 64,
        "reason_codes": ["PB020_EVIDENCE_VERIFIED"],
    }
    payload.update(overrides)
    return payload


def pbsec_state(**overrides):
    payload = {
        "status": "APPROVED",
        "production_release_approved": True,
        "blockers": [],
    }
    payload.update(overrides)
    return payload


def decide(obs=DEFAULT, prop=DEFAULT, runtime=DEFAULT, pbsec=DEFAULT, approval_payload=None):
    return evaluate_vision_governance(
        observation=observation() if obs is DEFAULT else obs,
        proposal=proposal() if prop is DEFAULT else prop,
        runtime_state=runtime_state() if runtime is DEFAULT else runtime,
        pbsec_state=pbsec_state() if pbsec is DEFAULT else pbsec,
        approval=approval_payload,
        now=NOW,
    )


def test_missing_observation_blocks():
    decision = decide(obs=None)

    assert decision.decision == DECISION_BLOCKED
    assert "VISION_OBSERVATION_MISSING" in decision.reason_codes


def test_low_confidence_requires_human_review():
    decision = decide(obs=observation(confidence=0.69))

    assert decision.decision == DECISION_HUMAN_REVIEW_REQUIRED
    assert "VISION_LOW_CONFIDENCE_REQUIRES_HUMAN_REVIEW" in decision.reason_codes


@pytest.mark.parametrize("action_type", ["CLICK", "TYPE", "RUN_COMMAND", "PUSH_CODE", "MERGE_PR"])
def test_execution_like_actions_block(action_type):
    decision = decide(prop=proposal(action_type=action_type))

    assert decision.decision == DECISION_BLOCKED
    assert f"VISION_EXECUTION_ACTION_BLOCKED:{action_type}" in decision.reason_codes


def test_unknown_action_type_blocks():
    decision = decide(prop=proposal(action_type="UNKNOWN_CONTROL"))

    assert decision.decision == DECISION_BLOCKED
    assert "VISION_UNKNOWN_ACTION_BLOCKED:UNKNOWN_CONTROL" in decision.reason_codes


def test_read_only_navigation_allowed_preview_only_when_runtime_valid():
    allowed = decide()
    blocked = decide(runtime=runtime_state(status="BLOCKED", fail_closed=True, evidence_hash=""))

    assert allowed.decision == DECISION_ALLOWED_PREVIEW
    assert "VISION_ALLOWED_PREVIEW_ONLY" in allowed.reason_codes
    assert blocked.decision == DECISION_BLOCKED
    assert "VISION_RUNTIME_GOVERNANCE_STATE_INVALID" in blocked.reason_codes


def test_production_like_action_requires_human_approval():
    prod_proposal = proposal(
        action_type="PREPARE_PR_DESCRIPTION",
        target="production-release",
        reason="Prepare release PR description",
        risk_level="HIGH",
    )

    decision = decide(prop=prod_proposal)

    assert decision.decision == DECISION_HUMAN_REVIEW_REQUIRED
    assert "VISION_HUMAN_APPROVAL_REQUIRED" in decision.reason_codes


def test_production_like_action_blocks_when_pbsec_missing_or_stale():
    prod_proposal = proposal(
        action_type="PREPARE_PR_DESCRIPTION",
        target="production-release",
        reason="Prepare release PR description",
        risk_level="HIGH",
    )

    decision = decide(prop=prod_proposal, pbsec={})

    assert decision.decision == DECISION_BLOCKED
    assert "VISION_PBSEC_STATE_INVALID_FOR_PRODUCTION" in decision.reason_codes


def test_valid_review_only_human_approval_allows_preview_for_production_like_proposal():
    prod_proposal = proposal(
        action_type="READ_ONLY_NAVIGATION",
        target="production-readiness-dashboard",
        reason="Review production dashboard only",
        risk_level="HIGH",
        requires_human_approval=True,
    )

    decision = decide(prop=prod_proposal, approval_payload=approval())

    assert decision.decision == DECISION_ALLOWED_PREVIEW
    assert decision.execution_adapter_status == EXECUTION_ADAPTER_STATUS


def test_audit_record_contains_hash_chain_and_redacted_flags():
    first = decide()
    second = evaluate_vision_governance(
        observation=observation(),
        proposal=proposal(),
        runtime_state=runtime_state(),
        pbsec_state=pbsec_state(),
        previous_audit_hash=first.audit_record["audit_hash"],
        now=NOW,
    )

    assert second.audit_record["previous_audit_hash"] == first.audit_record["audit_hash"]
    assert second.audit_record["audit_hash"]
    assert second.audit_record["raw_screenshot_logged"] is False
    assert second.audit_record["secrets_logged"] is False
    assert second.execution_adapter_status == EXECUTION_ADAPTER_STATUS
