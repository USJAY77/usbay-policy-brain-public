from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.vision_agent_contracts import (
    ACTION_PROPOSAL_SCHEMA,
    BLOCKED_ACTION_TYPES,
    HUMAN_APPROVAL_SCHEMA,
    OBSERVATION_SCHEMA,
    build_vision_audit_record,
    validate_action_proposal,
    validate_vision_human_approval,
    validate_vision_observation,
)


pytestmark = pytest.mark.governance

NOW = datetime(2026, 6, 17, 1, 0, tzinfo=timezone.utc)


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
        "detected_ui_elements": [{"kind": "button", "label_hash": "b" * 64}],
        "detected_text_summary": "Settings page summary only",
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


def test_valid_sanitized_observation_contract_accepts_hash_only_screenshot():
    result = validate_vision_observation(observation())

    assert result.valid is True
    assert result.reason_codes == ()


def test_unredacted_observation_blocks():
    result = validate_vision_observation(observation(redaction_applied=False))

    assert result.valid is False
    assert "VISION_OBSERVATION_REDACTION_REQUIRED" in result.reason_codes


def test_missing_screenshot_hash_blocks():
    result = validate_vision_observation(observation(screenshot_hash=""))

    assert result.valid is False
    assert "VISION_OBSERVATION_SCREENSHOT_HASH_MISSING" in result.reason_codes


def test_raw_screenshot_payload_is_rejected():
    result = validate_vision_observation(observation(raw_screenshot_payload="base64-payload"))

    assert result.valid is False
    assert "VISION_OBSERVATION_RAW_SCREENSHOT_PAYLOAD_BLOCKED" in result.reason_codes


@pytest.mark.parametrize("action_type", sorted(BLOCKED_ACTION_TYPES))
def test_blocked_action_types_are_rejected(action_type):
    result = validate_action_proposal(proposal(action_type=action_type))

    assert result.valid is False
    assert f"VISION_PROPOSAL_ACTION_BLOCKED:{action_type}" in result.reason_codes


def test_unknown_action_type_blocks():
    result = validate_action_proposal(proposal(action_type="DRIVE_BROWSER"))

    assert result.valid is False
    assert "VISION_PROPOSAL_ACTION_UNKNOWN:DRIVE_BROWSER" in result.reason_codes


def test_codex_ai_approval_is_rejected():
    result = validate_vision_human_approval(approval(approver_role="codex"), proposal=proposal(), now=NOW)

    assert result.valid is False
    assert "VISION_APPROVAL_AI_APPROVER_BLOCKED" in result.reason_codes


def test_valid_human_approval_is_accepted_for_review_only_scope():
    result = validate_vision_human_approval(approval(), proposal=proposal(), now=NOW)

    assert result.valid is True
    assert result.reason_codes == ()


def test_audit_record_hash_chains_and_logs_no_raw_payloads_or_secrets():
    obs = observation(raw_screenshot_payload="must-not-log")
    prop = proposal(parameters={"token": "must-not-log", "visible": "hash-only"})

    first = build_vision_audit_record(
        observation=obs,
        proposal=prop,
        decision="BLOCKED",
        reason_codes=["TEST"],
        policy_version="policy-v1",
        runtime_state_hash="r" * 64,
        pbsec_state_hash="p" * 64,
        previous_audit_hash="",
        generated_at="2026-06-17T00:03:00Z",
    )
    second = build_vision_audit_record(
        observation=obs,
        proposal=prop,
        decision="BLOCKED",
        reason_codes=["TEST"],
        policy_version="policy-v1",
        runtime_state_hash="r" * 64,
        pbsec_state_hash="p" * 64,
        previous_audit_hash=first["audit_hash"],
        generated_at="2026-06-17T00:04:00Z",
    )

    assert first["audit_hash"]
    assert second["previous_audit_hash"] == first["audit_hash"]
    assert second["audit_hash"] != first["audit_hash"]
    assert first["raw_screenshot_logged"] is False
    assert first["secrets_logged"] is False
    assert "must-not-log" not in str(first)
    assert "must-not-log" not in str(second)
