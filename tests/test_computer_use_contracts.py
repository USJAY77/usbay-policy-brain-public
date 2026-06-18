from __future__ import annotations

import pytest

from governance.computer_use_contracts import REASON_CODES, build_computer_use_record, validate_computer_use_record


pytestmark = pytest.mark.governance


def record(**overrides):
    payload = {
        "agent_id": "agent-1",
        "agent_type": "OPERATOR",
        "action_id": "action-1",
        "action_type": "REVIEW",
        "tenant_id": "tenant-1",
        "workspace_id": "ws-1",
        "registered_agent": True,
        "human_approval": True,
        "policy_binding": True,
        "audit_hash": "a" * 64,
        "evidence_hash": "e" * 64,
        "lineage_hash": "l" * 64,
        "policy_version": "policy-v1",
    }
    payload.update(overrides)
    return build_computer_use_record(**payload)


def test_valid_computer_use_contract():
    result = validate_computer_use_record(record())

    assert result.valid is True
    assert result.status == "GOVERNED"


def test_unknown_agent_action_and_registration_block():
    result = validate_computer_use_record(record(agent_id="", agent_type="UNKNOWN", action_id="", action_type="CLICK", registered_agent=False))

    assert "UNKNOWN_AGENT" in result.reason_codes
    assert "UNKNOWN_ACTION" in result.reason_codes
    assert "UNREGISTERED_AGENT" in result.reason_codes


def test_missing_approval_links_and_policy_block():
    result = validate_computer_use_record(
        record(human_approval=False, audit_hash="", evidence_hash="", lineage_hash="", policy_binding=False)
    )

    assert "MISSING_APPROVAL" in result.reason_codes
    assert "MISSING_AUDIT_LINKAGE" in result.reason_codes
    assert "MISSING_EVIDENCE_LINKAGE" in result.reason_codes
    assert "MISSING_LINEAGE" in result.reason_codes
    assert "MISSING_POLICY_BINDING" in result.reason_codes


def test_forbidden_control_flags_block():
    result = validate_computer_use_record(
        record(
            browser_control=True,
            mouse_control=True,
            keyboard_control=True,
            application_control=True,
            file_modification=True,
            shell_control=True,
            auto_remediation=True,
            auto_approval=True,
            governance_bypass=True,
        )
    )

    for code in (
        "BROWSER_CONTROL_FORBIDDEN",
        "MOUSE_CONTROL_FORBIDDEN",
        "KEYBOARD_CONTROL_FORBIDDEN",
        "APPLICATION_CONTROL_FORBIDDEN",
        "FILE_MODIFICATION_FORBIDDEN",
        "SHELL_CONTROL_FORBIDDEN",
        "AUTO_REMEDIATION_FORBIDDEN",
        "AUTO_APPROVAL_FORBIDDEN",
        "COMPUTER_USE_GOVERNANCE_BYPASS",
    ):
        assert code in result.reason_codes


def test_reason_codes_registry_contains_required_codes():
    assert "UNKNOWN_AGENT" in REASON_CODES
    assert "COMPUTER_USE_GOVERNANCE_BYPASS" in REASON_CODES
