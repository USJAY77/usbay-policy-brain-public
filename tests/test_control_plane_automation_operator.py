from __future__ import annotations

import json

import pytest

from control_plane.automation_operator import (
    AUTOMATION_OPERATOR_VERSION,
    ApprovalEvidence,
    AutomationAgent,
    AutomationRequest,
    automation_operator_contract,
    evaluate_automation_request,
    evaluate_dry_run_plan,
)


pytestmark = pytest.mark.governance


def _request(**overrides: object) -> AutomationRequest:
    values = {
        "action_id": "action-1",
        "actor": "codex",
        "agent": AutomationAgent.GOVERNANCE.value,
        "connector": "GitHub",
        "requested_action": "github.observe_pr",
        "policy_version": AUTOMATION_OPERATOR_VERSION,
    }
    values.update(overrides)
    return AutomationRequest(**values)


def _approval(gate: str = "GITHUB_MUTATION_APPROVAL") -> ApprovalEvidence:
    return ApprovalEvidence(
        approval_gate=gate,
        approver="human-reviewer",
        approved=True,
        approval_id="approval-1",
    )


def test_contract_declares_connectors_approval_gates_and_required_evidence() -> None:
    contract = automation_operator_contract()

    assert contract["status"] == "PB-352_GOVERNED_AUTOMATION_OPERATOR_DRY_RUN"
    assert "GitHub" in contract["connectors"]
    assert "Notion" in contract["connectors"]
    assert "LinkedIn" in contract["connectors"]
    assert "Email" in contract["connectors"]
    assert "Tasks" in contract["connectors"]
    assert "TERMINAL_EXECUTION_APPROVAL" in contract["approval_gates"]
    assert "GITHUB_MUTATION_APPROVAL" in contract["approval_gates"]
    assert contract["live_external_mutation_allowed"] is False
    assert set(contract["required_evidence_fields"]) >= {
        "action_id",
        "actor",
        "connector",
        "requested_action",
        "policy_decision",
        "approval_state",
        "timestamp",
        "evidence_hash",
        "outcome",
        "blocked_reason",
    }


def test_safe_dry_run_action_is_prepared_with_audit_evidence() -> None:
    result = evaluate_automation_request(_request())
    evidence = result["audit_evidence"]

    assert result["decision"] == "APPROVED_DRY_RUN"
    assert result["status"] == "DRY_RUN_READY"
    assert evidence["action_id"] == "action-1"
    assert evidence["actor"] == "codex"
    assert evidence["connector"] == "GitHub"
    assert evidence["requested_action"] == "github.observe_pr"
    assert evidence["policy_decision"] == "ALLOW"
    assert evidence["approval_state"] == "NOT_REQUIRED"
    assert len(evidence["evidence_hash"]) == 64
    assert evidence["external_mutation_performed"] is False


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("agent", "Unknown Agent", "unknown_agent"),
        ("connector", "Unknown", "unknown_connector"),
        ("policy_version", None, "missing_policy"),
        ("connector_error", "api_down", "connector_api_failure"),
    ],
)
def test_missing_or_unknown_governance_inputs_block(field: str, value: object, reason: str) -> None:
    result = evaluate_automation_request(_request(**{field: value}))

    assert result["decision"] == "BLOCKED"
    assert reason in result["blocked_reason"]
    assert result["audit_evidence"]["outcome"] == "BLOCKED"
    assert result["audit_evidence"]["external_mutation_performed"] is False


def test_github_mutation_blocks_without_approval() -> None:
    result = evaluate_automation_request(_request(requested_action="github.create_pr"))

    assert result["decision"] == "BLOCKED"
    assert result["approval_gate"] == "GITHUB_MUTATION_APPROVAL"
    assert "missing_approval" in result["blocked_reason"]


def test_github_mutation_remains_dry_run_only_even_with_approval_when_live_requested() -> None:
    result = evaluate_automation_request(
        _request(requested_action="github.create_pr", dry_run=False),
        _approval(),
    )

    assert result["decision"] == "BLOCKED"
    assert "live_external_mutation_disabled" in result["blocked_reason"]
    assert result["audit_evidence"]["approval_state"] == "APPROVED"
    assert result["audit_evidence"]["external_mutation_performed"] is False


def test_unsafe_terminal_command_blocks_without_approval() -> None:
    result = evaluate_automation_request(
        _request(
            connector="Terminal",
            requested_action="terminal.execute",
            command="rm -rf /tmp/example",
        )
    )

    assert result["decision"] == "BLOCKED"
    assert "unsafe_terminal_command" in result["blocked_reason"]
    assert "missing_approval" in result["blocked_reason"]


def test_terminal_execution_with_approval_is_still_dry_run_only() -> None:
    result = evaluate_automation_request(
        _request(
            connector="Terminal",
            requested_action="terminal.execute",
            command="echo validate",
        ),
        ApprovalEvidence(
            approval_gate="TERMINAL_EXECUTION_APPROVAL",
            approver="human-reviewer",
            approved=True,
            approval_id="approval-terminal",
        ),
    )

    assert result["decision"] == "APPROVED_DRY_RUN"
    assert result["audit_evidence"]["approval_state"] == "APPROVED"
    assert result["audit_evidence"]["external_mutation_performed"] is False


def test_missing_audit_hash_blocks() -> None:
    result = evaluate_automation_request(_request(simulate_evidence_failure=True))

    assert result["decision"] == "BLOCKED"
    assert "missing_audit_hash" in result["blocked_reason"]
    assert result["audit_evidence"]["evidence_hash"] == ""


def test_sensitive_payload_blocks_and_is_not_logged() -> None:
    result = evaluate_automation_request(_request(payload={"token": "raw-token"}))
    encoded = json.dumps(result)

    assert result["decision"] == "BLOCKED"
    assert "sensitive_payload_forbidden" in result["blocked_reason"]
    assert "raw-token" not in encoded


def test_self_approval_blocks() -> None:
    result = evaluate_automation_request(
        _request(requested_action="email.send", connector="Email"),
        ApprovalEvidence(
            approval_gate="EMAIL_SEND_APPROVAL",
            approver="codex",
            approved=True,
            approval_id="approval-email",
        ),
    )

    assert result["decision"] == "BLOCKED"
    assert "self_approval_blocked" in result["blocked_reason"]


def test_default_dry_run_plan_verifies_without_external_mutation() -> None:
    plan = evaluate_dry_run_plan()

    assert plan["decision"] == "VERIFIED"
    assert plan["status"] == "DRY_RUN_READY"
    assert plan["external_mutation_performed"] is False
    assert len(plan["actions"]) == 8
    assert all(action["audit_evidence"]["evidence_hash"] for action in plan["actions"])
    assert all(action["audit_evidence"]["external_mutation_performed"] is False for action in plan["actions"])

