from __future__ import annotations

import pytest

from control_plane.agent_registry import (
    AGENT_REGISTRY_VERSION,
    AgentHealth,
    AgentRegistry,
    ApprovalState,
    AuditState,
    agent_registry_contract,
    default_agent_registry,
)


pytestmark = pytest.mark.governance


def test_agent_registry_contract_declares_supported_agents_and_capabilities() -> None:
    contract = agent_registry_contract()

    assert contract["registry_version"] == AGENT_REGISTRY_VERSION
    assert contract["supported_agents"] == [
        "Codex Agent",
        "Runtime Agent",
        "Hydra Agent",
        "Governance Agent",
        usbay/pb-353a-euria-registry-extension
        "EURIA",
    ]
    assert contract["agent_capabilities"]["EURIA"] == ["project_dispatch"]

    ]
      main
    assert contract["capabilities"] == [
        "register",
        "enable",
        "disable",
        "health",
        "approval_state",
        "audit_state",
     usbay/pb-353a-euria-registry-extension
        "project_dispatch",

         main
    ]
    assert contract["connector_execution_allowed"] is False
    assert contract["github_execution_allowed"] is False
    assert contract["notion_execution_allowed"] is False
    assert contract["linkedin_execution_allowed"] is False
    assert contract["email_execution_allowed"] is False


def test_register_supported_agent_creates_disabled_fail_closed_record() -> None:
    registry = AgentRegistry(actor="codex")

    result = registry.register("Codex Agent")

    assert result["decision"] == "ALLOW"
    assert result["agent"]["enabled"] is False
    assert result["agent"]["health"] == "UNKNOWN"
    assert result["agent"]["approval_state"] == "UNKNOWN"
    assert result["agent"]["audit_state"] == "UNKNOWN"
    assert len(result["audit_evidence"]["evidence_hash"]) == 64


def test_unknown_agent_registration_blocks_with_audit_evidence() -> None:
    registry = AgentRegistry(actor="codex")

    result = registry.register("Unknown Agent")

    assert result["decision"] == "BLOCKED"
    assert result["reason_codes"] == ["unknown_agent"]
    assert result["agent"] is None
    assert result["audit_evidence"]["outcome"] == "BLOCKED"
    assert len(result["audit_evidence"]["evidence_hash"]) == 64


def test_disabled_agent_fails_closed_even_when_health_approval_and_audit_ready() -> None:
    registry = AgentRegistry(actor="codex")
    registry.register("Runtime Agent")
    registry.set_health("Runtime Agent", AgentHealth.HEALTHY)
    registry.set_approval_state("Runtime Agent", ApprovalState.APPROVED)
    registry.set_audit_state("Runtime Agent", AuditState.EVIDENCE_READY)

    decision = registry.decision_for("Runtime Agent")

    assert decision["decision"] == "BLOCKED"
    assert "agent_disabled" in decision["reason_codes"]


def test_agent_allows_only_when_enabled_healthy_approved_and_audited() -> None:
    registry = AgentRegistry(actor="codex")
    registry.register("Hydra Agent")
    registry.enable("Hydra Agent")
    registry.set_health("Hydra Agent", "HEALTHY")
    registry.set_approval_state("Hydra Agent", "APPROVED")
    registry.set_audit_state("Hydra Agent", "EVIDENCE_READY")

    decision = registry.decision_for("Hydra Agent")

    assert decision["decision"] == "ALLOW"
    assert decision["reason_codes"] == []
    assert decision["agent"]["enabled"] is True
    assert decision["audit_evidence"]["outcome"] == "ALLOW"


def test_unhealthy_or_missing_approval_or_audit_state_blocks() -> None:
    registry = AgentRegistry(actor="codex")
    registry.register("Governance Agent")
    registry.enable("Governance Agent")
    registry.set_health("Governance Agent", "DEGRADED")
    registry.set_approval_state("Governance Agent", "REQUIRED")
    registry.set_audit_state("Governance Agent", "EVIDENCE_MISSING")

    decision = registry.decision_for("Governance Agent")

    assert decision["decision"] == "BLOCKED"
    assert decision["reason_codes"] == [
        "agent_approval_not_ready",
        "agent_audit_not_ready",
        "agent_unhealthy",
    ]


def test_disable_blocks_agent_after_previous_allow_state() -> None:
    registry = AgentRegistry(actor="codex")
    registry.register("Codex Agent")
    registry.enable("Codex Agent")
    registry.set_health("Codex Agent", "HEALTHY")
    registry.set_approval_state("Codex Agent", "NOT_REQUIRED")
    registry.set_audit_state("Codex Agent", "EVIDENCE_READY")

    assert registry.decision_for("Codex Agent")["decision"] == "ALLOW"
    registry.disable("Codex Agent")

    blocked = registry.decision_for("Codex Agent")
    assert blocked["decision"] == "BLOCKED"
    assert blocked["reason_codes"] == ["agent_disabled"]


def test_all_state_changes_emit_audit_evidence() -> None:
    registry = AgentRegistry(actor="codex")
    registry.register("Codex Agent")
    registry.enable("Codex Agent")
    registry.set_health("Codex Agent", "HEALTHY")
    registry.set_approval_state("Codex Agent", "NOT_REQUIRED")
    registry.set_audit_state("Codex Agent", "EVIDENCE_READY")
    registry.disable("Codex Agent")

    assert len(registry.audit_events) == 6
    assert all(event["schema"] == "usbay.control_plane.agent_registry_evidence.v1" for event in registry.audit_events)
    assert all(len(event["evidence_hash"]) == 64 for event in registry.audit_events)


def test_default_registry_registers_all_supported_agents_disabled() -> None:
    registry = default_agent_registry(actor="codex")

       usbay/pb-353a-euria-registry-extension
    assert len(registry.audit_events) == 5
    for agent in ("Codex Agent", "Runtime Agent", "Hydra Agent", "Governance Agent", "EURIA"):

    assert len(registry.audit_events) == 4
    for agent in ("Codex Agent", "Runtime Agent", "Hydra Agent", "Governance Agent"):
        main
        record = registry.get(agent)
        assert record is not None
        assert record.enabled is False


def test_decision_for_unknown_agent_blocks_with_evidence() -> None:
    registry = AgentRegistry(actor="codex")

    decision = registry.decision_for("Unknown Agent")

    assert decision["decision"] == "BLOCKED"
    assert decision["reason_codes"] == ["unknown_agent"]
    assert len(decision["audit_evidence"]["evidence_hash"]) == 64
        usbay/pb-353a-euria-registry-extension


def test_register_euria_agent() -> None:
    registry = AgentRegistry(actor="codex")

    result = registry.register("EURIA")

    assert result["decision"] == "ALLOW"
    assert result["agent"]["name"] == "EURIA"
    assert result["agent"]["enabled"] is False
    assert len(result["audit_evidence"]["evidence_hash"]) == 64


def test_euria_capability_mapping() -> None:
    contract = agent_registry_contract()

    assert contract["agent_capabilities"]["EURIA"] == ["project_dispatch"]
    assert "project_dispatch" in contract["capabilities"]


def test_unknown_euria_agent_blocked() -> None:
    registry = AgentRegistry(actor="codex")

    dispatch = registry.project_dispatch("EURIA Agent", project_id="project-123", capabilities=("project_dispatch",))

    assert dispatch["decision"] == "BLOCKED"
    assert dispatch["reason_codes"] == ["unknown_agent"]
    assert len(dispatch["audit_evidence"]["evidence_hash"]) == 64


def test_disabled_euria_agent_blocked() -> None:
    registry = AgentRegistry(actor="codex")
    registry.register("EURIA")
    registry.set_health("EURIA", "HEALTHY")
    registry.set_approval_state("EURIA", "APPROVED")
    registry.set_audit_state("EURIA", "EVIDENCE_READY")

    dispatch = registry.project_dispatch("EURIA", project_id="project-123", capabilities=("project_dispatch",))

    assert dispatch["decision"] == "BLOCKED"
    assert dispatch["reason_codes"] == ["agent_disabled"]


def test_unhealthy_euria_agent_blocked() -> None:
    registry = AgentRegistry(actor="codex")
    registry.register("EURIA")
    registry.enable("EURIA")
    registry.set_health("EURIA", "UNHEALTHY")
    registry.set_approval_state("EURIA", "APPROVED")
    registry.set_audit_state("EURIA", "EVIDENCE_READY")

    dispatch = registry.project_dispatch("EURIA", project_id="project-123", capabilities=("project_dispatch",))

    assert dispatch["decision"] == "BLOCKED"
    assert dispatch["reason_codes"] == ["agent_unhealthy"]


def test_unapproved_euria_agent_blocked() -> None:
    registry = AgentRegistry(actor="codex")
    registry.register("EURIA")
    registry.enable("EURIA")
    registry.set_health("EURIA", "HEALTHY")
    registry.set_approval_state("EURIA", "REQUIRED")
    registry.set_audit_state("EURIA", "EVIDENCE_READY")

    dispatch = registry.project_dispatch("EURIA", project_id="project-123", capabilities=("project_dispatch",))

    assert dispatch["decision"] == "BLOCKED"
    assert dispatch["reason_codes"] == ["agent_approval_not_ready"]


def test_audit_not_ready_euria_agent_blocked() -> None:
    registry = AgentRegistry(actor="codex")
    registry.register("EURIA")
    registry.enable("EURIA")
    registry.set_health("EURIA", "HEALTHY")
    registry.set_approval_state("EURIA", "APPROVED")
    registry.set_audit_state("EURIA", "EVIDENCE_MISSING")

    dispatch = registry.project_dispatch("EURIA", project_id="project-123", capabilities=("project_dispatch",))

    assert dispatch["decision"] == "BLOCKED"
    assert dispatch["reason_codes"] == ["agent_audit_not_ready"]


def test_euria_missing_capability_blocked() -> None:
    registry = AgentRegistry(actor="codex")
    registry.register("EURIA")
    registry.enable("EURIA")
    registry.set_health("EURIA", "HEALTHY")
    registry.set_approval_state("EURIA", "APPROVED")
    registry.set_audit_state("EURIA", "EVIDENCE_READY")

    dispatch = registry.project_dispatch("EURIA", project_id="project-123")

    assert dispatch["decision"] == "BLOCKED"
    assert dispatch["reason_codes"] == ["missing_euria_capability"]


def test_euria_unsupported_action_blocked() -> None:
    registry = AgentRegistry(actor="codex")
    registry.register("EURIA")
    registry.enable("EURIA")
    registry.set_health("EURIA", "HEALTHY")
    registry.set_approval_state("EURIA", "APPROVED")
    registry.set_audit_state("EURIA", "EVIDENCE_READY")

    decision = registry.decision_for(
        "EURIA",
        requested_action="unsupported_action",
        capabilities=("unsupported_action",),
    )

    assert decision["decision"] == "BLOCKED"
    assert decision["reason_codes"] == ["unsupported_euria_action"]


def test_euria_agent_allowed_when_all_controls_pass() -> None:
    registry = AgentRegistry(actor="codex")
    registry.register("EURIA")
    registry.enable("EURIA")
    registry.set_health("EURIA", "HEALTHY")
    registry.set_approval_state("EURIA", "APPROVED")
    registry.set_audit_state("EURIA", "EVIDENCE_READY")

    dispatch = registry.project_dispatch("EURIA", project_id="project-123", capabilities=("project_dispatch",))

    assert dispatch["decision"] == "ALLOW"
    assert dispatch["reason_codes"] == []
    assert dispatch["audit_evidence"]["action"] == "project_dispatch"
    assert len(dispatch["audit_evidence"]["evidence_hash"]) == 64
    assert len(dispatch["project_dispatch"]["project_id_hash"]) == 64
    assert dispatch["project_dispatch"]["connector_execution_performed"] is False
    assert dispatch["project_dispatch"]["external_mutation_performed"] is False


def test_existing_agents_still_register_and_decide_without_capability_scope() -> None:
    for agent_name in ("Codex Agent", "Runtime Agent", "Hydra Agent", "Governance Agent"):
        registry = AgentRegistry(actor="codex")
        registry.register(agent_name)
        registry.enable(agent_name)
        registry.set_health(agent_name, "HEALTHY")
        registry.set_approval_state(agent_name, "APPROVED")
        registry.set_audit_state(agent_name, "EVIDENCE_READY")

        decision = registry.decision_for(agent_name)

        assert decision["decision"] == "ALLOW"
        assert decision["reason_codes"] == []


def test_project_dispatch_unknown_agent_blocks_with_evidence() -> None:
    registry = AgentRegistry(actor="codex")

    dispatch = registry.project_dispatch("Unknown Agent", project_id="project-123")

    assert dispatch["decision"] == "BLOCKED"
    assert dispatch["reason_codes"] == ["unknown_agent"]
    assert len(dispatch["audit_evidence"]["evidence_hash"]) == 64

        main
