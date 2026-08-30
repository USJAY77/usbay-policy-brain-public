from __future__ import annotations

import pytest

from governance.prompt_contracts import PROMPT_GOVERNANCE_POLICY_VERSION, build_prompt_record, compute_prompt_governance_hash
from governance.prompt_registry import PromptRegistry, empty_prompt_dashboard_state


pytestmark = pytest.mark.governance


def prompt_record(**overrides):
    payload = build_prompt_record(
        prompt_id="prompt-1",
        prompt_hash="p" * 64,
        tenant_id="tenant-1",
        workspace_id="workspace-1",
        prompt_owner="platform-governance",
        prompt_classification="HIGH_RISK",
        registered_prompt=True,
        prompt_governed=True,
        human_approval=True,
        policy_binding=True,
        audit_hash="a" * 64,
        evidence_hash="e" * 64,
        lineage_hash="l" * 64,
        validation_status="VALIDATED",
        injection_status="CLEAN",
        policy_version=PROMPT_GOVERNANCE_POLICY_VERSION,
    )
    payload.update(overrides)
    if "prompt_governance_hash" not in overrides:
        payload["prompt_governance_hash"] = compute_prompt_governance_hash(payload)
    return payload


def test_prompt_registry_lists_records_read_only():
    registry = PromptRegistry([prompt_record()])

    assert registry.get_prompt("prompt-1")["prompt_classification"] == "HIGH_RISK"
    assert registry.list_prompts()[0]["prompt_id"] == "prompt-1"
    assert registry.summary()["prompt_registry_status"] == "VALID"
    assert registry.summary()["prompt_execution_enabled"] is False
    assert registry.summary()["connector_write_enabled"] is False


def test_empty_prompt_registry_blocks_unknown_prompt():
    summary = PromptRegistry().summary()

    assert summary["prompt_registry_status"] == "BLOCKED"
    assert summary["prompt_reason_codes"] == ["UNKNOWN_PROMPT"]


def test_empty_prompt_dashboard_state_blocks_execution():
    state = empty_prompt_dashboard_state()

    assert state["prompt_status"] == "BLOCKED"
    assert state["prompt_registry_status"] == "BLOCKED"
    assert state["prompt_validation_status"] == "BLOCKED"
    assert state["prompt_injection_status"] == "BLOCKED"
    assert state["prompt_policy_binding_status"] == "BLOCKED"
    assert state["prompt_lineage_status"] == "BLOCKED"
    assert state["prompt_reason_codes"] == ["UNKNOWN_PROMPT"]
    assert state["prompt_execution_enabled"] is False
    assert state["model_invocation_enabled"] is False
    assert state["inference_execution_enabled"] is False
    assert state["tool_execution_enabled"] is False
    assert state["connector_write_enabled"] is False
    assert state["auto_routing_enabled"] is False
    assert state["deployment_enabled"] is False
    assert state["auto_remediation"] is False
    assert state["auto_approval"] is False
