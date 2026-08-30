from __future__ import annotations

import pytest

from governance.model_contracts import MODEL_GOVERNANCE_POLICY_VERSION, build_model_record, compute_model_governance_hash
from governance.model_registry import ModelRegistry, empty_model_dashboard_state


pytestmark = pytest.mark.governance


def model_record(**overrides):
    payload = build_model_record(
        model_id="model-1",
        model_class="OpenAI",
        tenant_id="tenant-1",
        workspace_id="workspace-1",
        model_owner="platform-governance",
        model_classification="HIGH_RISK_ASSISTANT",
        registered_model=True,
        model_governed=True,
        human_approval=True,
        policy_binding=True,
        audit_hash="a" * 64,
        evidence_hash="e" * 64,
        lineage_hash="l" * 64,
        risk_status="HIGH",
        validation_status="VALIDATED",
        policy_version=MODEL_GOVERNANCE_POLICY_VERSION,
    )
    payload.update(overrides)
    if "model_governance_hash" not in overrides:
        payload["model_governance_hash"] = compute_model_governance_hash(payload)
    return payload


def test_model_registry_lists_records_read_only():
    registry = ModelRegistry([model_record()])

    assert registry.get_model("model-1")["model_class"] == "OpenAI"
    assert registry.list_models()[0]["model_id"] == "model-1"
    assert registry.summary()["model_registry_status"] == "VALID"
    assert registry.summary()["model_invocation_enabled"] is False


def test_empty_model_registry_blocks_unknown_model():
    summary = ModelRegistry().summary()

    assert summary["model_registry_status"] == "BLOCKED"
    assert summary["model_reason_codes"] == ["UNKNOWN_MODEL"]


def test_empty_model_dashboard_state_blocks_execution():
    state = empty_model_dashboard_state()

    assert state["model_status"] == "BLOCKED"
    assert state["model_registry_status"] == "BLOCKED"
    assert state["model_validation_status"] == "BLOCKED"
    assert state["model_risk_status"] == "BLOCKED"
    assert state["model_lineage_status"] == "BLOCKED"
    assert state["model_reason_codes"] == ["UNKNOWN_MODEL"]
    assert state["model_execution_enabled"] is False
    assert state["model_invocation_enabled"] is False
    assert state["prompt_execution_enabled"] is False
    assert state["inference_execution_enabled"] is False
    assert state["auto_selection_enabled"] is False
    assert state["auto_routing_enabled"] is False
    assert state["deployment_enabled"] is False
    assert state["auto_remediation"] is False
    assert state["auto_approval"] is False
