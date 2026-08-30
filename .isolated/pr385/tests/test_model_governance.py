from __future__ import annotations

import pytest

from governance.model_contracts import MODEL_GOVERNANCE_POLICY_VERSION, build_model_record, compute_model_governance_hash
from governance.model_governance import evaluate_model_governance
from governance.model_registry import ModelRegistry


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


def test_valid_model_governance_is_read_only():
    record = model_record()
    result = evaluate_model_governance(
        record=record,
        registry=ModelRegistry([record]),
        requesting_tenant_id="tenant-1",
        requesting_workspace_id="workspace-1",
    )

    assert result["model_status"] == "GOVERNED"
    assert result["model_registry_status"] == "VALID"
    assert result["model_validation_status"] == "VALID"
    assert result["model_risk_status"] == "VALID"
    assert result["model_lineage_status"] == "VALID"
    assert result["model_reason_codes"] == []
    assert result["model_execution_enabled"] is False
    assert result["model_invocation_enabled"] is False
    assert result["prompt_execution_enabled"] is False
    assert result["inference_execution_enabled"] is False
    assert result["auto_selection_enabled"] is False
    assert result["auto_routing_enabled"] is False
    assert result["auto_approval"] is False


def test_missing_model_record_blocks_fail_closed():
    result = evaluate_model_governance(record=None)

    assert result["model_status"] == "BLOCKED"
    assert "UNKNOWN_MODEL" in result["model_reason_codes"]
    assert "MISSING_LINEAGE" in result["model_reason_codes"]


def test_cross_tenant_model_blocks():
    result = evaluate_model_governance(record=model_record(), requesting_tenant_id="tenant-2")

    assert result["model_status"] == "BLOCKED"
    assert "CROSS_TENANT_MODEL" in result["model_reason_codes"]
