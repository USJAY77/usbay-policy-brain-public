from __future__ import annotations

import pytest

from governance.prompt_contracts import PROMPT_GOVERNANCE_POLICY_VERSION, build_prompt_record, compute_prompt_governance_hash
from governance.prompt_governance import evaluate_prompt_governance
from governance.prompt_registry import PromptRegistry


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


def test_valid_prompt_governance_is_read_only():
    record = prompt_record()
    result = evaluate_prompt_governance(
        record=record,
        registry=PromptRegistry([record]),
        requesting_tenant_id="tenant-1",
        requesting_workspace_id="workspace-1",
    )

    assert result["prompt_status"] == "GOVERNED"
    assert result["prompt_registry_status"] == "VALID"
    assert result["prompt_validation_status"] == "VALID"
    assert result["prompt_injection_status"] == "VALID"
    assert result["prompt_policy_binding_status"] == "VALID"
    assert result["prompt_lineage_status"] == "VALID"
    assert result["prompt_reason_codes"] == []
    assert result["prompt_execution_enabled"] is False
    assert result["model_invocation_enabled"] is False
    assert result["inference_execution_enabled"] is False
    assert result["tool_execution_enabled"] is False
    assert result["connector_write_enabled"] is False
    assert result["auto_routing_enabled"] is False
    assert result["auto_approval"] is False


def test_missing_prompt_record_blocks_fail_closed():
    result = evaluate_prompt_governance(record=None)

    assert result["prompt_status"] == "BLOCKED"
    assert "UNKNOWN_PROMPT" in result["prompt_reason_codes"]
    assert "MISSING_LINEAGE" in result["prompt_reason_codes"]


def test_cross_tenant_prompt_blocks():
    result = evaluate_prompt_governance(record=prompt_record(), requesting_tenant_id="tenant-2")

    assert result["prompt_status"] == "BLOCKED"
    assert "CROSS_TENANT_PROMPT" in result["prompt_reason_codes"]
