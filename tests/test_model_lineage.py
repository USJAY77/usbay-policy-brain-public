from __future__ import annotations

import pytest

from governance.model_contracts import MODEL_GOVERNANCE_POLICY_VERSION, build_model_record, compute_model_governance_hash
from governance.model_lineage import evaluate_model_lineage


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


def test_valid_model_lineage_passes():
    assert evaluate_model_lineage(model_record())["model_lineage_status"] == "VALID"


def test_missing_model_lineage_blocks():
    result = evaluate_model_lineage(model_record(lineage_hash=""))

    assert result["model_lineage_status"] == "BLOCKED"
    assert result["reason_codes"] == ["MISSING_LINEAGE"]
