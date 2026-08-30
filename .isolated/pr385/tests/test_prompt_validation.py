from __future__ import annotations

import pytest

from governance.prompt_contracts import PROMPT_GOVERNANCE_POLICY_VERSION, build_prompt_record, compute_prompt_governance_hash
from governance.prompt_validation import evaluate_prompt_validation


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


def test_valid_prompt_validation_passes():
    assert evaluate_prompt_validation(prompt_record())["prompt_validation_status"] == "VALID"


def test_failed_prompt_validation_blocks():
    result = evaluate_prompt_validation(prompt_record(validation_status="FAILED"))

    assert result["prompt_validation_status"] == "BLOCKED"
    assert result["reason_codes"] == ["PROMPT_VALIDATION_FAILED"]
