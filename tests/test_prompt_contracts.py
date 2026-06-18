from __future__ import annotations

import pytest

from governance.prompt_contracts import (
    PROMPT_GOVERNANCE_POLICY_VERSION,
    PROMPT_GOVERNANCE_SCHEMA,
    PROMPT_REASON_CODES,
    SUPPORTED_PROMPT_CLASSIFICATIONS,
    build_prompt_record,
    compute_prompt_governance_hash,
    validate_prompt_record,
)


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


def test_valid_prompt_record_contract_is_governance_only():
    record = prompt_record()
    validation = validate_prompt_record(record)

    assert record["schema"] == PROMPT_GOVERNANCE_SCHEMA
    assert validation.valid is True
    assert validation.status == "GOVERNED"
    assert validation.reason_codes == ()
    assert "HIGH_RISK" in SUPPORTED_PROMPT_CLASSIFICATIONS
    assert "MODEL_INVOCATION_FORBIDDEN" in PROMPT_REASON_CODES
    assert "prompt_text" not in record


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("prompt_id", "UNKNOWN_PROMPT"),
        ("prompt_hash", "UNKNOWN_PROMPT"),
        ("prompt_owner", "MISSING_PROMPT_OWNER"),
        ("prompt_classification", "MISSING_PROMPT_CLASSIFICATION"),
        ("policy_version", "MISSING_POLICY_BINDING"),
        ("audit_hash", "MISSING_AUDIT_LINKAGE"),
        ("evidence_hash", "MISSING_EVIDENCE_LINKAGE"),
        ("lineage_hash", "MISSING_LINEAGE"),
    ],
)
def test_missing_prompt_contract_fields_block(field, reason):
    validation = validate_prompt_record(prompt_record(**{field: ""}))

    assert validation.valid is False
    assert validation.status == "BLOCKED"
    assert reason in validation.reason_codes


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("registered_prompt", "UNREGISTERED_PROMPT"),
        ("prompt_governed", "PROMPT_NOT_GOVERNED"),
        ("human_approval", "MISSING_APPROVAL"),
        ("policy_binding", "MISSING_POLICY_BINDING"),
    ],
)
def test_false_prompt_governance_requirements_block(field, reason):
    validation = validate_prompt_record(prompt_record(**{field: False}))

    assert validation.valid is False
    assert reason in validation.reason_codes


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("prompt_execution", "PROMPT_GOVERNANCE_BYPASS"),
        ("inference_execution", "PROMPT_GOVERNANCE_BYPASS"),
        ("deployment", "PROMPT_GOVERNANCE_BYPASS"),
        ("governance_bypass", "PROMPT_GOVERNANCE_BYPASS"),
        ("tool_execution", "TOOL_EXECUTION_FORBIDDEN"),
        ("connector_write", "CONNECTOR_WRITE_FORBIDDEN"),
        ("model_invocation", "MODEL_INVOCATION_FORBIDDEN"),
        ("auto_routing", "AUTO_ROUTING_FORBIDDEN"),
        ("auto_remediation", "AUTO_REMEDIATION_FORBIDDEN"),
        ("auto_approval", "AUTO_APPROVAL_FORBIDDEN"),
    ],
)
def test_prompt_forbidden_execution_paths_block(field, reason):
    validation = validate_prompt_record(prompt_record(**{field: True}))

    assert validation.valid is False
    assert reason in validation.reason_codes


def test_prompt_injection_risk_blocks():
    validation = validate_prompt_record(prompt_record(injection_status="RISK"))

    assert validation.valid is False
    assert "PROMPT_INJECTION_RISK" in validation.reason_codes


def test_prompt_hash_mismatch_is_tamper_detected():
    validation = validate_prompt_record(prompt_record(prompt_governance_hash="tampered"))

    assert validation.valid is False
    assert validation.status == "TAMPER_DETECTED"
    assert validation.reason_codes == ("PROMPT_GOVERNANCE_BYPASS",)
