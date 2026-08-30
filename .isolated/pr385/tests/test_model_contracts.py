from __future__ import annotations

import pytest

from governance.model_contracts import (
    MODEL_GOVERNANCE_POLICY_VERSION,
    MODEL_GOVERNANCE_SCHEMA,
    SUPPORTED_MODEL_CLASSES,
    build_model_record,
    compute_model_governance_hash,
    validate_model_record,
)


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


def test_valid_model_record_contract():
    record = model_record()
    validation = validate_model_record(record)

    assert record["schema"] == MODEL_GOVERNANCE_SCHEMA
    assert validation.valid is True
    assert validation.status == "GOVERNED"
    assert validation.reason_codes == ()
    assert {"OpenAI", "Claude", "Gemini", "Llama", "DeepSeek", "UI-TARS", "Hydra Nodes", "Custom Models"} == set(SUPPORTED_MODEL_CLASSES)


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("model_id", "UNKNOWN_MODEL"),
        ("model_class", "UNKNOWN_MODEL"),
        ("model_owner", "MISSING_MODEL_OWNER"),
        ("model_classification", "MISSING_MODEL_CLASSIFICATION"),
        ("policy_version", "MISSING_POLICY_BINDING"),
        ("audit_hash", "MISSING_AUDIT_LINKAGE"),
        ("evidence_hash", "MISSING_EVIDENCE_LINKAGE"),
        ("lineage_hash", "MISSING_LINEAGE"),
    ],
)
def test_missing_model_contract_fields_block(field, reason):
    validation = validate_model_record(model_record(**{field: ""}))

    assert validation.valid is False
    assert validation.status == "BLOCKED"
    assert reason in validation.reason_codes


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("registered_model", "UNREGISTERED_MODEL"),
        ("model_governed", "MODEL_NOT_GOVERNED"),
        ("human_approval", "MISSING_APPROVAL"),
        ("policy_binding", "MISSING_POLICY_BINDING"),
    ],
)
def test_false_model_governance_requirements_block(field, reason):
    validation = validate_model_record(model_record(**{field: False}))

    assert validation.valid is False
    assert reason in validation.reason_codes


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("model_execution", "MODEL_GOVERNANCE_BYPASS"),
        ("model_invocation", "MODEL_GOVERNANCE_BYPASS"),
        ("prompt_execution", "MODEL_GOVERNANCE_BYPASS"),
        ("inference_execution", "MODEL_GOVERNANCE_BYPASS"),
        ("auto_selection", "MODEL_GOVERNANCE_BYPASS"),
        ("auto_routing", "MODEL_GOVERNANCE_BYPASS"),
        ("deployment", "MODEL_GOVERNANCE_BYPASS"),
        ("auto_remediation", "AUTO_REMEDIATION_FORBIDDEN"),
        ("auto_approval", "AUTO_APPROVAL_FORBIDDEN"),
    ],
)
def test_model_forbidden_execution_paths_block(field, reason):
    validation = validate_model_record(model_record(**{field: True}))

    assert validation.valid is False
    assert reason in validation.reason_codes


def test_model_hash_mismatch_is_tamper_detected():
    validation = validate_model_record(model_record(model_governance_hash="tampered"))

    assert validation.valid is False
    assert validation.status == "TAMPER_DETECTED"
    assert validation.reason_codes == ("MODEL_GOVERNANCE_BYPASS",)
