from __future__ import annotations

import pytest

from governance.commercial_contracts import (
    COMMERCIAL_GOVERNANCE_POLICY_VERSION,
    COMMERCIAL_GOVERNANCE_SCHEMA,
    COMMERCIAL_REASON_CODES,
    build_commercial_record,
    compute_commercial_governance_hash,
    validate_commercial_record,
)


pytestmark = pytest.mark.governance


def commercial_record(**overrides):
    payload = build_commercial_record(
        commercial_id="commercial-1",
        tenant_id="tenant-1",
        workspace_id="workspace-1",
        registered_commercial_record=True,
        customer_commercial_record=True,
        contract_record=True,
        subscription_record=True,
        billing_record=True,
        invoice_record=True,
        pricing_record=True,
        renewal_record=True,
        human_approval=True,
        policy_binding=True,
        audit_hash="a" * 64,
        evidence_hash="e" * 64,
        lineage_hash="l" * 64,
        customer_commercial_status="AUTHORIZED",
        contract_status="AUTHORIZED",
        subscription_status="AUTHORIZED",
        billing_status="AUTHORIZED",
        invoice_status="AUTHORIZED",
        pricing_status="AUTHORIZED",
        renewal_status="AUTHORIZED",
        policy_version=COMMERCIAL_GOVERNANCE_POLICY_VERSION,
    )
    payload.update(overrides)
    if "commercial_governance_hash" not in overrides:
        payload["commercial_governance_hash"] = compute_commercial_governance_hash(payload)
    return payload


def test_valid_commercial_record_contract_is_governance_only():
    record = commercial_record()
    validation = validate_commercial_record(record)

    assert record["schema"] == COMMERCIAL_GOVERNANCE_SCHEMA
    assert validation.valid is True
    assert validation.status == "GOVERNED"
    assert validation.reason_codes == ()
    assert "PAYMENT_PROCESSING_FORBIDDEN" in COMMERCIAL_REASON_CODES
    assert "payment_payload" not in record


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("commercial_id", "UNKNOWN_COMMERCIAL_RECORD"),
        ("audit_hash", "MISSING_AUDIT_LINKAGE"),
        ("evidence_hash", "MISSING_EVIDENCE_LINKAGE"),
        ("lineage_hash", "MISSING_LINEAGE"),
        ("policy_version", "MISSING_POLICY_BINDING"),
    ],
)
def test_missing_commercial_fields_block(field, reason):
    validation = validate_commercial_record(commercial_record(**{field: ""}))

    assert validation.valid is False
    assert validation.status == "BLOCKED"
    assert reason in validation.reason_codes


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("registered_commercial_record", "UNREGISTERED_COMMERCIAL_RECORD"),
        ("customer_commercial_record", "MISSING_CUSTOMER_COMMERCIAL_RECORD"),
        ("contract_record", "MISSING_CONTRACT_RECORD"),
        ("subscription_record", "MISSING_SUBSCRIPTION_RECORD"),
        ("billing_record", "MISSING_BILLING_RECORD"),
        ("invoice_record", "MISSING_INVOICE_RECORD"),
        ("pricing_record", "MISSING_PRICING_RECORD"),
        ("renewal_record", "MISSING_RENEWAL_RECORD"),
        ("human_approval", "MISSING_HUMAN_APPROVAL"),
        ("policy_binding", "MISSING_POLICY_BINDING"),
    ],
)
def test_false_commercial_requirements_block(field, reason):
    validation = validate_commercial_record(commercial_record(**{field: False}))

    assert validation.valid is False
    assert reason in validation.reason_codes


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("billing_execution", "BILLING_EXECUTION_FORBIDDEN"),
        ("payment_processing", "PAYMENT_PROCESSING_FORBIDDEN"),
        ("invoice_sending", "INVOICE_SENDING_FORBIDDEN"),
        ("contract_signing", "CONTRACT_SIGNING_FORBIDDEN"),
        ("customer_activation", "CUSTOMER_ACTIVATION_FORBIDDEN"),
        ("subscription_activation", "SUBSCRIPTION_ACTIVATION_FORBIDDEN"),
        ("renewal_execution", "RENEWAL_EXECUTION_FORBIDDEN"),
        ("pricing_modification", "PRICING_MODIFICATION_FORBIDDEN"),
        ("email_sending", "EMAIL_SENDING_FORBIDDEN"),
        ("connector_write", "CONNECTOR_WRITE_FORBIDDEN"),
        ("deployment", "COMMERCIAL_GOVERNANCE_BYPASS"),
        ("auto_remediation", "AUTO_REMEDIATION_FORBIDDEN"),
        ("auto_approval", "AUTO_APPROVAL_FORBIDDEN"),
    ],
)
def test_forbidden_commercial_paths_block(field, reason):
    validation = validate_commercial_record(commercial_record(**{field: True}))

    assert validation.valid is False
    assert reason in validation.reason_codes


def test_commercial_hash_mismatch_is_tamper_detected():
    validation = validate_commercial_record(commercial_record(commercial_governance_hash="tampered"))

    assert validation.valid is False
    assert validation.status == "TAMPER_DETECTED"
    assert validation.reason_codes == ("COMMERCIAL_GOVERNANCE_BYPASS",)
