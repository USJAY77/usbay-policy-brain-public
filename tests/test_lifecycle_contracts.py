from __future__ import annotations

import pytest

from governance.lifecycle_contracts import (
    LIFECYCLE_GOVERNANCE_POLICY_VERSION,
    LIFECYCLE_GOVERNANCE_SCHEMA,
    LIFECYCLE_REASON_CODES,
    build_lifecycle_record,
    compute_lifecycle_governance_hash,
    validate_lifecycle_record,
)


pytestmark = pytest.mark.governance


def lifecycle_record(**overrides):
    payload = build_lifecycle_record(
        change_id="change-1",
        tenant_id="tenant-1",
        workspace_id="workspace-1",
        change_request=True,
        registered_change=True,
        release_approval=True,
        runtime_approval=True,
        rollback_approval=True,
        incident_record=True,
        maintenance_record=True,
        policy_binding=True,
        audit_hash="a" * 64,
        evidence_hash="e" * 64,
        lineage_hash="l" * 64,
        change_status="GOVERNED",
        release_status="AUTHORIZED",
        promotion_status="AUTHORIZED",
        runtime_status="AUTHORIZED",
        rollback_status="AUTHORIZED",
        incident_status="AUTHORIZED",
        maintenance_status="GOVERNED",
        policy_version=LIFECYCLE_GOVERNANCE_POLICY_VERSION,
    )
    payload.update(overrides)
    if "lifecycle_governance_hash" not in overrides:
        payload["lifecycle_governance_hash"] = compute_lifecycle_governance_hash(payload)
    return payload


def test_valid_lifecycle_record_contract_is_governance_only():
    record = lifecycle_record()
    validation = validate_lifecycle_record(record)

    assert record["schema"] == LIFECYCLE_GOVERNANCE_SCHEMA
    assert validation.valid is True
    assert validation.status == "GOVERNED"
    assert validation.reason_codes == ()
    assert "AUTO_ROLLBACK_FORBIDDEN" in LIFECYCLE_REASON_CODES
    assert "deployment_payload" not in record


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("change_id", "UNKNOWN_CHANGE"),
        ("audit_hash", "MISSING_AUDIT_LINKAGE"),
        ("evidence_hash", "MISSING_EVIDENCE_LINKAGE"),
        ("lineage_hash", "MISSING_LINEAGE"),
        ("policy_version", "MISSING_POLICY_BINDING"),
    ],
)
def test_missing_lifecycle_fields_block(field, reason):
    validation = validate_lifecycle_record(lifecycle_record(**{field: ""}))

    assert validation.valid is False
    assert validation.status == "BLOCKED"
    assert reason in validation.reason_codes


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("registered_change", "UNREGISTERED_CHANGE"),
        ("change_request", "MISSING_CHANGE_REQUEST"),
        ("release_approval", "MISSING_RELEASE_APPROVAL"),
        ("runtime_approval", "MISSING_RUNTIME_APPROVAL"),
        ("rollback_approval", "MISSING_ROLLBACK_APPROVAL"),
        ("incident_record", "MISSING_INCIDENT_RECORD"),
        ("maintenance_record", "MISSING_MAINTENANCE_RECORD"),
        ("policy_binding", "MISSING_POLICY_BINDING"),
    ],
)
def test_false_lifecycle_requirements_block(field, reason):
    validation = validate_lifecycle_record(lifecycle_record(**{field: False}))

    assert validation.valid is False
    assert reason in validation.reason_codes


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("execution", "LIFECYCLE_GOVERNANCE_BYPASS"),
        ("deployment", "LIFECYCLE_GOVERNANCE_BYPASS"),
        ("runtime_modification", "LIFECYCLE_GOVERNANCE_BYPASS"),
        ("policy_modification", "LIFECYCLE_GOVERNANCE_BYPASS"),
        ("connector_write", "LIFECYCLE_GOVERNANCE_BYPASS"),
        ("auto_release", "AUTO_RELEASE_FORBIDDEN"),
        ("auto_promotion", "AUTO_PROMOTION_FORBIDDEN"),
        ("auto_remediation", "AUTO_REMEDIATION_FORBIDDEN"),
        ("auto_rollback", "AUTO_ROLLBACK_FORBIDDEN"),
        ("auto_approval", "AUTO_APPROVAL_FORBIDDEN"),
    ],
)
def test_forbidden_lifecycle_paths_block(field, reason):
    validation = validate_lifecycle_record(lifecycle_record(**{field: True}))

    assert validation.valid is False
    assert reason in validation.reason_codes


def test_lifecycle_hash_mismatch_is_tamper_detected():
    validation = validate_lifecycle_record(lifecycle_record(lifecycle_governance_hash="tampered"))

    assert validation.valid is False
    assert validation.status == "TAMPER_DETECTED"
    assert validation.reason_codes == ("LIFECYCLE_GOVERNANCE_BYPASS",)
