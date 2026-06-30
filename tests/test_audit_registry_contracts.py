from __future__ import annotations

import pytest

from governance.audit_registry_contracts import (
    AUDIT_REGISTRY_POLICY_VERSION,
    REGISTRY_RECORD_TYPES,
    build_registry_record,
    validate_registry_record,
)


pytestmark = pytest.mark.governance


def record(**overrides):
    payload = {
        "record_id": "obs-1",
        "record_type": "Observation",
        "created_at": "2026-06-18T08:00:00Z",
        "audit_hash": "a" * 64,
        "lineage_hash": "l" * 64,
        "source_component": "runtime observation",
        "policy_version": AUDIT_REGISTRY_POLICY_VERSION,
    }
    payload.update(overrides)
    return build_registry_record(**payload)


def test_valid_registry_record():
    validation = validate_registry_record(record())

    assert validation.valid is True
    assert validation.status == "VERIFIED"


@pytest.mark.parametrize("record_type", REGISTRY_RECORD_TYPES)
def test_supported_registry_record_types(record_type):
    parent_id = "" if record_type == "Observation" else "parent-1"
    previous_hash = "" if record_type == "Observation" else "p" * 64
    payload = build_registry_record(
        record_id=f"{record_type}-1",
        record_type=record_type,
        parent_id=parent_id,
        previous_hash=previous_hash,
        created_at="2026-06-18T08:00:00Z",
        audit_hash="a" * 64,
        lineage_hash="l" * 64,
        source_component="runtime observation",
    )
    validation = validate_registry_record(payload)

    assert validation.status == "VERIFIED"
    assert f"AUDIT_REGISTRY_RECORD_TYPE_UNKNOWN:{record_type}" not in validation.reason_codes


@pytest.mark.parametrize("field", ["audit_hash", "lineage_hash", "policy_version", "created_at"])
def test_missing_trust_fields_block(field):
    validation = validate_registry_record(record(**{field: ""}))

    assert validation.valid is False
    assert validation.status == "BLOCKED"


def test_unknown_record_type_blocks():
    validation = validate_registry_record(record(record_type="Auto Repair", parent_id="parent-1", previous_hash="p" * 64))

    assert validation.valid is False
    assert "AUDIT_REGISTRY_RECORD_TYPE_UNKNOWN:Auto Repair" in validation.reason_codes


def test_missing_parent_blocks_non_root_record():
    validation = validate_registry_record(record(record_type="Proposal", parent_id="", previous_hash="p" * 64))

    assert validation.valid is False
    assert "AUDIT_REGISTRY_PARENT_MISSING" in validation.reason_codes


def test_hash_mismatch_reports_tamper_detected():
    tampered = record()
    tampered["source_component"] = "changed"

    validation = validate_registry_record(tampered)

    assert validation.valid is False
    assert validation.status == "TAMPER_DETECTED"
    assert "AUDIT_REGISTRY_HASH_MISMATCH" in validation.reason_codes


def test_sensitive_registry_record_blocks():
    validation = validate_registry_record(record(source_component="contains api_key"))

    assert validation.valid is False
    assert "AUDIT_REGISTRY_SENSITIVE_PAYLOAD_BLOCKED" in validation.reason_codes
