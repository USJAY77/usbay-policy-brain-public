from __future__ import annotations

import pytest

from governance.audit_lineage_validator import validate_audit_lineage
from governance.audit_registry_contracts import REGISTRY_RECORD_TYPES, build_registry_record


pytestmark = pytest.mark.governance


def chain():
    records = []
    parent_id = ""
    previous_hash = ""
    for index, record_type in enumerate(REGISTRY_RECORD_TYPES):
        record = build_registry_record(
            record_id=f"record-{index}",
            record_type=record_type,
            parent_id=parent_id,
            previous_hash=previous_hash,
            created_at=f"2026-06-18T08:{index:02d}:00Z",
            audit_hash="a" * 64,
            lineage_hash="l" * 64,
            source_component="governance registry",
        )
        records.append(record)
        parent_id = record["record_id"]
        previous_hash = record["current_hash"]
    return records


def test_valid_lineage_verifies():
    result = validate_audit_lineage(chain())

    assert result["lineage_status"] == "VERIFIED"
    assert result["tamper_status"] == "NO_TAMPER_DETECTED"
    assert result["fail_closed"] is False


def test_missing_parent_blocks():
    records = chain()
    parent_id = "missing"
    previous_hash = "p" * 64
    for index in range(2, len(REGISTRY_RECORD_TYPES)):
        records[index] = build_registry_record(
            record_id=f"record-{index}",
            record_type=REGISTRY_RECORD_TYPES[index],
            parent_id=parent_id,
            previous_hash=previous_hash,
            created_at=f"2026-06-18T08:{index:02d}:00Z",
            audit_hash="a" * 64,
            lineage_hash="l" * 64,
            source_component="governance registry",
        )
        parent_id = records[index]["record_id"]
        previous_hash = records[index]["current_hash"]

    result = validate_audit_lineage(records)

    assert result["lineage_status"] == "BLOCKED"
    assert "AUDIT_LINEAGE_PARENT_MISSING:record-2" in result["reason_codes"]


def test_missing_hash_blocks():
    records = chain()
    parent_id = records[0]["record_id"]
    previous_hash = ""
    for index in range(1, len(REGISTRY_RECORD_TYPES)):
        records[index] = build_registry_record(
            record_id=f"record-{index}",
            record_type=REGISTRY_RECORD_TYPES[index],
            parent_id=parent_id,
            previous_hash=previous_hash,
            created_at=f"2026-06-18T08:{index:02d}:00Z",
            audit_hash="a" * 64,
            lineage_hash="l" * 64,
            source_component="governance registry",
        )
        parent_id = records[index]["record_id"]
        previous_hash = records[index]["current_hash"]

    result = validate_audit_lineage(records)

    assert result["lineage_status"] == "BLOCKED"
    assert "AUDIT_LINEAGE_PREVIOUS_HASH_MISSING:record-1" in result["reason_codes"]


def test_timestamp_inversion_blocks():
    records = chain()
    parent_id = records[2]["record_id"]
    previous_hash = records[2]["current_hash"]
    for index in range(3, len(REGISTRY_RECORD_TYPES)):
        created_at = "2026-06-18T07:00:00Z" if index == 3 else f"2026-06-18T08:{index:02d}:00Z"
        records[index] = build_registry_record(
            record_id=f"record-{index}",
            record_type=REGISTRY_RECORD_TYPES[index],
            parent_id=parent_id,
            previous_hash=previous_hash,
            created_at=created_at,
            audit_hash="a" * 64,
            lineage_hash="l" * 64,
            source_component="governance registry",
        )
        parent_id = records[index]["record_id"]
        previous_hash = records[index]["current_hash"]

    result = validate_audit_lineage(records)

    assert result["lineage_status"] == "BLOCKED"
    assert "AUDIT_LINEAGE_TIMESTAMP_INVERSION:record-3" in result["reason_codes"]


def test_hash_mismatch_detects_tamper():
    records = chain()
    records[4]["source_component"] = "changed"

    result = validate_audit_lineage(records)

    assert result["lineage_status"] == "TAMPER_DETECTED"
    assert result["tamper_status"] == "TAMPER_DETECTED"
