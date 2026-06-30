from __future__ import annotations

import pytest

from governance.audit_registry import build_audit_registry, empty_audit_registry_dashboard_state
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


def test_valid_registry_verifies_complete_chain():
    registry = build_audit_registry(chain())

    assert registry["audit_registry_status"] == "VERIFIED"
    assert registry["audit_registry_record_count"] == 10
    assert registry["audit_registry_tamper_status"] == "NO_TAMPER_DETECTED"
    assert registry["governance_history_status"] == "AVAILABLE_READ_ONLY"
    assert registry["read_only"] is True


def test_empty_registry_fails_closed():
    registry = empty_audit_registry_dashboard_state()

    assert registry["audit_registry_status"] == "BLOCKED"
    assert registry["fail_closed"] is True
    assert registry["mutation_enabled"] is False
    assert registry["delete_enabled"] is False
    assert registry["repair_enabled"] is False


def test_malformed_registry_blocks():
    registry = build_audit_registry(None)

    assert registry["audit_registry_status"] == "BLOCKED"
    assert "AUDIT_REGISTRY_RECORDS_MALFORMED" in registry["audit_registry_reason_codes"]


def test_hash_mismatch_sets_tamper_status():
    records = chain()
    records[-1]["audit_hash"] = "b" * 64

    registry = build_audit_registry(records)

    assert registry["audit_registry_status"] == "TAMPER_DETECTED"
    assert registry["audit_registry_tamper_status"] == "TAMPER_DETECTED"


def test_registry_does_not_enable_automatic_trust_or_repair():
    registry = build_audit_registry(chain())

    assert registry["auto_repaired"] is False
    assert registry["auto_fixed"] is False
    assert registry["auto_trusted"] is False
    assert registry["auto_verified"] is False
    assert registry["auto_merged"] is False
    assert registry["auto_deployed"] is False
