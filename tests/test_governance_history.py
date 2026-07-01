from __future__ import annotations

import pytest

from governance.audit_registry_contracts import REGISTRY_RECORD_TYPES, build_registry_record
from governance.governance_history import GovernanceHistory


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


def test_get_record_returns_copy():
    records = chain()
    history = GovernanceHistory(records)

    record = history.get_record("record-0")
    record["record_id"] = "changed"

    assert history.get_record("record-0")["record_id"] == "record-0"


def test_get_children_returns_read_only_copies():
    history = GovernanceHistory(chain())

    children = history.get_children("record-0")

    assert len(children) == 1
    assert children[0]["record_type"] == "Proposal"


def test_get_chain_returns_root_to_record():
    history = GovernanceHistory(chain())

    result = history.get_chain("record-3")

    assert [record["record_type"] for record in result] == ["Observation", "Proposal", "Request", "Approval"]


def test_get_history_summary_read_only():
    history = GovernanceHistory(chain())

    summary = history.get_history_summary()

    assert summary["governance_history_status"] == "AVAILABLE_READ_ONLY"
    assert summary["record_count"] == 10
    assert summary["read_only"] is True
    assert summary["mutation_enabled"] is False
    assert summary["delete_enabled"] is False
    assert summary["repair_enabled"] is False


def test_get_tamper_findings_reports_hash_mismatch():
    records = chain()
    records[-1]["source_component"] = "changed"
    history = GovernanceHistory(records)

    findings = history.get_tamper_findings()

    assert findings
    assert any("HASH_MISMATCH" in finding for finding in findings)


def test_history_has_no_mutation_apis():
    history = GovernanceHistory(chain())

    assert not hasattr(history, "delete")
    assert not hasattr(history, "update")
    assert not hasattr(history, "repair")
    assert not hasattr(history, "auto_fix")
