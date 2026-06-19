from __future__ import annotations

import pytest

from governance.aggregate_owner_registry import list_owner_records
from governance.dashboard_owner_registry import list_dashboard_owner_records
from governance.duplicate_detector import detect_governance_duplicates


pytestmark = pytest.mark.governance


def test_duplicate_detector_passes_for_canonical_registries():
    report = detect_governance_duplicates()

    assert report["duplicate_status"] == "VALID"
    assert report["duplicate_owner_count"] == 0
    assert report["duplicate_dashboard_owner_count"] == 0
    assert report["duplicate_reason_code_owner_count"] == 0
    assert report["duplicate_audit_owner_count"] == 0
    assert report["duplicate_evidence_owner_count"] == 0
    assert report["duplicate_lineage_owner_count"] == 0
    assert report["read_only"] is True
    assert report["execution_enabled"] is False
    assert report["deployment_enabled"] is False
    assert report["runtime_modification_enabled"] is False
    assert report["policy_mutation_enabled"] is False


def test_duplicate_detector_fails_closed_for_duplicate_aggregate_owner():
    records = list_owner_records()
    duplicate = dict(next(record for record in records if record["owner_role"] == "aggregate_owner"))
    duplicate["module"] = duplicate["module"] + ".duplicate"
    records.append(duplicate)

    report = detect_governance_duplicates(owner_records=records)

    assert report["duplicate_status"] == "BLOCKED"
    assert report["duplicate_owner_count"] == 1


def test_duplicate_detector_fails_closed_for_duplicate_dashboard_owner():
    records = list_dashboard_owner_records()
    duplicate = dict(records[0])
    duplicate["dashboard_owner_module"] = duplicate["dashboard_owner_module"] + ".duplicate"
    records.append(duplicate)

    report = detect_governance_duplicates(dashboard_records=records)

    assert report["duplicate_status"] == "BLOCKED"
    assert report["duplicate_dashboard_owner_count"] == 1


def test_duplicate_detector_fails_closed_for_duplicate_reason_code_owner():
    report = detect_governance_duplicates(
        reason_namespaces={
            "one": ("DUPLICATE_REASON",),
            "two": ("DUPLICATE_REASON",),
        }
    )

    assert report["duplicate_status"] == "BLOCKED"
    assert report["duplicate_reason_code_owner_count"] == 1
