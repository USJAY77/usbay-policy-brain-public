from __future__ import annotations

import pytest

from governance.dashboard_conflict_report import dashboard_ownership_report
from governance.dashboard_owner_registry import list_dashboard_owner_records
from governance.dashboard_validation import (
    REASON_DASHBOARD_FIELD_CONFLICT,
    REASON_DUPLICATE_DASHBOARD_OWNER,
    REASON_MISSING_DASHBOARD_OWNER,
    REASON_PROVIDER_DASHBOARD_TRUTH,
    validate_dashboard_ownership,
)


pytestmark = pytest.mark.governance


def test_dashboard_ownership_validation_passes_for_canonical_registry():
    validation = validate_dashboard_ownership()

    assert validation["dashboard_ownership_status"] == "VALID"
    assert validation["dashboard_conflict_count"] == 0
    assert validation["missing_dashboard_owner_count"] == 0
    assert validation["reason_codes"] == []
    assert validation["read_only"] is True
    assert validation["execution_enabled"] is False
    assert validation["deployment_enabled"] is False
    assert validation["runtime_modification_enabled"] is False
    assert validation["policy_mutation_enabled"] is False


def test_duplicate_dashboard_owner_detection_fails_closed():
    records = list_dashboard_owner_records()
    duplicate = dict(records[0])
    duplicate["dashboard_owner_module"] = duplicate["dashboard_owner_module"] + ".duplicate"
    records.append(duplicate)

    validation = validate_dashboard_ownership(records=records)

    assert validation["dashboard_ownership_status"] == "BLOCKED"
    assert validation["dashboard_conflict_count"] >= 1
    assert REASON_DUPLICATE_DASHBOARD_OWNER in validation["reason_codes"]


def test_missing_dashboard_owner_detection_fails_closed():
    records = [record for record in list_dashboard_owner_records() if record["capability_id"] != "commercial_governance"]

    validation = validate_dashboard_ownership(records=records)

    assert validation["dashboard_ownership_status"] == "BLOCKED"
    assert validation["missing_dashboard_owner_count"] == 1
    assert REASON_MISSING_DASHBOARD_OWNER in validation["reason_codes"]


def test_provider_dashboard_truth_detection_fails_closed():
    records = list_dashboard_owner_records()
    provider_record = dict(records[0])
    provider_record["capability_id"] = "commercial_governance"
    provider_record["owner_role"] = "provider"
    provider_record["dashboard_owner_module"] = "governance.legacy_provider"
    records = [record for record in records if record["capability_id"] != "commercial_governance"]
    records.append(provider_record)

    validation = validate_dashboard_ownership(records=records)

    assert validation["dashboard_ownership_status"] == "BLOCKED"
    assert REASON_PROVIDER_DASHBOARD_TRUTH in validation["reason_codes"]


def test_conflicting_dashboard_field_detection_fails_closed():
    records = list_dashboard_owner_records()
    records[1]["dashboard_fields"] = tuple(records[0]["dashboard_fields"])

    validation = validate_dashboard_ownership(records=records)

    assert validation["dashboard_ownership_status"] == "BLOCKED"
    assert validation["conflicting_dashboard_fields"] == sorted(records[0]["dashboard_fields"])
    assert REASON_DASHBOARD_FIELD_CONFLICT in validation["reason_codes"]


def test_dashboard_ownership_report_is_read_only():
    report = dashboard_ownership_report()

    assert report["dashboard_ownership_status"] == "VALID"
    assert report["dashboard_conflict_count"] == 0
    assert report["blocked_capabilities"] == []
    assert report["read_only"] is True
    assert report["execution_enabled"] is False
    assert report["deployment_enabled"] is False
    assert report["runtime_modification_enabled"] is False
    assert report["policy_mutation_enabled"] is False
