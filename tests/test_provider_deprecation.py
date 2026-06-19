from __future__ import annotations

import pytest

from governance.aggregate_owner_registry import list_owner_records
from governance.owner_roles import AGGREGATE_OWNER, CONTRACT_OWNER
from governance.provider_deprecation import (
    REASON_AGGREGATE_OWNER_MISSING,
    REASON_CONTRACT_OWNER_MISSING,
    REASON_PROVIDER_DASHBOARD_TRUTH,
    REASON_PROVIDER_DECISION_OVERRIDE,
    REASON_PROVIDER_OWNERSHIP_CLAIM,
    REASON_PROVIDER_REASON_CODE_OWNER,
    REASON_PROVIDER_STATUS_FIELD_OWNER,
    empty_provider_deprecation_dashboard_state,
    migration_readiness_report,
    provider_drift_report,
    validate_provider_deprecation,
)


pytestmark = pytest.mark.governance


def test_provider_deprecation_maps_every_deprecated_provider_to_owners():
    validation = validate_provider_deprecation()

    assert validation["provider_status"] == "VALID"
    assert validation["provider_drift_count"] == 0
    assert validation["deprecated_provider_count"] > 0
    for row in validation["deprecated_provider_inventory"]:
        assert row["aggregate_owner"]
        assert row["contract_owner"]
        assert row["deprecated_provider"]
        assert row["dashboard_truth_allowed"] is False
        assert row["status_field_owner"] is False
        assert row["reason_code_owner"] is False
        assert row["aggregate_decision_override_allowed"] is False
        assert row["provider_status"] == "VALID"


def test_provider_deprecation_fails_closed_if_provider_claims_ownership():
    records = list_owner_records()
    records.append(
        {
            "capability_id": "commercial_governance",
            "module": "governance.billing_governance",
            "owner_role": AGGREGATE_OWNER,
            "source": "test",
        }
    )

    validation = validate_provider_deprecation(records)

    assert validation["provider_status"] == "BLOCKED"
    assert validation["provider_drift_count"] >= 1
    assert REASON_PROVIDER_OWNERSHIP_CLAIM in validation["reason_codes"]


def test_provider_deprecation_fails_closed_if_aggregate_owner_missing():
    records = [
        record
        for record in list_owner_records()
        if not (record["capability_id"] == "commercial_governance" and record["owner_role"] == AGGREGATE_OWNER)
    ]

    validation = validate_provider_deprecation(records)

    assert validation["provider_status"] == "BLOCKED"
    assert REASON_AGGREGATE_OWNER_MISSING in validation["reason_codes"]


def test_provider_deprecation_fails_closed_if_contract_owner_missing():
    records = [
        record
        for record in list_owner_records()
        if not (record["capability_id"] == "commercial_governance" and record["owner_role"] == CONTRACT_OWNER)
    ]

    validation = validate_provider_deprecation(records)

    assert validation["provider_status"] == "BLOCKED"
    assert REASON_CONTRACT_OWNER_MISSING in validation["reason_codes"]


def test_provider_reports_and_dashboard_are_read_only():
    drift = provider_drift_report()
    readiness = migration_readiness_report()
    dashboard = empty_provider_deprecation_dashboard_state()

    assert drift["provider_status"] == "VALID"
    assert readiness["migration_readiness_status"] == "READY"
    assert dashboard["provider_status"] == "VALID"
    assert dashboard["provider_drift_count"] == 0
    assert dashboard["deprecated_provider_count"] > 0
    assert dashboard["read_only"] is True
    assert dashboard["execution_enabled"] is False
    assert dashboard["deployment_enabled"] is False
    assert dashboard["runtime_modification_enabled"] is False


def test_provider_deprecation_fails_closed_if_provider_emits_truth():
    records = list_owner_records()
    records.append(
        {
            "capability_id": "commercial_governance",
            "module": "governance.provider_with_truth",
            "owner_role": "deprecated_provider",
            "source": "test",
            "dashboard_fields": ("commercial_status",),
            "status_fields": ("commercial_status",),
            "reason_codes": ("COMMERCIAL_GOVERNANCE_BYPASS",),
            "overrides_aggregate_owner": True,
        }
    )

    validation = validate_provider_deprecation(records)

    assert validation["provider_status"] == "BLOCKED"
    assert REASON_PROVIDER_DASHBOARD_TRUTH in validation["reason_codes"]
    assert REASON_PROVIDER_STATUS_FIELD_OWNER in validation["reason_codes"]
    assert REASON_PROVIDER_REASON_CODE_OWNER in validation["reason_codes"]
    assert REASON_PROVIDER_DECISION_OVERRIDE in validation["reason_codes"]
