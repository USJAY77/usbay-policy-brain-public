from __future__ import annotations

import pytest

from governance.aggregate_owner_registry import list_owner_records
from governance.capability_manifest import capability_ids
from governance.owner_validation import (
    REASON_DUPLICATE_AGGREGATE_OWNER,
    REASON_MISSING_AGGREGATE_OWNER,
    REASON_MISSING_CONTRACT_OWNER,
    validate_owner_registry,
)


pytestmark = pytest.mark.governance


def test_owner_validation_passes_for_manifest_derived_registry():
    validation = validate_owner_registry()

    assert validation["owner_validation_status"] == "VALID"
    assert validation["owner_conflict_count"] == 0
    assert validation["missing_aggregate_owner_count"] == 0
    assert validation["missing_contract_owner_count"] == 0
    assert validation["capability_count"] == len(capability_ids())
    assert validation["read_only"] is True
    assert validation["execution_enabled"] is False
    assert validation["deployment_enabled"] is False
    assert validation["runtime_modification_enabled"] is False
    assert validation["policy_mutation_enabled"] is False


def test_duplicate_aggregate_owner_detection_fails_closed():
    records = list_owner_records()
    first_aggregate = next(record for record in records if record["owner_role"] == "aggregate_owner")
    duplicate = dict(first_aggregate)
    duplicate["module"] = duplicate["module"] + ".duplicate"
    records.append(duplicate)

    validation = validate_owner_registry(records=records)

    assert validation["owner_validation_status"] == "BLOCKED"
    assert validation["owner_conflict_count"] == 1
    assert REASON_DUPLICATE_AGGREGATE_OWNER in validation["reason_codes"]


def test_missing_aggregate_owner_detection_fails_closed():
    records = [
        record
        for record in list_owner_records()
        if not (record["capability_id"] == "commercial_governance" and record["owner_role"] == "aggregate_owner")
    ]

    validation = validate_owner_registry(records=records)

    assert validation["owner_validation_status"] == "BLOCKED"
    assert validation["missing_aggregate_owner_count"] == 1
    assert REASON_MISSING_AGGREGATE_OWNER in validation["reason_codes"]


def test_missing_contract_owner_detection_fails_closed():
    records = [
        record
        for record in list_owner_records()
        if not (record["capability_id"] == "commercial_governance" and record["owner_role"] == "contract_owner")
    ]

    validation = validate_owner_registry(records=records)

    assert validation["owner_validation_status"] == "BLOCKED"
    assert validation["missing_contract_owner_count"] == 1
    assert REASON_MISSING_CONTRACT_OWNER in validation["reason_codes"]


def test_provider_and_deprecated_provider_are_supported_without_conflict():
    records = list_owner_records()
    records.append(
        {
            "capability_id": "commercial_governance",
            "module": "governance.legacy_commercial_provider",
            "owner_role": "deprecated_provider",
            "source": "test",
        }
    )

    validation = validate_owner_registry(records=records)
    commercial = next(row for row in validation["capability_results"] if row["capability_id"] == "commercial_governance")

    assert validation["owner_validation_status"] == "VALID"
    assert commercial["deprecated_provider_count"] == 1
