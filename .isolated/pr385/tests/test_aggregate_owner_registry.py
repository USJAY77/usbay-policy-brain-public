from __future__ import annotations

import pytest

from governance.aggregate_owner_registry import (
    AGGREGATE_OWNER_REGISTRY,
    OWNER_ROLES,
    empty_owner_validation_dashboard_state,
    list_owner_records,
    owner_records_for_capability,
)
from governance.capability_manifest import capability_ids


pytestmark = pytest.mark.governance


def test_owner_registry_has_records_for_every_manifest_capability():
    owner_records = list_owner_records()
    capabilities_with_owners = {record["capability_id"] for record in owner_records}

    assert set(capability_ids()) <= capabilities_with_owners
    assert owner_records[0] is not AGGREGATE_OWNER_REGISTRY[0]
    assert {"aggregate_owner", "contract_owner", "provider", "deprecated_provider"} == set(OWNER_ROLES)


def test_owner_registry_assigns_exactly_one_aggregate_owner_per_capability():
    for capability_id in capability_ids():
        records = owner_records_for_capability(capability_id)
        aggregate_owners = [record for record in records if record["owner_role"] == "aggregate_owner"]
        contract_owners = [record for record in records if record["owner_role"] == "contract_owner"]

        assert len(aggregate_owners) == 1
        assert len(contract_owners) >= 1


def test_owner_validation_dashboard_state_is_read_only():
    state = empty_owner_validation_dashboard_state()

    assert state["owner_validation_status"] == "VALID"
    assert state["owner_conflict_count"] == 0
    assert state["read_only"] is True
    assert state["execution_enabled"] is False
    assert state["deployment_enabled"] is False
    assert state["runtime_modification_enabled"] is False
    assert state["policy_mutation_enabled"] is False
