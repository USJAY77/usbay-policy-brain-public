from __future__ import annotations

import pytest

from governance.aggregate_owner_registry import owner_records_for_capability
from governance.capability_manifest import capability_ids
from governance.dashboard_owner_registry import (
    DASHBOARD_OWNER_REGISTRY,
    dashboard_owner_records_for_capability,
    list_dashboard_owner_records,
)


pytestmark = pytest.mark.governance


def test_dashboard_owner_registry_has_one_owner_for_every_capability():
    records = list_dashboard_owner_records()
    capabilities_with_dashboard_owners = {record["capability_id"] for record in records}

    assert capabilities_with_dashboard_owners == set(capability_ids())
    assert records[0] is not DASHBOARD_OWNER_REGISTRY[0]
    for capability_id in capability_ids():
        assert len(dashboard_owner_records_for_capability(capability_id)) == 1


def test_dashboard_owner_registry_uses_aggregate_owner_module():
    for capability_id in capability_ids():
        dashboard_owner = dashboard_owner_records_for_capability(capability_id)[0]
        aggregate_owner = next(
            record for record in owner_records_for_capability(capability_id) if record["owner_role"] == "aggregate_owner"
        )

        assert dashboard_owner["dashboard_owner_module"] == aggregate_owner["module"]
        assert dashboard_owner["owner_role"] == "aggregate_owner"
        assert dashboard_owner["read_only"] is True
        assert dashboard_owner["execution_enabled"] is False
        assert dashboard_owner["deployment_enabled"] is False
        assert dashboard_owner["runtime_modification_enabled"] is False
