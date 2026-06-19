from __future__ import annotations

import pytest

from governance.owner_roles import AGGREGATE_OWNER, CONTRACT_OWNER, DEPRECATED_PROVIDER
from governance.provider_inventory import deprecated_provider_inventory


pytestmark = pytest.mark.governance


def test_deprecated_provider_inventory_is_read_only():
    inventory = deprecated_provider_inventory()

    assert inventory["provider_status"] == "VALID"
    assert inventory["deprecated_provider_count"] > 0
    assert inventory["read_only"] is True
    assert inventory["execution_enabled"] is False
    assert inventory["deployment_enabled"] is False
    assert inventory["runtime_modification_enabled"] is False
    assert all(record["owner_role"] == DEPRECATED_PROVIDER for record in inventory["deprecated_providers"])
    assert all(record["owner_role"] in {AGGREGATE_OWNER, CONTRACT_OWNER} for record in inventory["ownership_claims"])
