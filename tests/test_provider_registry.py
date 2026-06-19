from __future__ import annotations

import pytest

from governance.owner_roles import DEPRECATED_PROVIDER
from governance.provider_registry import DEPRECATED_PROVIDER_MODULES, provider_records, provider_registry_summary


pytestmark = pytest.mark.governance


def test_provider_registry_deprecates_duplicate_ownership_paths():
    summary = provider_registry_summary()
    deprecated_modules = {record["module"] for record in summary["providers"] if record["owner_role"] == DEPRECATED_PROVIDER}

    assert summary["read_only"] is True
    assert summary["execution_enabled"] is False
    assert summary["deployment_enabled"] is False
    assert summary["runtime_modification_enabled"] is False
    assert summary["deprecated_provider_count"] >= sum(len(modules) for modules in DEPRECATED_PROVIDER_MODULES.values())
    assert "governance.release_governance" in deprecated_modules
    assert "governance.billing_governance" in deprecated_modules
    for record in summary["providers"]:
        assert "aggregate_owner" in record
        assert "contract_owner" in record
        assert "provider" in record
        assert "deprecated_provider" in record
        assert record["dashboard_truth_allowed"] is False
        assert record["status_field_owner"] is False
        assert record["reason_code_owner"] is False
        assert record["aggregate_decision_override_allowed"] is False


def test_provider_records_are_copied():
    records = provider_records()

    assert records
    assert isinstance(records[0], dict)
