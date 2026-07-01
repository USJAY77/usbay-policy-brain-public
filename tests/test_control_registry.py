from __future__ import annotations

import pytest

from governance.control_registry import CONTROL_REGISTRY, control_ids, list_controls, validate_control_registry


pytestmark = pytest.mark.governance


def test_control_registry_is_unique_and_read_only():
    validation = validate_control_registry()

    assert validation["status"] == "VALID"
    assert validation["duplicate_control_ids"] == []
    assert validation["read_only"] is True
    assert len(control_ids()) == len(set(control_ids()))
    assert list_controls()[0] is not CONTROL_REGISTRY[0]


def test_control_registry_contains_required_governance_controls():
    ids = set(control_ids())

    assert {"audit_linkage", "evidence_linkage", "lineage_validation", "human_approval", "tenant_isolation", "workspace_isolation"} <= ids
    assert {"fail_closed", "read_only_dashboard", "deployment_forbidden", "auto_approval_forbidden"} <= ids
