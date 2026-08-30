from __future__ import annotations

import pytest

from governance.governance_inventory import governance_capability_inventory, governance_coverage_matrix, validate_governance_inventory


pytestmark = pytest.mark.governance


def test_governance_inventory_is_read_only_and_complete():
    inventory = governance_capability_inventory()
    validation = validate_governance_inventory()

    assert inventory["read_only"] is True
    assert inventory["execution_enabled"] is False
    assert inventory["deployment_enabled"] is False
    assert inventory["runtime_modification_enabled"] is False
    assert validation["status"] == "VALID"
    assert validation["gap_count"] == 0


def test_governance_coverage_matrix_is_generated_from_registry_data():
    matrix = governance_coverage_matrix()
    by_id = {row["capability_id"]: row for row in matrix}

    assert by_id["commercial_governance"]["coverage_status"] == "COVERED"
    assert by_id["commercial_governance"]["human_approval_required"] is True
    assert by_id["lifecycle_governance"]["tenant_required"] is True
    assert by_id["prompt_governance"]["lineage_required"] is True
    assert by_id["model_governance"]["evidence_required"] is True
