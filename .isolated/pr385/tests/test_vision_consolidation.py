from __future__ import annotations

import pytest

from governance.aggregate_owner_registry import list_owner_records
from governance.owner_roles import AGGREGATE_OWNER
from governance.vision_consolidation import (
    REASON_VISION_OWNER_INVALID,
    VISION_CAPABILITY_ID,
    validate_vision_consolidation,
)


pytestmark = pytest.mark.governance


def test_vision_consolidation_uses_canonical_ownership_and_statuses():
    report = validate_vision_consolidation()

    assert report["vision_consolidation_status"] == "VALID"
    assert report["capability_id"] == VISION_CAPABILITY_ID
    assert report["aggregate_owner"] == "governance.vision_governance"
    assert report["contract_owner"] == "governance.vision_agent_contracts"
    assert report["provider_count"] == 0
    assert report["audit_status"] == "VALID"
    assert report["evidence_status"] == "VALID"
    assert report["lineage_status"] == "VALID"
    assert report["human_approval_status"] == "REQUIRED"
    assert report["reason_namespace"] == "vision"
    assert report["read_only"] is True
    assert report["execution_enabled"] is False
    assert report["deployment_enabled"] is False
    assert report["runtime_modification_enabled"] is False
    assert report["policy_mutation_enabled"] is False
    assert report["connector_write_enabled"] is False
    assert report["auto_remediation_enabled"] is False
    assert report["auto_approval_enabled"] is False


def test_vision_consolidation_fails_closed_on_duplicate_aggregate_owner():
    records = list_owner_records()
    records.append(
        {
            "capability_id": VISION_CAPABILITY_ID,
            "module": "governance.vision_duplicate_owner",
            "owner_role": AGGREGATE_OWNER,
            "source": "test",
        }
    )

    report = validate_vision_consolidation(owner_records=records)

    assert report["vision_consolidation_status"] == "BLOCKED"
    assert REASON_VISION_OWNER_INVALID in report["reason_codes"]
