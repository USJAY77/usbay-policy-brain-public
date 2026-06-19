from __future__ import annotations

import pytest

from governance.vision_readiness import vision_readiness_report


pytestmark = pytest.mark.governance


def test_vision_readiness_report_is_ready_for_canonical_state():
    report = vision_readiness_report()

    assert report["vision_readiness_status"] == "READY"
    assert report["vision_readiness_score"] == 100
    assert report["vision_blockers"] == []
    assert report["vision_drift_count"] == 0
    assert report["duplicate_owners"] == 0
    assert report["duplicate_dashboard_owners"] == 0
    assert report["duplicate_reason_code_owners"] == 0
    assert report["runtime_parity_status"] == "VALID"
    assert report["read_only"] is True
    assert report["execution_enabled"] is False
    assert report["deployment_enabled"] is False
    assert report["runtime_modification_enabled"] is False
    assert report["policy_mutation_enabled"] is False
    assert report["connector_write_enabled"] is False
    assert report["auto_remediation_enabled"] is False
    assert report["auto_approval_enabled"] is False


def test_vision_readiness_blocks_on_runtime_drift():
    report = vision_readiness_report(
        runtime_truth={
            "capability_id": "vision_agent_control",
            "runtime_status": "VALID",
            "dashboard_owner": "governance.other_owner",
            "dashboard_fields": ["latest_observation_status"],
        }
    )

    assert report["vision_readiness_status"] == "BLOCKED"
    assert report["vision_readiness_score"] < 100
    assert report["vision_drift_count"] >= 1
    assert "vision_runtime_parity" in report["vision_blockers"]
