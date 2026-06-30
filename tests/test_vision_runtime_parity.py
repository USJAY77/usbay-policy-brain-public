from __future__ import annotations

import pytest

from governance.runtime_parity_validator import validate_runtime_parity
from governance.vision_runtime_parity import (
    REASON_VISION_RUNTIME_TRUTH_DIVERGED,
    validate_vision_runtime_parity,
)


pytestmark = pytest.mark.governance


def test_vision_runtime_parity_passes_for_canonical_truth():
    report = validate_vision_runtime_parity()

    assert report["vision_runtime_parity_status"] == "VALID"
    assert report["manifest_truth"] == "VALID"
    assert report["dashboard_truth"] == "VALID"
    assert report["runtime_truth"] == "VALID"
    assert report["read_only"] is True
    assert report["execution_enabled"] is False
    assert report["deployment_enabled"] is False
    assert report["runtime_modification_enabled"] is False
    assert report["policy_mutation_enabled"] is False
    assert report["connector_write_enabled"] is False
    assert report["auto_remediation_enabled"] is False
    assert report["auto_approval_enabled"] is False


def test_vision_runtime_parity_fails_closed_on_runtime_drift():
    report = validate_vision_runtime_parity(
        runtime_truth={
            "capability_id": "vision_agent_control",
            "runtime_status": "VALID",
            "dashboard_owner": "governance.other_owner",
            "dashboard_fields": ["latest_observation_status"],
        }
    )

    assert report["vision_runtime_parity_status"] == "BLOCKED"
    assert REASON_VISION_RUNTIME_TRUTH_DIVERGED in report["reason_codes"]


def test_generic_runtime_parity_includes_vision_subcheck():
    report = validate_runtime_parity()

    assert report["runtime_parity_status"] == "VALID"
    assert report["checks"]["vision_runtime_parity"] == "VALID"
