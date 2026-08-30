from __future__ import annotations

import pytest

from governance.dashboard_owner_registry import list_dashboard_owner_records
from governance.vision_dashboard_validation import (
    REASON_VISION_DASHBOARD_FIELD_MISSING,
    REASON_VISION_DASHBOARD_OWNER_INVALID,
    REASON_VISION_DASHBOARD_REASON_CODE_INVALID,
    validate_vision_dashboard,
)
from governance.vision_governance import empty_vision_dashboard_state


pytestmark = pytest.mark.governance


def test_vision_dashboard_validation_uses_canonical_fields_and_reason_codes():
    state = empty_vision_dashboard_state()
    report = validate_vision_dashboard(dashboard_state=state)

    assert report["vision_dashboard_status"] == "VALID"
    assert report["dashboard_owner"] == "governance.vision_governance"
    assert report["missing_dashboard_fields"] == []
    assert report["invalid_reason_codes"] == []
    assert "vision_reason_codes" in state
    assert set(state["vision_reason_codes"]) <= {
        "VISION_OBSERVATION_MISSING",
        "VISION_ACTION_BLOCKED",
        "VISION_GOVERNANCE_BYPASS",
    }
    assert state["audit_status"] == "VALID"
    assert state["evidence_status"] == "VALID"
    assert state["lineage_status"] == "VALID"
    assert state["human_approval_status"] == "REQUIRED"


def test_vision_dashboard_validation_fails_closed_on_duplicate_dashboard_owner():
    records = list_dashboard_owner_records()
    vision = next(record for record in records if record["capability_id"] == "vision_agent_control")
    duplicate = dict(vision)
    duplicate["dashboard_owner_module"] = "governance.vision_dashboard_duplicate"
    records.append(duplicate)

    report = validate_vision_dashboard(dashboard_records=records)

    assert report["vision_dashboard_status"] == "BLOCKED"
    assert REASON_VISION_DASHBOARD_OWNER_INVALID in report["reason_codes"]


def test_vision_dashboard_validation_fails_closed_on_field_or_reason_drift():
    state = empty_vision_dashboard_state()
    state.pop("vision_reason_codes")
    state["reason_codes"] = ["VISION_PRIVATE_DEVIATION"]

    report = validate_vision_dashboard(dashboard_state=state)

    assert report["vision_dashboard_status"] == "BLOCKED"
    assert REASON_VISION_DASHBOARD_FIELD_MISSING in report["reason_codes"]

    state = empty_vision_dashboard_state()
    state["vision_reason_codes"] = ["VISION_PRIVATE_DEVIATION"]
    report = validate_vision_dashboard(dashboard_state=state)

    assert report["vision_dashboard_status"] == "BLOCKED"
    assert REASON_VISION_DASHBOARD_REASON_CODE_INVALID in report["reason_codes"]
