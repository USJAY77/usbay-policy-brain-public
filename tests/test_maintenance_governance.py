from __future__ import annotations

import pytest

from governance.maintenance_governance import evaluate_maintenance_governance


pytestmark = pytest.mark.governance


def test_valid_maintenance_governance_passes():
    assert evaluate_maintenance_governance({"maintenance_record": True, "maintenance_status": "GOVERNED"})["maintenance_status"] == "VALID"


def test_missing_maintenance_record_blocks():
    result = evaluate_maintenance_governance({"maintenance_record": False, "maintenance_status": ""})

    assert result["maintenance_status"] == "BLOCKED"
    assert result["reason_codes"] == ["MISSING_MAINTENANCE_RECORD"]
