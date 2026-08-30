from __future__ import annotations

import pytest

from governance.change_governance import evaluate_change_governance


pytestmark = pytest.mark.governance


def test_valid_change_governance_passes():
    result = evaluate_change_governance({"change_id": "change-1", "registered_change": True, "change_request": True, "change_status": "GOVERNED"})

    assert result["change_status"] == "VALID"
    assert result["reason_codes"] == []


def test_missing_change_request_blocks():
    result = evaluate_change_governance({"change_id": "change-1", "registered_change": False, "change_request": False})

    assert result["change_status"] == "BLOCKED"
    assert result["reason_codes"] == ["MISSING_CHANGE_REQUEST", "UNREGISTERED_CHANGE"]
