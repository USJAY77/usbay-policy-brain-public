from __future__ import annotations

import pytest

from governance.operator_governance import evaluate_operator_governance


pytestmark = pytest.mark.governance


def test_operator_governance_valid_with_human_approval():
    result = evaluate_operator_governance({"agent_type": "OPERATOR", "human_approval": True})

    assert result["operator_status"] == "VALID"
    assert result["auto_approval"] is False


def test_operator_governance_blocks_missing_and_auto_approval():
    result = evaluate_operator_governance({"agent_type": "OPERATOR", "human_approval": False, "auto_approval": True})

    assert "MISSING_APPROVAL" in result["reason_codes"]
    assert "AUTO_APPROVAL_FORBIDDEN" in result["reason_codes"]
