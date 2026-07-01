from __future__ import annotations

import pytest

from governance.rollback_governance import evaluate_rollback_governance


pytestmark = pytest.mark.governance


def test_valid_rollback_governance_passes():
    assert evaluate_rollback_governance({"rollback_approval": True, "rollback_status": "AUTHORIZED"})["rollback_status"] == "VALID"


def test_auto_rollback_blocks():
    result = evaluate_rollback_governance({"rollback_approval": True, "rollback_status": "AUTHORIZED", "auto_rollback": True})

    assert result["rollback_status"] == "BLOCKED"
    assert result["reason_codes"] == ["AUTO_ROLLBACK_FORBIDDEN"]
