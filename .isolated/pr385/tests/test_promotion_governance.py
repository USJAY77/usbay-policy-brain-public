from __future__ import annotations

import pytest

from governance.promotion_governance import evaluate_promotion_governance


pytestmark = pytest.mark.governance


def test_valid_promotion_governance_passes():
    assert evaluate_promotion_governance({"promotion_status": "AUTHORIZED"})["promotion_status"] == "VALID"


def test_auto_promotion_blocks():
    result = evaluate_promotion_governance({"promotion_status": "AUTHORIZED", "auto_promotion": True})

    assert result["promotion_status"] == "BLOCKED"
    assert result["reason_codes"] == ["AUTO_PROMOTION_FORBIDDEN"]
