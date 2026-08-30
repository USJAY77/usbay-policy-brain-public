from __future__ import annotations

import pytest

from governance.pricing_governance import evaluate_pricing_governance


pytestmark = pytest.mark.governance


def test_valid_pricing_governance_passes():
    assert evaluate_pricing_governance({"pricing_record": True, "pricing_status": "AUTHORIZED"})["pricing_status"] == "VALID"


def test_pricing_modification_blocks():
    result = evaluate_pricing_governance({"pricing_record": True, "pricing_status": "AUTHORIZED", "pricing_modification": True})

    assert result["pricing_status"] == "BLOCKED"
    assert result["reason_codes"] == ["PRICING_MODIFICATION_FORBIDDEN"]
