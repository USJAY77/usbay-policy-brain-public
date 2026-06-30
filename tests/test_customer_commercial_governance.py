from __future__ import annotations

import pytest

from governance.customer_commercial_governance import evaluate_customer_commercial_governance


pytestmark = pytest.mark.governance


def test_valid_customer_commercial_governance_passes():
    result = evaluate_customer_commercial_governance({"customer_commercial_record": True, "customer_commercial_status": "AUTHORIZED"})

    assert result["customer_commercial_status"] == "VALID"
    assert result["reason_codes"] == []


def test_customer_activation_blocks():
    result = evaluate_customer_commercial_governance(
        {"customer_commercial_record": True, "customer_commercial_status": "AUTHORIZED", "customer_activation": True}
    )

    assert result["customer_commercial_status"] == "BLOCKED"
    assert result["reason_codes"] == ["CUSTOMER_ACTIVATION_FORBIDDEN"]
