from __future__ import annotations

import pytest

from governance.billing_governance import evaluate_billing_governance


pytestmark = pytest.mark.governance


def test_valid_billing_governance_passes():
    assert evaluate_billing_governance({"billing_record": True, "billing_status": "AUTHORIZED"})["billing_status"] == "VALID"


def test_payment_processing_blocks():
    result = evaluate_billing_governance({"billing_record": True, "billing_status": "AUTHORIZED", "payment_processing": True})

    assert result["billing_status"] == "BLOCKED"
    assert result["reason_codes"] == ["PAYMENT_PROCESSING_FORBIDDEN"]
