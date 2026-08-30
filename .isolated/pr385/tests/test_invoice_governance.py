from __future__ import annotations

import pytest

from governance.invoice_governance import evaluate_invoice_governance


pytestmark = pytest.mark.governance


def test_valid_invoice_governance_passes():
    assert evaluate_invoice_governance({"invoice_record": True, "invoice_status": "AUTHORIZED"})["invoice_status"] == "VALID"


def test_invoice_sending_blocks():
    result = evaluate_invoice_governance({"invoice_record": True, "invoice_status": "AUTHORIZED", "invoice_sending": True})

    assert result["invoice_status"] == "BLOCKED"
    assert result["reason_codes"] == ["INVOICE_SENDING_FORBIDDEN"]
