from __future__ import annotations

from pathlib import Path


CUSTOMER_SELECTION = Path("governance/evidence/pb226_230/pilot_customer_selection.md")
COMMERCIAL_PACK = Path("governance/evidence/pb226_230/pilot_commercial_evidence_pack.md")


def test_pilot_customer_selection_defines_approved_workflow_without_customer_data() -> None:
    text = CUSTOMER_SELECTION.read_text(encoding="utf-8")
    assert "GitHub -> USBAY Gateway -> Human Approval -> Codex" in text
    assert "customer_id: pilot-customer-redacted" in text
    assert "No customer data" in text
    assert "No real live execution" in text


def test_commercial_evidence_pack_contains_required_sections_and_blocks_activation() -> None:
    text = COMMERCIAL_PACK.read_text(encoding="utf-8")
    for heading in (
        "Pilot value proposition",
        "Pricing range",
        "Buyer profile",
        "Success metrics",
        "Audit evidence needed",
        "Remaining legal/compliance gaps",
    ):
        assert heading in text
    assert "No sales automation activation" in text
    assert "No connector activation" in text
