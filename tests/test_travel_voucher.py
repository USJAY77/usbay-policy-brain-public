"""PB-TRAVEL-002 Partner Voucher Framework — server-rendered contract tests.

The voucher framework is a read-only, preview-only layer inside the Governance
Simulator (/simulator). These tests assert the framework markup and constants are
present and that no payment/booking/partner-API/crypto/cashback rails leak into
the rendered page. The interactive eligibility/lifecycle logic is covered by the
Playwright suite scripts/_shot_travel_v2.py.
"""

import pytest
from fastapi.testclient import TestClient

from gateway import app as gateway_app


@pytest.fixture()
def client():
    return TestClient(gateway_app.app, raise_server_exceptions=False)


def _simulator_html(client):
    res = client.get("/simulator")
    assert res.status_code == 200
    return res.text


def test_partner_catalog_present(client):
    html = _simulator_html(client)
    for label in ("Airline", "Train", "Bus", "Cruise", "Hotel / Stay"):
        assert label in html
    for ptype in ("airline", "train", "bus", "cruise", "hotel"):
        assert ptype in html


def test_eligibility_rule_engine_dimensions(client):
    html = _simulator_html(client)
    for reason in (
        "RANK_BELOW_REQUIREMENT",
        "MISSIONS_BELOW_REQUIREMENT",
        "AUDIT_QUALITY_BELOW_REQUIREMENT",
        "REPUTATION_BELOW_REQUIREMENT",
    ):
        assert reason in html


def test_voucher_object_contract(client):
    html = _simulator_html(client)
    for field in ("voucher_id", "partner_id", "expires_at", "eligible"):
        assert field in html
    # non-monetary invariants
    assert "transferable: false" in html
    assert "cash_value: 'none'" in html
    assert "funding: 'partner_funded'" in html


def test_voucher_lifecycle_audit_evidence(client):
    html = _simulator_html(client)
    assert "Voucher Lifecycle Audit Evidence" in html
    for event in ("ISSUANCE", "EXPIRATION", "REVOCATION"):
        assert event in html
    assert "VOUCHER_REVOKED" in html


def test_fail_closed_markers(client):
    html = _simulator_html(client)
    assert "NO_PARTNER_RULE" in html
    assert "VOUCHER_EXPIRED" in html
    # disclaimer present
    assert "not redeemable for cash" in html


def test_no_payment_or_partner_api_rails(client):
    html = _simulator_html(client).lower()
    for banned in (
        "stripe",
        "paypal",
        "checkout.session",
        "payment_intent",
        "booking_id",
        "card_number",
        "cashback",
        "wallet",
        "stored-value",
        "stored_value",
    ):
        assert banned not in html


def test_governance_approval_evidence_markers(client):
    # PB-TRAVEL-005: the approval chain is surfaced as evidence only.
    html = _simulator_html(client)
    for reason in (
        "APPROVAL_MISSING",
        "APPROVAL_INVALID",
        "APPROVAL_SUBJECT_MISMATCH",
        "APPROVAL_EXPIRED",
        "TIMESTAMP_MISSING",
        "TIMESTAMP_INVALID",
    ):
        assert reason in html
    # the approval lifecycle audit events
    for event in ("approved", "approval_failed"):
        assert event in html
    # surfaced explicitly as evidence only -- never money or a reward
    assert "evidence only" in html.lower()
    assert "governance approval" in html.lower()
    assert "Verify w/o approval" in html


def test_control_plane_untouched(client):
    # The decide control-plane endpoint must still reject unsigned requests
    # (additive travel layer changes nothing about runtime governance).
    res = client.post("/decide", json={})
    assert res.status_code in (400, 401, 403, 422)
