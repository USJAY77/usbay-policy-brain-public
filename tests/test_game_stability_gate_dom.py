"""USBAY-GAME-010R - stability-gate regression contract for the demo-only /game.

These tests make the prototype's *stability guarantees* explicit and auditable:
one focused test per safety property the GAME-010R stability gate must keep
green. They reuse the single shared jsdom render (tests/conftest.py::dom_result)
so they add zero additional jsdom imports.

Strictly additive, read-only browser-level coverage. They do not touch the
control plane, any /api route, /execute, governance enforcement, the simulator,
booking, or payment.
"""

import pytest

pytestmark = pytest.mark.regression

TRANSPORT_MODES = {"Flight", "Train", "Bus", "Cruise", "Ferry", "Metro"}
DISCOUNTED_KINDS = ["air", "rail", "bus", "cruise", "ferry", "hotel", "logistics"]


def test_stability_demo_banner_remains_visible(dom_result):
    """The demo-only safety banner is present at load (naming it as no real
    booking / no real payment) and stays visible after route selection and after
    toggling child-safe and accessibility modes."""
    b = dom_result["banner"]
    assert b["load"]["present"] is True
    assert "DEMO ONLY - NO REAL BOOKING" in b["load"]["text"]
    assert "NO REAL PAYMENT" in b["load"]["text"]
    assert b["afterRoute"] is True
    assert b["afterCs"] is True
    assert b["afterA11y"] is True


def test_stability_no_booking_or_payment_ui(dom_result):
    """No booking/payment buttons and no booking/payment form fields exist in the
    rendered, interacted prototype."""
    u = dom_result["unsafe"]
    assert u["buttonsBad"] == []
    assert u["inputs"] == []


def test_stability_no_external_network_calls(dom_result):
    """No forbidden external network calls (fetch/XHR/WebSocket/EventSource/
    sendBeacon) occur while the prototype is interacted with. The evidence
    panel's read-only diagnostic GET probes are permitted only under the
    strict fail-closed conditions in tests/game_net_policy.py."""
    from game_net_policy import forbidden_net
    assert forbidden_net(dom_result) == []


def test_stability_no_personal_data_persisted(dom_result):
    """No personal data is persisted: nothing written to localStorage /
    sessionStorage and no cookie is set."""
    u = dom_result["unsafe"]
    assert u["persist"] == []
    assert u["cookie"] == ""


def test_stability_vip_discount_is_demo_only(dom_result):
    """VIP discount stays a demo-only, fixed 20% cut for every kind, and the
    prototype never implies rewards are redeemable for real money."""
    d = dom_result["discount"]
    assert d["vipOn"] is True
    for kind in DISCOUNTED_KINDS:
        cell = d["modes"].get(kind)
        assert cell is not None, f"no trip rendered for {kind}"
        assert cell["pv"] == round(cell["po"] * 0.8), f"{kind} not a 20% cut"
        assert "-20%" in cell["vd"], f"{kind} missing VIP marker"
    assert dom_result["rewardsDisclaimer"] is True
    assert dom_result["forbidden"]["found"] == []


def test_stability_route_selection_is_deterministic(dom_result):
    """Route selection remains deterministic: each precedence mode resolves to
    its fixed winner and the full trip set is present."""
    r = dom_result["route"]
    assert "Line 3 - Teal" in r["winners"]["cheapest"]
    assert "Line 3 - Teal" in r["winners"]["fastest"]
    assert "Pacific Star" in r["winners"]["xp"]
    assert "Atlas Express R-12" in r["winners"]["gov"]
    assert TRANSPORT_MODES.issubset(set(r["hubModes"]))
    assert r["tripCount"] == 15


def test_stability_child_safe_mode_active_after_interactions(dom_result):
    """Child-safe mode remains active after a route is selected, and the safety
    banner persists in that state."""
    ux = dom_result["ux009r"]
    assert ux["csActiveAfterRoute"] is True
    assert ux["csBannerAfterRoute"] is True


def test_stability_accessibility_mode_active_after_interactions(dom_result):
    """Accessibility mode remains active after a route is selected, and the
    safety banner persists in that state."""
    ux = dom_result["ux009r"]
    assert ux["a11yActiveAfterRoute"] is True
    assert ux["a11yBannerAfterRoute"] is True
