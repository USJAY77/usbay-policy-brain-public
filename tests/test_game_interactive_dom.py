"""USBAY-GAME-008 - interactive DOM-level (browser) coverage for /game.

These tests render the additive, demo-only /game prototype, execute its real
client-side JavaScript inside jsdom (a browser DOM/JS engine), and drive the
live DOM the way a user would - toggling child-safe / accessibility / VIP modes,
selecting routes with the route finder, filtering transport modes, and walking
every screen. Assertions are made against the resulting DOM state and against
spies that record any network or storage activity.

This is strictly additive and read-only: it does not touch the control plane,
any /api route, /execute, governance enforcement, or any backend system. It runs
the rendered HTML in-process (no live server, no external calls).
"""

import pytest

# The session-scoped ``dom_result`` fixture lives in tests/conftest.py so that
# the 008 interactive suite and the 009R UX-hardening suite share a single jsdom
# render (jsdom's module load is expensive).

pytestmark = pytest.mark.regression

TRANSPORT_MODES = {"Flight", "Train", "Bus", "Cruise", "Ferry", "Metro"}
DISCOUNTED_KINDS = ["air", "rail", "bus", "cruise", "ferry", "hotel", "logistics"]


def test_game_dom_safety_banner_is_always_visible(dom_result):
    """Persistent safety banner stays visible after load, route selection, and
    after toggling child-safe and accessibility modes."""
    banner = dom_result["banner"]
    assert banner["load"]["present"] is True
    assert "DEMO ONLY - NO REAL BOOKING" in banner["load"]["text"]
    assert "NO REAL PAYMENT" in banner["load"]["text"]
    assert banner["afterRoute"] is True
    assert banner["afterCs"] is True
    assert banner["afterA11y"] is True


def test_game_dom_child_safe_mode_toggles_and_relabels(dom_result):
    """Child-safe toggle exists, flips UI state, relabels wording to child-safe
    copy, and surfaces no booking/payment call-to-action language."""
    cs = dom_result["childSafe"]
    assert cs["toggleExists"] is True
    assert cs["bodyBefore"] is False
    assert cs["bodyAfter"] is True
    assert cs["aria"] == "true"
    assert cs["fraudBefore"] == "Fraud Alert"
    assert cs["fraudAfter"] == "Safety Check"
    assert cs["relabeled"] is True
    assert cs["noBadLang"] is True


def test_game_dom_accessibility_mode_toggles_and_keeps_controls(dom_result):
    """Accessibility toggle exists, flips UI state, applies the body.a11y
    (reduced-motion) class, and leaves key controls reachable."""
    a = dom_result["a11y"]
    assert a["toggleExists"] is True
    assert a["bodyBefore"] is False
    assert a["bodyAfter"] is True
    assert a["aria"] == "true"
    assert a["controlsReachable"] is True


def test_game_dom_vip_discount_applies_to_every_kind(dom_result):
    """VIP discount applies to flights, trains, buses, cruises, ferries, hotels
    and logistics: each shows the original struck price, a strictly lower
    discounted price equal to a 20% cut, and a VIP -20% marker."""
    d = dom_result["discount"]
    assert d["vipOn"] is True
    for kind in DISCOUNTED_KINDS:
        cell = d["modes"].get(kind)
        assert cell is not None, f"no trip rendered for {kind}"
        assert isinstance(cell["po"], int) and isinstance(cell["pv"], int)
        assert cell["pv"] < cell["po"], f"{kind} not discounted"
        assert cell["pv"] == round(cell["po"] * 0.8), f"{kind} wrong discount"
        assert "-20%" in cell["vd"], f"{kind} missing VIP marker"


def test_game_dom_never_implies_real_money_or_confirmed_booking(dom_result):
    """Across every screen, the prototype never says rewards are redeemable for
    real money and never claims a real-world booking/payment was confirmed; the
    rewards disclaimer is present."""
    assert dom_result["forbidden"]["found"] == []
    assert dom_result["rewardsDisclaimer"] is True


def test_game_dom_route_finder_precedence(dom_result):
    """Route finder selects the correct winner for each precedence mode and the
    multi-modal (All modes) view spans every transport type."""
    r = dom_result["route"]
    assert "Line 3 - Teal" in r["winners"]["cheapest"]
    assert "Line 3 - Teal" in r["winners"]["fastest"]
    assert "Pacific Star" in r["winners"]["xp"]
    assert "Atlas Express R-12" in r["winners"]["gov"]
    assert "Cheapest" in r["badges"]["cheapest"]
    assert "Fastest" in r["badges"]["fastest"]
    assert "Highest XP" in r["badges"]["xp"]
    assert "Highest Governance" in r["badges"]["gov"]
    assert TRANSPORT_MODES.issubset(set(r["hubModes"]))
    assert r["tripCount"] == 15


def test_game_dom_has_no_unsafe_ui(dom_result):
    """No hidden booking/payment buttons, no booking/payment form fields, no
    external booking/payment network calls, and no personal-data persistence
    occur while the prototype is interacted with."""
    u = dom_result["unsafe"]
    assert u["buttonsBad"] == []
    assert u["inputs"] == []
    assert u["net"] == []
    assert u["persist"] == []
    assert u["cookie"] == ""


def test_game_dom_visual_coverage(dom_result):
    """Each transport mode, hotels, logistics, a diverse crew, and the
    governance missions are all rendered into the live DOM."""
    v = dom_result["visual"]
    assert TRANSPORT_MODES.issubset(set(v["hubModes"]))
    assert v["hotelVisible"] is True
    assert v["logiVisible"] is True
    assert v["crewThey"] is True
    assert v["crewCards"] >= 10
    assert set(v["govMissions"]) == {
        "Policy Vote",
        "Audit Mission",
        "Fraud Alert",
        "Human Review",
    }
