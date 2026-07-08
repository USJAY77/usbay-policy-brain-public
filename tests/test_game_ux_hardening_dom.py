"""USBAY-GAME-009R - interactive UX/behavior hardening for the demo-only /game.

Additive, read-only browser-level coverage that reuses the single shared jsdom
render (see tests/conftest.py::dom_result, which executes the prototype's real
client-side JavaScript inside jsdom once per session). It proves:

  1. VIP discount math is exactly 20% across every transport kind, and rewards
     are never redeemable for anything real.
  2. Route precedence is deterministic and the multi-modal view is visible AND
     selectable.
  3. No personal-data storage (localStorage / sessionStorage / cookie) and no
     booking/payment network activity occur while interacting.
  4. Accessibility and child-safe modes remain active after a route is selected
     and the demo-only safety banner persists.
  5. The main controls are keyboard reachable, and every transport type, hotels,
     logistics, a diverse crew, and the governance missions are all rendered.

It does not touch the control plane, any /api route, /execute, governance
enforcement, the simulator, or any backend system.
"""

import pytest

pytestmark = pytest.mark.regression

TRANSPORT_MODES = {"Flight", "Train", "Bus", "Cruise", "Ferry", "Metro"}
DISCOUNTED_KINDS = ["air", "rail", "bus", "cruise", "ferry", "hotel", "logistics"]


def test_game_ux_vip_discount_is_exactly_20pct_across_modes(dom_result):
    """VIP discount is a strict 20% cut for flights, trains, buses, cruises,
    ferries, hotels and logistics, and the prototype never implies rewards are
    redeemable for real money."""
    d = dom_result["discount"]
    assert d["vipOn"] is True
    for kind in DISCOUNTED_KINDS:
        cell = d["modes"].get(kind)
        assert cell is not None, f"no trip rendered for {kind}"
        assert isinstance(cell["po"], int) and isinstance(cell["pv"], int)
        assert cell["pv"] == round(cell["po"] * 0.8), f"{kind} not a 20% cut"
        assert cell["pv"] < cell["po"], f"{kind} not discounted"
        assert "-20%" in cell["vd"], f"{kind} missing VIP marker"
    assert dom_result["rewardsDisclaimer"] is True
    assert dom_result["forbidden"]["found"] == []


def test_game_ux_route_precedence_and_multimodal_selectable(dom_result):
    """Route precedence stays deterministic per mode and the multi-modal (All
    modes) view is visible, selectable (active), spans every transport type, and
    lists the full trip set."""
    r = dom_result["route"]
    assert "Line 3 - Teal" in r["winners"]["cheapest"]
    assert "Line 3 - Teal" in r["winners"]["fastest"]
    assert "Pacific Star" in r["winners"]["xp"]
    assert "Atlas Express R-12" in r["winners"]["gov"]
    ux = dom_result["ux009r"]
    assert ux["multiModalClicked"] is True
    assert ux["multiModalActive"] is True
    assert TRANSPORT_MODES.issubset(set(ux["multiModalModes"]))
    assert ux["multiModalTripCount"] == 15


def test_game_ux_no_personal_storage_or_booking_network(dom_result):
    """While interacting, the prototype performs no booking/payment network
    calls, persists nothing to localStorage / sessionStorage, sets no cookie,
    and exposes no booking/payment form fields."""
    from game_net_policy import forbidden_net
    u = dom_result["unsafe"]
    assert forbidden_net(dom_result) == []
    assert u["persist"] == []
    assert u["cookie"] == ""
    assert u["inputs"] == []


def test_game_ux_a11y_and_child_safe_persist_after_route_selection(dom_result):
    """Child-safe and accessibility modes stay active after a route is selected,
    and the demo-only safety banner persists in both cases."""
    ux = dom_result["ux009r"]
    assert ux["csActiveAfterRoute"] is True
    assert ux["csBannerAfterRoute"] is True
    assert ux["a11yActiveAfterRoute"] is True
    assert ux["a11yBannerAfterRoute"] is True


def test_game_ux_main_controls_keyboard_reachable(dom_result):
    """The main controls (VIP / child-safe / accessibility toggles and the nav
    buttons) are keyboard reachable."""
    ux = dom_result["ux009r"]
    assert ux["kbToggles"] is True
    assert ux["kbNav"] is True
    assert ux["keyboardReachable"] is True


def test_game_ux_visible_transport_coverage(dom_result):
    """Every transport type (including cruise and ferry), hotels, logistics, a
    diverse crew, and the governance missions are all rendered into the DOM."""
    v = dom_result["visual"]
    assert TRANSPORT_MODES.issubset(set(v["hubModes"]))
    assert v["cruiseFerryVisible"] is True
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


def test_game_ux_timing_instrumentation_present(dom_result):
    """The harness reports phase timing (import / construction / execution /
    teardown) so suite performance is observable."""
    t = dom_result["__timing"]
    for key in (
        "nodeStartupMs",
        "importMs",
        "constructMs",
        "executionMs",
        "teardownMs",
        "totalMs",
    ):
        assert key in t, f"missing timing field {key}"
        assert isinstance(t[key], int) and t[key] >= 0, f"bad timing for {key}"
