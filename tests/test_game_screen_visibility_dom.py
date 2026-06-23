"""USBAY-GAME-012R - screen-visibility / deep-link DOM coverage for /game.

These tests render the additive, demo-only /game prototype, execute its real
client-side JavaScript inside jsdom, and prove that every implemented screen is
reviewable: it is listed in the visible selector, it is reachable via a
per-screen hash deep-link (/game#home, /game#rail, ... /game#marketplace), the
persistent DEMO ONLY banner stays visible on every screen, and no screen exposes
booking/payment controls, form inputs, network calls, or persistence.

Strictly additive and read-only: it does not touch the control plane, any /api
route, /execute, governance enforcement, the simulator, or any backend system.
It runs the rendered HTML in-process (no live server, no external calls).
"""

import json
import os
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

from gateway.app import app

pytestmark = pytest.mark.regression

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
HARNESS = os.path.join(HERE, "game_screen_visibility_harness.mjs")

# The 15 originally-shipped screens plus the new coming-soon marketplace.
REQUIRED_SCREENS = [
    "home", "map", "hub", "rail", "bus", "cruise", "ferry", "airport",
    "hotel", "business", "governance", "academy", "crew", "rewards", "profile",
]
EXPECTED_HEADING = {
    "home": "home",
    "map": "map",
    "hub": "hub",
    "rail": "rail",
    "bus": "bus",
    "cruise": "cruise",
    "ferry": "ferry",
    "airport": "airport",
    "hotel": "hotel",
    "business": "business",
    "governance": "governance",
    "academy": "academy",
    "crew": "crew",
    "rewards": "reward",
    "profile": "profile",
    "marketplace": "marketplace",
}


def _have_node():
    return shutil.which("node") is not None


@pytest.fixture(scope="module")
def vis_result():
    if not _have_node():
        pytest.skip("node not available for jsdom screen-visibility harness")
    html = TestClient(app).get("/game").text
    proc = subprocess.run(
        ["node", HARNESS],
        input=html,
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=120,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise AssertionError(
            "screen-visibility harness failed: rc=%s stderr=%s"
            % (proc.returncode, proc.stderr[-2000:])
        )
    return json.loads(proc.stdout)


def test_selector_lists_every_screen(vis_result):
    """The visible nav selector lists all 15 original screens plus marketplace,
    every entry is a focusable native button, and arrow-key navigation works."""
    sel = vis_result["selector"]
    for sid in REQUIRED_SCREENS + ["marketplace"]:
        assert sid in sel["navIds"], f"{sid} missing from selector"
    assert sel["navCount"] == len(REQUIRED_SCREENS) + 1
    assert sel["allButtons"] is True
    assert sel["allFocusable"] is True
    assert sel["keyboardMovesFocus"] is True


def test_every_screen_deep_links_and_renders(vis_result):
    """Each /game#<id> deep-link renders the correct screen: the selector entry
    becomes active (aria-current=page), a non-empty heading shows, the DEMO
    banner is present, and no form inputs or booking/payment buttons appear."""
    by_id = {s["id"]: s for s in vis_result["screens"]}
    for sid in REQUIRED_SCREENS + ["marketplace"]:
        s = by_id.get(sid)
        assert s is not None, f"{sid} not rendered by harness"
        assert s["activeNav"] == sid, f"{sid} selector not marked active"
        assert s["ariaCurrent"] == "page", f"{sid} missing aria-current"
        assert s["h1"], f"{sid} rendered empty heading"
        assert EXPECTED_HEADING[sid] in s["h1"].lower(), (
            f"{sid} heading mismatch: {s['h1']!r}"
        )
        assert s["bannerPresent"] is True, f"{sid} missing DEMO banner"
        assert "DEMO ONLY - NO REAL BOOKING" in s["bannerText"]
        assert s["mainInputs"] == 0, f"{sid} exposes form inputs"
        assert s["mainBadButtons"] == [], f"{sid} exposes booking/payment buttons"


def test_initial_hash_boots_to_requested_screen(vis_result):
    """Loading /game#governance directly boots straight to the Governance screen
    (deep-links are honored on initial page load, not only on hashchange)."""
    init = vis_result["initialHash"]
    assert init.get("error") is None, init
    assert init["activeNav"] == "governance"
    assert "governance" in init["h1"].lower()


def test_marketplace_is_coming_soon_placeholder(vis_result):
    """The Marketplace screen is an explicit NOT IMPLEMENTED / Coming Soon
    placeholder with no buying, selling, payment, inputs, or actionable
    buttons - it is review-only."""
    mp = vis_result["marketplace"]
    assert mp["present"] is True
    assert "marketplace" in mp["h1"].lower()
    assert mp["comingSoon"] is True
    assert mp["notImplemented"] is True
    assert mp["noPaymentWords"] is True
    assert mp["mainInputs"] == 0
    assert mp["mainButtons"] == 0


def test_no_forbidden_phrases_network_or_persistence(vis_result):
    """Across every screen there are no real-money / booking / payment phrases,
    and walking all screens performs no network calls, no storage writes, and
    sets no cookies."""
    assert vis_result["forbidden"] == []
    assert vis_result["net"] == []
    assert vis_result["persist"] == []
    assert vis_result["cookie"] == ""
    assert vis_result["jsErrors"] == []
