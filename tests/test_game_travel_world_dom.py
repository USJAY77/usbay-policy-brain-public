"""USBAY-GAME-014 - travel-world landing DOM coverage for /game.

These tests render the additive, demo-only /game prototype, execute its real
client-side JavaScript inside jsdom, and prove the travel-first landing
experience is in place and demo-safe:

* the World Map is the default landing screen (loads with no hash);
* a visible travel navigation (Flights / Trains / Buses / Cruises / Ferries /
  Hotels / Logistics) is present on the landing;
* world destination cards render (New York, London, Dubai, Tokyo, Cape Town,
  Rio, Sydney);
* the map shows route visualization and a transport selection panel;
* the Governance Center stays reachable behind its own navigation;
* Academy, Rewards, Crew and Profile remain accessible;
* every screen keeps the persistent DEMO banner and there are no booking /
  payment controls, form inputs, network calls or persistence.

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
HARNESS = os.path.join(HERE, "game_travel_world_harness.mjs")

REQUIRED_TRAVEL_NAV = [
    "Flights", "Trains", "Buses", "Cruises", "Ferries", "Hotels", "Logistics",
]
CORE_SCREENS = ["academy", "rewards", "crew", "profile"]



def _policy_violations(result):
    """Apply the shared fail-closed net policy (tests/game_net_policy.py)."""
    from game_net_policy import forbidden_net
    return forbidden_net({
        "unsafe": {"net": result.get("net") or []},
        "evidencePanel": result.get("evidencePanel") or {},
        "forbidden": {"found": result.get("forbidden") if isinstance(result.get("forbidden"), list) else (result.get("forbidden") or {}).get("found", [])},
    })

def _have_node():
    return shutil.which("node") is not None


@pytest.fixture(scope="module")
def tw_result():
    if not _have_node():
        pytest.skip("node not available for jsdom travel-world harness")
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
            "travel-world harness failed: rc=%s stderr=%s"
            % (proc.returncode, proc.stderr[-2000:])
        )
    return json.loads(proc.stdout)


def test_world_map_is_default_landing(tw_result):
    """With no hash, /game lands on the World Map (travel-first)."""
    d = tw_result["defaultLanding"]
    assert d["activeNavId"] == "map", d
    assert "map" in d["h1"].lower(), d["h1"]
    assert d["hasMap"] is True
    assert d["hasTravelNav"] is True


def test_travel_navigation_visible(tw_result):
    """The landing shows the full visible travel navigation."""
    tn = tw_result["travelNav"]
    assert tn["count"] >= 7, tn
    assert tn["hasAll"] is True, tn["labels"]
    for label in REQUIRED_TRAVEL_NAV:
        assert label in tn["labels"], f"travel nav missing {label}"


def test_transport_selection_panel(tw_result):
    """A transport selection panel with per-mode cards is present."""
    tp = tw_result["transportPanel"]
    assert tp["present"] is True
    assert tp["cards"] >= 7, tp


def test_world_destination_cards(tw_result):
    """World destination cards render for all required cities."""
    de = tw_result["destinations"]
    assert de["present"] is True
    assert de["cards"] >= 7, de
    assert de["hasAllCities"] is True


def test_route_visualization_present(tw_result):
    """The map keeps multi-modal route visualization and a legend."""
    r = tw_result["routes"]
    assert r["svg"] is True
    assert r["lines"] >= 5, r["lines"]
    assert r["legend"] is True


def test_governance_center_accessible(tw_result):
    """The Governance Center is still reachable behind its own navigation."""
    g = tw_result["governance"]
    assert g["inNav"] is True
    assert g["renders"] is True
    assert "governance" in g["h1"].lower(), g["h1"]


def test_core_screens_accessible(tw_result):
    """Academy, Rewards, Crew and Profile remain accessible."""
    core = tw_result["coreScreens"]
    for sid in CORE_SCREENS:
        assert core[sid]["inNav"] is True, f"{sid} missing from nav"
        assert core[sid]["renders"] is True, f"{sid} did not render"


def test_demo_banner_no_booking_payment_network_or_persistence(tw_result):
    """Every screen keeps the DEMO banner; no booking/payment phrases, no form
    inputs, no network calls and no persistence anywhere in the game."""
    assert tw_result["everyScreenHasBanner"] is True
    assert tw_result["forbidden"] == []
    assert tw_result["totalInputs"] == 0
    assert _policy_violations(tw_result) == []
    assert tw_result["persist"] == []
    assert tw_result["cookie"] == ""
    assert tw_result["jsErrors"] == []
