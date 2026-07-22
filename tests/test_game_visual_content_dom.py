"""USBAY-GAME-013R - visual-content DOM coverage for /game.

These tests render the additive, demo-only /game prototype, execute its real
client-side JavaScript inside jsdom, and prove the newly added demo VISUAL
content is present and demo-safe:

* the World Map shows city hubs (incl. New York, London, Dubai, Tokyo,
  Cape Town, Rio, Sydney), multi-modal route lines and status tags;
* the Travel Hub shows the six travel mission cards plus the route finder;
* every transport mode screen (flight, train, bus, cruise, ferry) renders;
* the Marketplace shell shows transport-pass and reward-token concept cards
  with no buy / sell / payment controls;
* the demo economy display marks the VIP pass simulated / non-redeemable;
* every screen keeps the persistent DEMO banner and there are no booking /
  payment phrases, network calls or persistence.

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
HARNESS = os.path.join(HERE, "game_visual_content_harness.mjs")

REQUIRED_CITIES = [
    "New York", "London", "Dubai", "Tokyo", "Cape Town", "Rio", "Sydney",
]
REQUIRED_MISSIONS = [
    "Cheapest Route", "Fastest Route", "Highest Governance Score",
    "Sustainability Route", "Accessibility-Safe Route", "Family / Child-Safe Route",
]
REQUIRED_STATUS_TAGS = ["HOT", "LOW COST", "GOVERNED", "DEMO"]
MODE_SCREENS = ["airport", "rail", "bus", "cruise", "ferry"]



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
def vc_result():
    if not _have_node():
        pytest.skip("node not available for jsdom visual-content harness")
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
            "visual-content harness failed: rc=%s stderr=%s"
            % (proc.returncode, proc.stderr[-2000:])
        )
    return json.loads(proc.stdout)


def test_every_screen_renders_with_banner(vc_result):
    """All 16 screens render a heading and keep the persistent DEMO banner."""
    assert len(vc_result["navIds"]) == 16
    assert vc_result["everyScreenHasBanner"] is True


def test_world_map_has_cities_routes_and_status_tags(vc_result):
    """The World Map shows the required city hubs, multi-modal route lines and
    status tags (HOT / LOW COST / GOVERNED / DEMO)."""
    m = vc_result["map"]
    assert m["present"] is True
    assert m["routeSvg"] is True
    assert m["routeLines"] >= 5, m["routeLines"]
    for city in REQUIRED_CITIES:
        assert city in m["cities"], f"map missing city {city}"
    legend = set(m["legendStatusTags"])
    for tag in REQUIRED_STATUS_TAGS:
        assert tag in legend, f"map legend missing status tag {tag}"
    # status tags are also pinned to individual hubs
    assert len(m["nodeStatusTags"]) >= 4


def test_travel_hub_has_mission_cards_and_modes(vc_result):
    """The Travel Hub lists the six travel mission cards and keeps the
    multi-modal route finder."""
    h = vc_result["hub"]
    assert h["hasMissionsHeading"] is True
    for mission in REQUIRED_MISSIONS:
        assert mission in h["missionCards"], f"hub missing mission {mission}"
    assert h["tripRows"] > 0, "route finder rendered no trips"


def test_all_transport_mode_screens_render(vc_result):
    """Every dedicated transport-mode screen renders with a mode tag."""
    modes = vc_result["modes"]
    for mid in MODE_SCREENS:
        assert modes[mid]["rendered"] is True, f"{mid} did not render"
        assert modes[mid]["hasModeTag"] is True, f"{mid} missing mode tag"


def test_marketplace_shell_has_concept_cards_only(vc_result):
    """The Marketplace shell shows transport-pass and reward-token concept cards
    but exposes no buy / sell / payment controls and no inputs."""
    mp = vc_result["marketplace"]
    assert mp["comingSoon"] is True
    assert mp["notImplemented"] is True
    assert mp["passCards"] >= 4, mp["passCards"]
    assert mp["tokenCards"] >= 3, mp["tokenCards"]
    assert mp["mainButtons"] == 0
    assert mp["mainInputs"] == 0
    assert mp["noPaymentWords"] is True
    assert mp["nonRedeemable"] is True


def test_crew_and_economy_display(vc_result):
    """The crew roster shows multiple character cards and the demo economy marks
    the VIP pass simulated / non-redeemable."""
    assert vc_result["crew"]["cards"] >= 6
    assert vc_result["crew"]["hasRoles"] >= 6
    econ = vc_result["economy"]
    assert econ["hasTravel"] is True
    assert econ["hasGov"] is True
    assert econ["hasXp"] is True
    assert econ["hasAudit"] is True
    assert econ["vipSimulated"] is True


def test_no_forbidden_phrases_network_or_persistence(vc_result):
    """No real-money / booking / payment phrases on any screen, and walking the
    whole game performs no network calls and writes no storage."""
    assert vc_result["forbidden"] == []
    assert _policy_violations(vc_result) == []
    assert vc_result["persist"] == []
    assert vc_result["cookie"] == ""
    assert vc_result["jsErrors"] == []
