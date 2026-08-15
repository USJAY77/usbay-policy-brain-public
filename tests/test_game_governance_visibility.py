"""GAME GOVERNANCE VISIBILITY HARDENING V1.0 tests.

Server-side assertions on the /game HTML plus a node-evaluated unit harness
for the demo evidence-chain engine (deterministic hashing, chaining, tamper
detection, fail-closed behavior, human-review simulation, export).

All governance-visibility features are client-side, simulated, and local:
these tests also prove no new network transports were added to the page.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from gateway.app import usbay_game_html

ROOT = Path(__file__).resolve().parent.parent
HTML = usbay_game_html()


# ---- 1. governance status bar ----

def test_status_bar_fields_present():
    for marker in [
        "Runtime Mode", "DEMO_ONLY",
        "Policy Status", "ACTIVE",
        "Policy Version", "USBAY-GAME-DEMO-V1",
        "Execution Authority", "NOT_GRANTED",
        "Human Approval", "NOT_REQUIRED_FOR_SIMULATION",
        "Evidence Chain",
        "Provider Access", "DISABLED",
        "Real Booking",
        "Real Payment",
    ]:
        assert marker in HTML, marker


# ---- 2. hero hierarchy ----

def test_hero_primary_hierarchy():
    hero = HTML[HTML.index('class="hero-actions"'):]
    idx = [hero.index(x) for x in
           ("Start Demo Trip", "Governance Center", "Simulator", "World Map", "Rewards")]
    assert idx == sorted(idx), "hero order must be Trip, Governance, Simulator, Map, Rewards"


# ---- 3/4. receipts + evidence chain markers ----

def test_receipt_fields_in_page():
    for marker in [
        "decisionId", "timestampUtc", "actionType", "requestedTarget",
        "policyVersion", "ALLOWED_SIMULATION", "BLOCKED", "humanApproval",
        "executionAuthority", "providerCall", "paymentCall",
        "evidenceHash", "prevHash", "simulationOnly", "reasonCode",
        "usbgov-genesis-00000000", "INTEGRITY_VALID", "INTEGRITY_FAILED",
        "DEMO EVIDENCE CHAIN",
    ]:
        assert marker in HTML, marker


def test_chain_controls_present():
    for marker in ["View evidence", "Verify chain", "Export demo evidence JSON",
                   "Clear demo session", "usbgov-confirm"]:
        assert marker in HTML, marker


# ---- 6. human oversight ----

def test_human_oversight_text():
    assert "Approval authorizes simulation only. It does not authorize real-world execution." in HTML
    for marker in ["APPROVE_SIMULATION", "REJECT_SIMULATION", "REVIEW_REQUIRED",
                   "PENDING_HUMAN_REVIEW"]:
        assert marker in HTML, marker


# ---- 7. fail-closed scenarios ----

def test_fail_closed_reason_codes():
    for code in [
        "MISSING_POLICY_VERSION", "MALFORMED_ACTION_CONTRACT",
        "EVIDENCE_CHAIN_INTEGRITY_FAILURE", "CHILD_SAFE_RESTRICTION",
        "SIMULATED_PROVIDER_UNAVAILABLE", "UNSUPPORTED_CAPABILITY",
        "MISSING_HUMAN_APPROVAL",
    ]:
        assert code in HTML, code


# ---- 8. governance center content + disclaimer ----

def test_governance_center_disclaimer():
    assert ("This Governance Center displays local simulated governance evidence. "
            "It is not production authorization and does not execute real-world actions.") in HTML


# ---- 9. runtime trace steps ----

def test_runtime_trace_steps():
    for step in [
        "Action requested", "Action contract validated", "Policy evaluated",
        "Human review checked", "Execution authority checked",
        "External provider access checked", "Simulation decision produced",
        "Evidence receipt appended",
    ]:
        assert step in HTML, step


# ---- 11. safety messaging ----

def test_persistent_safety_footer():
    assert "No external provider calls" in HTML
    assert "No financial transaction" in HTML
    assert "No production authority" in HTML
    # existing banner preserved
    assert "DEMO ONLY" in HTML
    assert "KID-FRIENDLY" in HTML.upper()


# ---- no new network transports (net policy stays intact) ----

def test_no_new_network_calls_added():
    # the #usbgre panel is now a server-rendered snapshot: NO client fetches
    assert HTML.count("fetch(") == 0
    for forbidden in ["XMLHttpRequest", "sendBeacon", "new WebSocket",
                      "EventSource(", "localStorage", "sessionStorage",
                      "indexedDB", "document.cookie"]:
        assert forbidden not in HTML, forbidden


def test_no_forbidden_commercial_phrases():
    lc = HTML.lower()
    for phrase in ["buy now", "book now", "add to cart", "checkout", "pay now",
                   "enter card", "card number", "cvv", "credit card",
                   "real money", "booking confirmed", "payment confirmed",
                   "payment successful"]:
        assert phrase not in lc, phrase


# ---- engine unit harness (node) ----

@pytest.mark.skipif(shutil.which("node") is None, reason="node unavailable")
def test_engine_unit_harness():
    proc = subprocess.run(
        ["node", str(ROOT / "tests" / "game_gov_engine_harness.mjs")],
        input=HTML.encode(), capture_output=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr.decode()[:2000]
    result = json.loads(proc.stdout.decode().strip().splitlines()[-1])
    failing = [k for k, v in result.get("checks", {}).items() if not v]
    assert result.get("ok") is True, f"failing checks: {failing} err={result.get('error')}"
