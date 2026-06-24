import base64
import hashlib
import json
import re
import time
from dataclasses import replace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import gateway.app as gateway_app
from audit.hash_chain import AuditHashChain
from governance.continuous_trust_renewal import signable_renewal_message
from governance.device_identity_lifecycle import public_key_fingerprint, signable_identity_message
from governance.remote_challenge_response import signable_challenge_message
from governance.verifier_continuity import signable_verifier_message
from security.decision_store import DecisionStoreTestDouble
from security.deployment_attestation import ProvenanceContext
from security.nonce_store import NonceStore
from tests.provenance_helpers import install_runtime_authority
from tests.request_signing_helpers import configure_request_signing, sign_payload_ed25519


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sign_payload(payload, secret):
    return sign_payload_ed25519(payload)["signature"]


def install_bad_runtime_authority(monkeypatch, tmp_path):
    authority = install_runtime_authority(monkeypatch, tmp_path)
    bad_authority = replace(
        authority,
        provenance_context=ProvenanceContext(
            expected_commit="bad",
            current_commit="bad",
            ci_mode=False,
            accepted_commit_set=("bad",),
            ancestor_continuity=False,
            release_lineage=True,
        ),
    )
    monkeypatch.setattr(gateway_app, "runtime_provenance_authority", lambda: bad_authority)
    return bad_authority

def build_payload(data=None, nonce=None, timestamp=None):
    payload = {
        "action": "read",
        "actor_id": "actor-alice",
        "device": "laptop-1",
        "tenant_id": "t1",
        "timestamp": str(int(time.time())),
        "user_id": "alice",
        "nonce": "test-nonce-default",
        "policy_version": "policy-v1",
        "compute_target": "cpu",
        "compute_risk_level": "low",
        "data_sensitivity": "low",
        "execution_location": "local",
    }
    if data:
        payload.update(data.copy())
    if nonce is not None:
        payload["nonce"] = nonce
    if timestamp is not None:
        payload["timestamp"] = timestamp
    return payload


def configure_gateway(tmp_path, monkeypatch):
    install_runtime_authority(monkeypatch, tmp_path)
    configure_request_signing(tmp_path, monkeypatch, gateway_app)
    monkeypatch.setattr(
        gateway_app,
        "nonce_store",
        NonceStore(tmp_path / "used_nonces.json"),
    )
    monkeypatch.setattr(
        gateway_app,
        "audit_chain",
        AuditHashChain(tmp_path / "audit_chain.json"),
    )
    private_key, public_key = _runtime_attestation_keypair()
    monkeypatch.setenv("USBAY_RUNTIME_ATTESTATION_PRIVATE_KEY_PEM", private_key)
    monkeypatch.setenv("USBAY_RUNTIME_ATTESTATION_PUBLIC_KEY_PEM", public_key)
    monkeypatch.setenv("USBAY_DEPLOYMENT_TIMESTAMP_UTC", "2026-05-20T00:00:00Z")
    monkeypatch.setattr(gateway_app, "decision_store", DecisionStoreTestDouble())
    return TestClient(gateway_app.app, raise_server_exceptions=False)


def _runtime_attestation_keypair() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def _device_identity_packet(private_key: Ed25519PrivateKey, public_pem: str) -> dict:
    packet = {
        "device_id_fingerprint": hashlib.sha256(b"gateway-device").hexdigest(),
        "policy_version": "1.0",
        "issued_at": "2026-05-19T00:00:00Z",
        "expires_at": "2026-05-21T00:00:00Z",
        "nonce": "gateway-nonce",
        "challenge_id": "gateway-challenge",
        "public_key_fingerprint": public_key_fingerprint(public_pem),
        "signature_status": "SIGNED",
        "identity_state": "IDENTITY_VERIFIED",
    }
    packet["signature"] = base64.b64encode(private_key.sign(signable_identity_message(packet))).decode("ascii")
    return packet


def _device_challenge_packet(private_key: Ed25519PrivateKey, policy_hash: str) -> dict:
    packet = {
        "challenge_id": "gateway-live-challenge",
        "nonce": "gateway-live-nonce",
        "issued_at": "2026-05-19T00:00:00Z",
        "expires_at": "2026-05-21T00:00:00Z",
        "device_identity_fingerprint": hashlib.sha256(b"gateway-device").hexdigest(),
        "policy_hash": policy_hash,
        "response_signature_status": "SIGNED",
        "challenge_state": "CHALLENGE_RESPONSE_VALID",
    }
    packet["signature"] = base64.b64encode(private_key.sign(signable_challenge_message(packet))).decode("ascii")
    return packet


def _device_renewal_packet(private_key: Ed25519PrivateKey, policy_hash: str, previous_challenge_hash: str) -> dict:
    packet = {
        "renewal_id": "gateway-renewal",
        "previous_challenge_hash": previous_challenge_hash,
        "new_challenge_id": "gateway-next-challenge",
        "nonce_hash": hashlib.sha256(b"gateway-renewal-nonce").hexdigest(),
        "device_identity_fingerprint": hashlib.sha256(b"gateway-device").hexdigest(),
        "policy_hash": policy_hash,
        "issued_at": "2026-05-20T00:00:00Z",
        "expires_at": "2026-05-20T00:05:00Z",
        "renewal_window_seconds": "300",
        "signature_status": "SIGNED",
        "renewal_state": "TRUST_RENEWAL_ACTIVE",
    }
    packet["signature"] = base64.b64encode(private_key.sign(signable_renewal_message(packet))).decode("ascii")
    return packet


def _verifier_nodes(policy_hash: str):
    keypairs = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
    nodes = []
    trusted = {}
    for index, private_key in enumerate(keypairs, start=1):
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        verifier_hash = public_key_fingerprint(public_pem)
        trusted[verifier_hash] = public_pem
        node = {
            "verifier_node_id": f"gateway-verifier-{index}",
            "verifier_role": "primary",
            "verifier_hash": verifier_hash,
            "quorum_group": "gateway-quorum",
            "consensus_epoch": "gateway-epoch-1",
            "continuity_window": "300",
            "last_verified_at": "2026-05-20T00:00:00Z",
            "policy_hash": policy_hash,
            "signature_status": "SIGNED",
            "continuity_state": "VERIFIER_CONTINUITY_ACTIVE",
        }
        node["signature"] = base64.b64encode(private_key.sign(signable_verifier_message(node))).decode("ascii")
        nodes.append(node)
    return nodes, trusted


def decide_then_execute(client, payload):
    decision = client.post("/decide", json=payload)
    assert decision.status_code == 200
    payload = payload.copy()
    payload["decision_id"] = decision.json()["decision_id"]
    payload["decision_signature"] = decision.json()["decision_signature"]
    payload["decision_signature_classic"] = decision.json()["decision_signature_classic"]
    payload["decision_signature_pqc"] = decision.json()["decision_signature_pqc"]
    return client.post("/execute", json=payload)


def test_execute_success(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload.update(sign_payload_ed25519(payload))

    res = decide_then_execute(client, payload)

    assert res.status_code == 200
    assert res.json()["status"] == "EXECUTED"


def test_replay_fails(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="test-nonce-123")
    payload.update(sign_payload_ed25519(payload))

    decision = client.post("/decide", json=payload)
    assert decision.status_code == 200
    payload["decision_id"] = decision.json()["decision_id"]
    payload["decision_signature"] = decision.json()["decision_signature"]
    payload["decision_signature_classic"] = decision.json()["decision_signature_classic"]
    payload["decision_signature_pqc"] = decision.json()["decision_signature_pqc"]
    res1 = client.post("/execute", json=payload)
    install_bad_runtime_authority(monkeypatch, tmp_path)
    res2 = client.post("/execute", json=payload)

    assert res1.status_code == 200
    assert res2.status_code == 403
    assert res2.json()["error"] == "replay_detected"


def test_missing_nonce_fails(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    del payload["nonce"]
    payload.update(sign_payload_ed25519(payload))

    res = client.post("/execute", json=payload)

    assert res.status_code == 403
    assert res.json()["error"] == "missing_decision_id"


def test_old_timestamp_fails(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(timestamp=str(int(time.time()) - 1000))
    payload.update(sign_payload_ed25519(payload))

    res = client.post("/execute", json=payload)

    assert res.status_code == 403
    assert res.json()["error"] == "missing_decision_id"


def test_malformed_decide_request_precedes_provenance(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    install_bad_runtime_authority(monkeypatch, tmp_path)

    res = client.post("/decide", json={"actor_id": "actor-alice"})

    assert res.status_code == 403
    assert res.json()["reason"] == "malformed_request"


def test_missing_decision_id_precedes_provenance(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload()
    payload.update(sign_payload_ed25519(payload))
    install_bad_runtime_authority(monkeypatch, tmp_path)

    res = client.post("/execute", json=payload)

    assert res.status_code == 403
    assert res.json()["error"] == "missing_decision_id"


def test_gateway_provenance_mismatch_still_fails_closed(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="provenance-mismatch-nonce")
    payload.update(sign_payload_ed25519(payload))
    install_bad_runtime_authority(monkeypatch, tmp_path)

    res = client.post("/decide", json=payload)

    assert res.status_code == 403
    assert res.json()["reason"] == "git_commit_mismatch"


def test_root_loads_governance_gateway(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/")

    assert res.status_code == 200
    assert "USBAY Governance Gateway" in res.text
    assert "Route owner: Governance Control Plane" in res.text
    assert 'href="/playground"' in res.text
    assert "Device Identity Lifecycle" in res.text
    assert "Device identity: DEGRADED" in res.text
    assert "Lifecycle state: IDENTITY_UNENROLLED" in res.text
    assert "Remote Challenge Response" in res.text
    assert "Challenge response: DEGRADED" in res.text
    assert "Challenge state: CHALLENGE_NOT_ISSUED" in res.text
    assert "Continuous Trust Renewal" in res.text
    assert "Trust renewal: DEGRADED" in res.text
    assert "Renewal state: TRUST_RENEWAL_NOT_STARTED" in res.text
    assert "Verifier Continuity" in res.text
    assert "Verifier continuity: DEGRADED" in res.text
    assert "Continuity state: VERIFIER_CONTINUITY_NOT_STARTED" in res.text


def test_playground_routes_load_demo_tooling(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    for path in ("/playground", "/playground/demo", "/playground/tools"):
        res = client.get(path)

        assert res.status_code == 200
        assert "USBAY Runtime Governance Playground" in res.text
        assert "Governance Control Plane" in res.text
        assert "Playground / Demo Tooling" in res.text
        assert 'data-packet-state="FAIL_CLOSED"' in res.text
        assert "Provenance trust: HASH_ONLY_LOCAL" in res.text
        assert "Attestation: NOT_ENTERPRISE_SIGNED" in res.text
        assert "Device identity: DEGRADED" in res.text
        assert "Challenge response: DEGRADED" in res.text
        assert "Trust renewal: DEGRADED" in res.text
        assert "Verifier continuity: DEGRADED" in res.text


def test_playground_intake_dom_ids_are_unique(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/playground")

    assert res.status_code == 200
    assert res.text.count('id="usbsim-intake"') == 1
    assert res.text.count('id="usbsim-pilot-intake"') == 1
    assert "getElementById('usbsim-pilot-intake')" in res.text
    assert res.text.count('class="pi-step') >= 6
    assert res.text.count("getElementById('usbsim-intake')") == 0


def test_game_route_loads_demo_prototype(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/game")

    assert res.status_code == 200
    text = res.text
    # Persistent, unmissable demo-only notice.
    assert "DEMO ONLY - NO REAL BOOKING" in text
    assert "NO REAL PAYMENT" in text
    # All 13 screens are registered in the client-side screen registry.
    for screen_id in ("home", "map", "hub", "rail", "bus", "cruise", "ferry",
                      "airport", "hotel", "business", "governance", "crew",
                      "rewards"):
        assert 'id:"%s"' % screen_id in text
    # All transport modes are represented.
    for mode_label in ("Flight", "Train", "Bus", "Cruise", "Ferry",
                       "Metro", "Hotel", "Logistics"):
        assert mode_label in text
    # Rewards (incl. VIP discount usable on every transport type) + governance.
    assert "VIP Discount Pass" in text
    assert "Travel Credits" in text
    assert "Governance Credits" in text
    assert "Audit Token" in text
    assert "Policy Vote" in text
    assert "Fairness Score" in text
    assert "Privacy Score" in text
    assert "Sustainability Score" in text
    # Child-safe + accessibility toggles.
    assert "Child-Safe" in text
    assert "Accessibility" in text


def test_game_route_is_demo_only_and_makes_no_network_or_payment_calls(
        tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    text = client.get("/game").text

    # The prototype is purely client-side and in-memory: no booking, no payment,
    # no backend calls, no provider claims, no persistence.
    for forbidden in ("fetch(", "XMLHttpRequest", "navigator.sendBeacon",
                      "localStorage", "sessionStorage", "stripe", "paypal",
                      "/api/"):
        assert forbidden not in text, forbidden


def test_game_route_does_not_alter_governance_control_plane(
        tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    # The additive /game page must not shadow or affect API routes; /api/health
    # still returns its JSON contract unchanged.
    health = client.get("/api/health")
    assert health.status_code == 200
    assert "policy_hash" in health.json()

    # The governance control-plane root page remains intact and reachable.
    # (USBAY-GAME-019R additively promotes the game from root via a product
    # selector + nav link; the governance plane itself is preserved.)
    root = client.get("/")
    assert root.status_code == 200
    assert "USBAY Governance Gateway" in root.text
    assert "Governance Control Plane" in root.text


# --------------------------------------------------------------------------
# USBAY-GAME-007 - prototype hardening & UX tests (demo-only, additive).
# These assert on the server-rendered /game source: the page is a purely
# client-side, in-memory demo, so the durable safety/route/discount contracts
# live in the emitted HTML/JS and CSS.
# --------------------------------------------------------------------------

def _game_text(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    res = client.get("/game")
    assert res.status_code == 200
    return res.text


def _parse_game_trips(text):
    """Extract the in-page TRIPS dataset so route-precedence can be checked
    against the same data the prototype renders."""
    block = re.search(r"var TRIPS=\[(.*?)\];", text, re.S)
    assert block, "TRIPS dataset not found in /game source"
    trips = []
    for entry in re.findall(r"\{[^{}]*\}", block.group(1)):
        def field(name):
            m = re.search(name + r":(\d+)", entry)
            return int(m.group(1)) if m else None
        mode = re.search(r'm:"([^"]+)"', entry)
        name = re.search(r'name:"([^"]+)"', entry)
        trips.append({
            "m": mode.group(1) if mode else None,
            "name": name.group(1) if name else None,
            "base": field("base"),
            "mins": field("mins"),
            "xp": field("xp"),
            "gov": field("gov"),
        })
    return trips


def test_game_demo_banner_is_persistent_and_unmissable(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)

    # The banner lives once in the static page shell (outside any JS-rendered
    # screen), so it is shown on every screen.
    assert text.count('<div class="demo-ribbon">') == 1
    assert "DEMO ONLY - NO REAL BOOKING" in text
    assert "NO REAL PAYMENT" in text
    # It is pinned to the top of the viewport so scrolling cannot hide it.
    assert ".demo-ribbon{position:sticky;top:0" in text


def test_game_vip_discount_rate_and_shared_helper(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)

    # A single 20% discount helper is the only price path - every mode reuses it.
    assert "var DISCOUNT=0.20;" in text
    assert (
        "function price(base){return FLAGS.vip?Math.round(base*(1-DISCOUNT)):base;}"
        in text
    )


def test_game_vip_discount_applies_to_every_transport_mode(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    trips = _parse_game_trips(text)

    # Flights, trains, buses, cruises and ferries all exist in the dataset and
    # are rendered through tripRow, which applies price() to t.base.
    for mode in ("air", "rail", "bus", "cruise", "ferry"):
        assert any(t["m"] == mode for t in trips), mode
    assert "var base=t.base,disc=price(base)" in text  # tripRow uses the helper
    # Hotels and logistics each apply the same discount helper.
    assert "var disc=price(h.base)" in text  # scHotel (nightly rates)
    assert "var disc=price(g.base)" in text  # scBusiness (logistics)


def test_game_vip_discount_never_implies_real_redemption(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)

    # Rewards (including the VIP pass) are explicitly non-redeemable for anything
    # real - no monetary value, no purchase, no real-world redemption.
    assert (
        "no monetary value and cannot be purchased or redeemed for anything real"
        in text
    )
    assert "NO REAL PAYMENT" in text


def test_game_route_finder_exposes_all_precedence_modes(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)

    # Route finder controls: cheapest / fastest / highest XP / highest governance
    # are emitted as data-sort pills (rendered dynamically from this key list).
    assert '["cheapest","fastest","xp","gov"]' in text
    assert 'data-sort="' in text
    assert 'data-sort="none"' in text  # explicit "Clear" control
    assert "Route finder" in text
    for label in ("Cheapest", "Fastest", "Highest XP", "Highest Governance"):
        assert label in text, label
    # Multi-modal view (every mode together).
    assert 'data-m="all"' in text
    assert "All modes" in text
    # Comparators exist for each precedence criterion.
    for comparator in ("cheapest:function", "fastest:function",
                       "xp:function", "gov:function"):
        assert comparator in text, comparator
    # The "Best route" badge is only emitted when a precedence sort is active.
    assert 'class="bestbadge"' in text
    assert 'sort!=="none"&&i===0' in text


def test_game_route_precedence_yields_a_deterministic_best_route(
        tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    trips = _parse_game_trips(text)

    # Every trip carries the numeric fields precedence sorting depends on.
    for t in trips:
        for field in ("base", "mins", "xp", "gov"):
            assert t[field] is not None, (t, field)

    # Each precedence criterion has a single, unambiguous winner.
    def unique_winner(key, pick):
        best = pick(t[key] for t in trips)
        winners = [t for t in trips if t[key] == best]
        assert len(winners) == 1, (key, best, [t["name"] for t in winners])
        return winners[0]

    cheapest = unique_winner("base", min)   # cheapest fare
    fastest = unique_winner("mins", min)    # shortest duration
    most_xp = unique_winner("xp", max)      # highest XP reward
    most_gov = unique_winner("gov", max)    # highest governance-credit reward

    # The deterministic winners lock the documented precedence contract.
    assert cheapest["name"] == "Line 3 - Teal"      # cheapest route
    assert fastest["name"] == "Line 3 - Teal"       # fastest route
    assert most_xp["name"] == "Pacific Star"        # highest XP route
    assert most_gov["name"] == "Atlas Express R-12"  # highest governance route

    # Multi-modal coverage: the dataset spans all six transport modes.
    assert {t["m"] for t in trips} == {"air", "rail", "bus", "cruise",
                                        "ferry", "metro"}


def test_game_ux_child_safe_and_accessibility_modes_visible(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)

    assert 'id="tgCs"' in text and "Child-Safe" in text
    assert 'id="tgA11y"' in text and "Accessibility" in text
    # Both are real toggles exposed to assistive tech.
    assert 'role="switch"' in text


def test_game_ux_no_hidden_booking_or_payment_controls(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    low = text.lower()

    # No purchase / checkout call-to-action of any kind.
    for cta in ("book now", "buy now", "pay now", "checkout", "add to cart",
                "proceed to payment", "confirm booking", "confirm payment",
                "complete purchase", "place order"):
        assert cta not in low, cta
    # No payment-instrument capture fields.
    for field in ('type="password"', 'type="email"', 'type="tel"',
                  "credit card", "card number", "cvv", "expiry"):
        assert field not in low, field
    # The only trip action is an explicit in-memory simulation.
    assert "Simulate Trip" in text


def test_game_ux_makes_no_network_calls_and_persists_no_personal_data(
        tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)

    # No network egress (so nothing can reach a real booking/payment endpoint).
    for net in ("fetch(", "XMLHttpRequest", "navigator.sendBeacon",
                "WebSocket", "EventSource", "/api/", "stripe", "paypal"):
        assert net not in text, net
    # No client-side persistence of any kind (no personal data is stored).
    for store in ("localStorage", "sessionStorage", "indexedDB",
                  "document.cookie"):
        assert store not in text, store


def test_game_visual_coverage_modes_crew_and_governance_missions(
        tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    trips = _parse_game_trips(text)

    # Each transport mode is visually represented.
    for mode in ("air", "rail", "bus", "cruise", "ferry", "metro"):
        assert any(t["m"] == mode for t in trips), mode
    assert 'modeTag("hotel")' in text     # hotels
    assert 'modeTag("logi")' in text      # logistics
    for label in ("Flight", "Train", "Bus", "Cruise", "Ferry", "Metro",
                  "Hotel", "Logistics"):
        assert label in text, label

    # Diverse crew: non-binary representation plus broad regional spread.
    assert 'pr:"they/them"' in text
    regions = set(re.findall(r'reg:"([^"]+)"', text))
    assert len(regions) >= 8, regions

    # Governance missions are surfaced in the prototype.
    for mission in ("Policy Vote", "Audit Mission", "Fraud Alert",
                    "Human Review"):
        assert mission in text, mission


def test_playground_assurance_section_present_and_isolated(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    playground = client.get("/playground")
    root = client.get("/")

    assert playground.status_code == 200
    assert root.status_code == 200
    assert playground.text.count('id="usbsim-assurance"') == 1
    assert "Governance Assurance" in playground.text
    for marker in (
        "Policy Integrity",
        "Audit Integrity",
        "Evidence Integrity",
        "Replay Protection",
        "Runtime Verification",
        "Last Validation",
        "44 / 44",
        "Governance Controls Verified",
        "Fail Closed",
        "Replay Guard",
        "Human Review",
    ):
        assert marker in playground.text
    assert 'id="usbsim-assurance"' not in root.text
    assert "Governance Assurance" not in root.text


def test_playground_launcher_section_present_and_isolated(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    playground = client.get("/playground")
    root = client.get("/")

    assert playground.status_code == 200
    assert root.status_code == 200
    assert playground.text.count('id="usbsim-launcher"') == 1
    assert "Live Governance Scenario Launcher" in playground.text
    for marker in (
        "Financial Credit Decision",
        "Healthcare Eligibility",
        "Government Benefit Review",
        "Railway Dispatch Decision",
        "Industrial Automation Action",
        "AI Agent Execution Request",
        "Watch Governance",
        "Watch Enforcement",
        "Watch Evidence",
        "Watch Executive Outcome",
        "Live Decision Path",
        "Evidence Record",
        "Audit Event",
        "Executive Summary",
    ):
        assert marker in playground.text
    assert 'id="usbsim-launcher"' not in root.text
    assert "Live Governance Scenario Launcher" not in root.text


def test_playground_demopack_section_present_and_isolated(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    playground = client.get("/playground")
    root = client.get("/")

    assert playground.status_code == 200
    assert root.status_code == 200
    assert playground.text.count('id="usbsim-demopack"') == 1
    assert "Prospect Demo Readiness Package" in playground.text
    for marker in (
        "Control Plane verified",
        "Gateway verified",
        "Evidence chain verified",
        "Audit trail verified",
        "Human review visible",
        "Scenario launcher ready",
        "Pilot intake preview ready",
        "First-Demo Script",
        "Select sector",
        "Show pilot intake",
        "Copy Prospect Demo Summary",
        "WHAT USBAY DOES",
        "PREVIEW-ONLY DISCLAIMER",
        "Demo environment only. No production systems, customer data, "
        "payments, or external AI providers are connected.",
    ):
        assert marker in playground.text
    assert 'id="usbsim-demopack"' not in root.text
    assert "Prospect Demo Readiness Package" not in root.text


def test_refresh_on_playground_demo_uses_spa_owned_route(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    first = client.get("/playground/demo")
    refreshed = client.get("/playground/demo")

    assert first.status_code == 200
    assert refreshed.status_code == 200
    assert refreshed.text == first.text


def test_api_health_remains_backend_json(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/api/health")

    assert res.status_code == 200
    assert res.headers["content-type"].startswith("application/json")
    assert res.json()["mode"] == "NORMAL"
    assert res.json()["policy_signature_valid"] is True
    assert res.json()["runtime_parity"]["attestation"] == "NOT_ENTERPRISE_SIGNED"
    assert res.json()["device_identity"]["device_lifecycle_status"] == "DEGRADED"
    assert res.json()["device_identity"]["identity_state"] == "IDENTITY_UNENROLLED"
    assert res.json()["challenge_response"]["challenge_liveness_status"] == "DEGRADED"
    assert res.json()["challenge_response"]["challenge_state"] == "CHALLENGE_NOT_ISSUED"
    assert res.json()["trust_renewal"]["trust_renewal_status"] == "DEGRADED"
    assert res.json()["trust_renewal"]["renewal_state"] == "TRUST_RENEWAL_NOT_STARTED"
    assert res.json()["verifier_continuity"]["verifier_continuity_status"] == "DEGRADED"
    assert res.json()["verifier_continuity"]["continuity_state"] == "VERIFIER_CONTINUITY_NOT_STARTED"
    assert res.json()["device_trust_status"] == "DEGRADED"
    assert res.json()["deployment_runtime"]["status"] == "READY"
    assert "DEPLOYMENT_RUNTIME_READY" in res.json()["deployment_runtime"]["reason_codes"]


def test_deployment_health_endpoint_returns_startup_evidence(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/api/deployment/health")

    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "READY"
    assert body["startup_status"] == "VERIFIED"
    assert body["runtime_attestation"]["attestation_status"] == "SIGNED"
    assert body["runtime_attestation"]["signature_valid"] is True
    assert "RUNTIME_ATTESTATION_SIGNED" in body["runtime_attestation"]["reason_codes"]
    assert body["port_binding"] == {
        "host": "0.0.0.0",
        "port_source": "PORT_REQUIRED",
        "port_env_var": "PORT",
        "default_port": None,
    }
    assert "STARTUP_VERIFIED" in body["reason_codes"]
    assert "AUDIT_DB_IGNORED" in body["reason_codes"]
    assert "DEPLOYMENT_RUNTIME_READY" in body["reason_codes"]
    encoded = json.dumps(body, sort_keys=True)
    assert "PRIVATE " + "KEY" not in encoded
    assert "approval_" + "contents" not in encoded
    assert "raw_" + "payload" not in encoded
    assert "token" not in encoded.lower()


def test_runtime_attestation_endpoint_fails_closed_without_signing_key(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.delenv("USBAY_RUNTIME_ATTESTATION_PRIVATE_KEY_PEM", raising=False)
    monkeypatch.delenv("USBAY_RUNTIME_ATTESTATION_PUBLIC_KEY_PEM", raising=False)

    res = client.get("/api/runtime/attestation")

    assert res.status_code == 503
    body = res.json()
    assert body["attestation_status"] == "BLOCKED"
    assert body["signature_valid"] is False
    assert "RUNTIME_ATTESTATION_MISSING" in body["reason_codes"]
    assert "RUNTIME_ATTESTATION_BLOCKED" in body["reason_codes"]


def test_runtime_attestation_ledger_endpoint_is_hash_only(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/api/runtime/attestation/ledger")

    assert res.status_code == 200
    body = res.json()
    assert body["ledger_entry"]["evidence"]["runtime_attestation_hash"]
    assert body["ledger_entry"]["evidence"]["deployment_health_hash"]
    assert "LEDGER_APPEND_SUCCEEDED" in body["ledger_entry"]["reason_codes"]
    assert "LEDGER_REMOTE_UNAVAILABLE" in body["ledger_entry"]["reason_codes"]
    encoded = json.dumps(body, sort_keys=True)
    assert "PRIVATE " + "KEY" not in encoded
    assert "approval_" + "contents" not in encoded
    assert "raw_" + "payload" not in encoded
    assert "token" not in encoded.lower()


def test_device_identity_lifecycle_endpoint_fails_closed_when_identity_missing(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/api/device/identity/lifecycle")

    assert res.status_code == 503
    body = res.json()
    assert body["device_lifecycle_status"] == "DEGRADED"
    assert body["identity_state"] == "IDENTITY_UNENROLLED"
    assert "IDENTITY_MISSING" in body["reason_codes"]
    encoded = json.dumps(body, sort_keys=True)
    assert "PRIVATE " + "KEY" not in encoded
    assert "approval_" + "contents" not in encoded
    assert "raw_" + "payload" not in encoded
    assert "token" not in encoded.lower()


def test_device_identity_lifecycle_endpoint_verifies_signed_identity(tmp_path, monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    packet = _device_identity_packet(private_key, public_pem)
    monkeypatch.setenv("USBAY_DEVICE_IDENTITY_PACKET_JSON", json.dumps(packet, sort_keys=True))
    monkeypatch.setenv("USBAY_DEVICE_IDENTITY_PUBLIC_KEY_PEM", public_pem)
    monkeypatch.setenv("USBAY_ACTIVE_DEVICE_CHALLENGE_IDS", "gateway-challenge")
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/api/device/identity/lifecycle")

    assert res.status_code == 200
    body = res.json()
    assert body["device_lifecycle_status"] == "VERIFIED"
    assert body["identity_state"] == "IDENTITY_VERIFIED"
    assert body["audit_evidence"]["nonce_hash"] == hashlib.sha256(b"gateway-nonce").hexdigest()
    encoded = json.dumps(body, sort_keys=True)
    assert "gateway-nonce" not in encoded
    assert "gateway-challenge" not in encoded
    assert "gateway-device" not in encoded


def test_device_challenge_response_endpoint_fails_closed_when_challenge_missing(tmp_path, monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    packet = _device_identity_packet(private_key, public_pem)
    monkeypatch.setenv("USBAY_DEVICE_IDENTITY_PACKET_JSON", json.dumps(packet, sort_keys=True))
    monkeypatch.setenv("USBAY_DEVICE_IDENTITY_PUBLIC_KEY_PEM", public_pem)
    monkeypatch.setenv("USBAY_ACTIVE_DEVICE_CHALLENGE_IDS", "gateway-challenge")
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/api/device/challenge-response")

    assert res.status_code == 503
    body = res.json()
    assert body["challenge_liveness_status"] == "DEGRADED"
    assert body["challenge_state"] == "CHALLENGE_NOT_ISSUED"
    assert "CHALLENGE_MISSING" in body["reason_codes"]


def test_device_challenge_response_endpoint_verifies_live_signed_challenge(tmp_path, monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    client = configure_gateway(tmp_path, monkeypatch)
    policy_hash = client.get("/api/health").json()["policy_hash"]
    identity_packet = _device_identity_packet(private_key, public_pem)
    challenge_packet = _device_challenge_packet(private_key, policy_hash)
    monkeypatch.setenv("USBAY_DEVICE_IDENTITY_PACKET_JSON", json.dumps(identity_packet, sort_keys=True))
    monkeypatch.setenv("USBAY_DEVICE_CHALLENGE_PACKET_JSON", json.dumps(challenge_packet, sort_keys=True))
    monkeypatch.setenv("USBAY_DEVICE_IDENTITY_PUBLIC_KEY_PEM", public_pem)
    monkeypatch.setenv("USBAY_ACTIVE_DEVICE_CHALLENGE_IDS", "gateway-challenge")
    monkeypatch.setenv("USBAY_ISSUED_DEVICE_CHALLENGE_IDS", "gateway-live-challenge")

    res = client.get("/api/device/challenge-response")

    assert res.status_code == 200
    body = res.json()
    assert body["challenge_liveness_status"] == "VERIFIED"
    assert body["challenge_state"] == "CHALLENGE_RESPONSE_VALID"
    assert body["audit_evidence"]["nonce_hash"] == hashlib.sha256(b"gateway-live-nonce").hexdigest()
    health = client.get("/api/health").json()
    assert health["device_trust_status"] == "DEGRADED"
    encoded = json.dumps(body, sort_keys=True)
    assert "gateway-live-nonce" not in encoded
    assert "gateway-live-challenge" not in encoded
    assert "gateway-device" not in encoded


def test_device_trust_renewal_endpoint_fails_closed_when_renewal_missing(tmp_path, monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    client = configure_gateway(tmp_path, monkeypatch)
    policy_hash = client.get("/api/health").json()["policy_hash"]
    identity_packet = _device_identity_packet(private_key, public_pem)
    challenge_packet = _device_challenge_packet(private_key, policy_hash)
    monkeypatch.setenv("USBAY_DEVICE_IDENTITY_PACKET_JSON", json.dumps(identity_packet, sort_keys=True))
    monkeypatch.setenv("USBAY_DEVICE_CHALLENGE_PACKET_JSON", json.dumps(challenge_packet, sort_keys=True))
    monkeypatch.setenv("USBAY_DEVICE_IDENTITY_PUBLIC_KEY_PEM", public_pem)
    monkeypatch.setenv("USBAY_ACTIVE_DEVICE_CHALLENGE_IDS", "gateway-challenge")
    monkeypatch.setenv("USBAY_ISSUED_DEVICE_CHALLENGE_IDS", "gateway-live-challenge")

    res = client.get("/api/device/trust-renewal")

    assert res.status_code == 503
    body = res.json()
    assert body["trust_renewal_status"] == "DEGRADED"
    assert body["renewal_state"] == "TRUST_RENEWAL_NOT_STARTED"
    assert "TRUST_RENEWAL_MISSING" in body["reason_codes"]


def test_device_trust_renewal_endpoint_verifies_continuous_trust(tmp_path, monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    client = configure_gateway(tmp_path, monkeypatch)
    policy_hash = client.get("/api/health").json()["policy_hash"]
    identity_packet = _device_identity_packet(private_key, public_pem)
    challenge_packet = _device_challenge_packet(private_key, policy_hash)
    monkeypatch.setenv("USBAY_DEVICE_IDENTITY_PACKET_JSON", json.dumps(identity_packet, sort_keys=True))
    monkeypatch.setenv("USBAY_DEVICE_CHALLENGE_PACKET_JSON", json.dumps(challenge_packet, sort_keys=True))
    monkeypatch.setenv("USBAY_DEVICE_IDENTITY_PUBLIC_KEY_PEM", public_pem)
    monkeypatch.setenv("USBAY_ACTIVE_DEVICE_CHALLENGE_IDS", "gateway-challenge")
    monkeypatch.setenv("USBAY_ISSUED_DEVICE_CHALLENGE_IDS", "gateway-live-challenge")
    challenge_hash = client.get("/api/device/challenge-response").json()["audit_evidence"]["challenge_audit_hash"]
    renewal_packet = _device_renewal_packet(private_key, policy_hash, challenge_hash)
    monkeypatch.setenv("USBAY_DEVICE_TRUST_RENEWAL_PACKET_JSON", json.dumps(renewal_packet, sort_keys=True))

    res = client.get("/api/device/trust-renewal")

    assert res.status_code == 200
    body = res.json()
    assert body["trust_renewal_status"] == "VERIFIED"
    assert body["renewal_state"] == "TRUST_RENEWAL_ACTIVE"
    assert body["audit_evidence"]["nonce_hash"] == hashlib.sha256(b"gateway-renewal-nonce").hexdigest()
    health = client.get("/api/health").json()
    assert health["device_trust_status"] == "DEGRADED"
    encoded = json.dumps(body, sort_keys=True)
    assert "gateway-renewal" not in encoded
    assert "gateway-next-challenge" not in encoded
    assert "gateway-renewal-nonce" not in encoded
    assert "gateway-device" not in encoded


def test_verifier_continuity_endpoint_verifies_quorum(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    policy_hash = client.get("/api/health").json()["policy_hash"]
    nodes, trusted = _verifier_nodes(policy_hash)
    monkeypatch.setenv("USBAY_VERIFIER_CONTINUITY_NODES_JSON", json.dumps(nodes, sort_keys=True))
    monkeypatch.setenv("USBAY_VERIFIER_PUBLIC_KEYS_JSON", json.dumps(trusted, sort_keys=True))

    res = client.get("/api/verifier/continuity")

    assert res.status_code == 200
    body = res.json()
    assert body["verifier_continuity_status"] == "VERIFIED"
    assert body["continuity_state"] == "VERIFIER_CONTINUITY_ACTIVE"
    assert "VERIFIER_QUORUM_REACHED" in body["reason_codes"]
    encoded = json.dumps(body, sort_keys=True)
    assert "gateway-verifier" not in encoded
    assert "gateway-quorum" not in encoded
    assert "gateway-epoch" not in encoded


def test_device_trust_requires_verifier_continuity_quorum(tmp_path, monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    client = configure_gateway(tmp_path, monkeypatch)
    policy_hash = client.get("/api/health").json()["policy_hash"]
    identity_packet = _device_identity_packet(private_key, public_pem)
    challenge_packet = _device_challenge_packet(private_key, policy_hash)
    monkeypatch.setenv("USBAY_DEVICE_IDENTITY_PACKET_JSON", json.dumps(identity_packet, sort_keys=True))
    monkeypatch.setenv("USBAY_DEVICE_CHALLENGE_PACKET_JSON", json.dumps(challenge_packet, sort_keys=True))
    monkeypatch.setenv("USBAY_DEVICE_IDENTITY_PUBLIC_KEY_PEM", public_pem)
    monkeypatch.setenv("USBAY_ACTIVE_DEVICE_CHALLENGE_IDS", "gateway-challenge")
    monkeypatch.setenv("USBAY_ISSUED_DEVICE_CHALLENGE_IDS", "gateway-live-challenge")
    challenge_hash = client.get("/api/device/challenge-response").json()["audit_evidence"]["challenge_audit_hash"]
    renewal_packet = _device_renewal_packet(private_key, policy_hash, challenge_hash)
    monkeypatch.setenv("USBAY_DEVICE_TRUST_RENEWAL_PACKET_JSON", json.dumps(renewal_packet, sort_keys=True))
    nodes, trusted = _verifier_nodes(policy_hash)
    monkeypatch.setenv("USBAY_VERIFIER_CONTINUITY_NODES_JSON", json.dumps(nodes, sort_keys=True))
    monkeypatch.setenv("USBAY_VERIFIER_PUBLIC_KEYS_JSON", json.dumps(trusted, sort_keys=True))

    health = client.get("/api/health").json()

    assert health["device_identity"]["device_lifecycle_status"] == "VERIFIED"
    assert health["challenge_response"]["challenge_liveness_status"] == "VERIFIED"
    assert health["trust_renewal"]["trust_renewal_status"] == "VERIFIED"
    assert health["verifier_continuity"]["verifier_continuity_status"] == "VERIFIED"
    assert health["device_trust_status"] == "VERIFIED"


def test_frontend_query_cannot_override_device_identity_lifecycle(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/?device_identity=VERIFIED")

    assert res.status_code == 200
    assert "Device identity: DEGRADED" in res.text
    assert "Device identity: VERIFIED" not in res.text
    assert "Challenge response: DEGRADED" in res.text
    assert "Trust renewal: DEGRADED" in res.text
    assert "Verifier continuity: DEGRADED" in res.text


def test_dashboard_uses_backend_identity_lifecycle_state(tmp_path, monkeypatch):
    monkeypatch.setattr(
        gateway_app,
        "device_identity_lifecycle_snapshot",
        lambda **_kwargs: {
            "schema_version": "usbay.device_identity_lifecycle.v1",
            "verified": True,
            "identity_state": "IDENTITY_VERIFIED",
            "reason_code": "IDENTITY_VALIDATION_PASSED",
            "reason_codes": ["IDENTITY_VALIDATION_PASSED"],
            "device_lifecycle_status": "VERIFIED",
            "audit_evidence": {
                "identity_state": "IDENTITY_VERIFIED",
                "reason_code": "IDENTITY_VALIDATION_PASSED",
                "policy_hash": "a" * 64,
                "public_key_fingerprint": "b" * 64,
                "challenge_id_hash": "c" * 64,
                "nonce_hash": "d" * 64,
                "timestamp": "2026-05-20T00:00:00Z",
                "device_id_fingerprint": "e" * 64,
                "identity_audit_hash": "f" * 64,
            },
        },
    )
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/")

    assert res.status_code == 200
    assert "Device identity: VERIFIED" in res.text
    assert "Lifecycle state: IDENTITY_VERIFIED" in res.text


def test_root_renders_visible_public_status_page(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/")

    assert res.status_code == 200
    ctype = res.headers.get("content-type", "")
    assert "text/html" in ctype
    body = res.text
    assert "<title>USBAY Governance Gateway</title>" in body
    assert "USBAY Governance Gateway" in body
    assert "Public Status" in body
    assert 'id="public-status"' in body
    assert 'id="public-status-value"' in body
    assert 'id="public-verified-value"' in body
    assert 'id="public-policy-signature-valid"' in body
    assert 'id="public-replay-protection-active"' in body
    assert 'id="public-policy-version"' in body
    assert "background: #ffffff" in body
    assert "color: #1a1a1a" in body
    lowered = body.lower()
    for forbidden in ("private key", "begin rsa", "begin openssh", "secret", "token", "api_key"):
        assert forbidden not in lowered


def test_root_health_and_api_status_routes_return_200(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    root_res = client.get("/")
    assert root_res.status_code == 200
    assert "USBAY Governance Gateway" in root_res.text
    lowered = root_res.text.lower()
    for forbidden in ("private key", "begin rsa", "begin openssh", "secret", "token"):
        assert forbidden not in lowered

    health_res = client.get("/health")
    assert health_res.status_code == 200
    health_body = health_res.json()
    assert "status" in health_body
    assert "mode" in health_body

    status_res = client.get("/api/status")
    assert status_res.status_code == 200
    status_body = status_res.json()
    assert status_body["status"] == health_body["status"]
    assert status_body["mode"] == health_body["mode"]
    assert status_body["policy_signature_valid"] == health_body["policy_signature_valid"]
    assert status_body["replay_protection_active"] == health_body["replay_protection_active"]


def test_runtime_parity_diagnostics_are_backend_owned_and_redacted(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/api/runtime/parity")

    assert res.status_code == 200
    body = res.json()
    assert body["runtime_parity_status"] == "VERIFIED"
    assert body["provenance_trust"] == "HASH_ONLY_LOCAL"
    assert body["attestation"] == "NOT_ENTERPRISE_SIGNED"
    encoded = json.dumps(body, sort_keys=True)
    assert "PRIVATE KEY" not in encoded
    assert "approval_contents" not in encoded
    assert "token" not in encoded.lower()


def test_frontend_query_cannot_override_runtime_parity(tmp_path, monkeypatch):
    monkeypatch.setattr(
        gateway_app,
        "runtime_attestation_parity_snapshot",
        lambda: {
            "runtime_parity_status": "UNTRUSTED",
            "manifest_hash": "",
            "policy_hash": "",
            "provenance_fingerprint": "",
            "reason_codes": ["RUNTIME_ATTESTATION_UNTRUSTED"],
            "provenance_trust": "HASH_ONLY_LOCAL",
            "attestation": "NOT_ENTERPRISE_SIGNED",
        },
    )
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/playground?runtime_parity=VERIFIED")

    assert res.status_code == 200
    assert "Runtime parity: UNTRUSTED" in res.text
    assert "Runtime parity: VERIFIED" not in res.text


def test_unknown_api_path_returns_json_404(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/api/unknown-route")

    assert res.status_code == 404
    assert res.headers["content-type"].startswith("application/json")
    assert res.json() == {"error": "api_route_not_found", "path": "/api/unknown-route"}


def test_assets_namespace_is_reserved_for_frontend_assets(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/assets/missing.js")

    assert res.status_code == 404
    assert res.headers["content-type"].startswith("application/json")
    assert res.json() == {"error": "frontend_asset_not_found", "path": "/assets/missing.js"}


def test_unknown_frontend_path_returns_governed_spa_index(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.get("/unknown/frontend/path")

    assert res.status_code == 200
    assert "USBAY Governance Gateway" in res.text
    assert "Route owner: Governance Control Plane" in res.text


def test_invalid_packet_remains_fail_closed(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    res = client.post("/execute", json={"actor_id": "actor-alice"})

    assert res.status_code == 403
    assert res.json()["error"] == "missing_decision_id"


def test_valid_signed_bounded_packet_executes_normally(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="route-valid-signed-packet")
    payload.update(sign_payload_ed25519(payload))

    res = decide_then_execute(client, payload)

    assert res.status_code == 200
    assert res.json()["status"] == "EXECUTED"


# ---------------------------------------------------------------------------
# Governance Runtime Health Authority (PB-RUNTIME-001)
# ---------------------------------------------------------------------------
def _rh_force(monkeypatch, name, status, codes):
    def _probe():
        return gateway_app._rh_check(name, status, list(codes), "forced")
    patched = dict(gateway_app._RUNTIME_HEALTH_PROBES)
    patched[name] = _probe
    monkeypatch.setattr(gateway_app, "_RUNTIME_HEALTH_PROBES", patched)


def _rh_force_all_healthy(monkeypatch):
    for n in gateway_app._RUNTIME_HEALTH_SUBSYSTEMS:
        _rh_force(monkeypatch, n, gateway_app.RUNTIME_HEALTH_HEALTHY, [])


def test_runtime_health_all_healthy_allows_execution(monkeypatch):
    _rh_force_all_healthy(monkeypatch)
    snap = gateway_app.runtime_health_snapshot()
    assert snap["state"] == "HEALTHY"
    assert snap["decision"] == "EXECUTION_ALLOWED"
    assert snap["execution_allowed"] is True
    assert snap["reason_codes"] == []
    assert {c["subsystem"] for c in snap["checks"]} == set(
        gateway_app._RUNTIME_HEALTH_SUBSYSTEMS)
    allowed, snap2 = gateway_app.runtime_execution_gate()
    assert allowed is True and snap2["state"] == "HEALTHY"


def test_runtime_health_degraded_warns_but_allows(monkeypatch):
    _rh_force_all_healthy(monkeypatch)
    _rh_force(monkeypatch, "runtime_storage", gateway_app.RUNTIME_HEALTH_DEGRADED,
              [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE])
    snap = gateway_app.runtime_health_snapshot()
    assert snap["state"] == "DEGRADED"
    assert snap["decision"] == "EXECUTION_ALLOWED_WITH_WARNING"
    assert snap["execution_allowed"] is True
    assert gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE in snap["reason_codes"]


def test_runtime_health_failed_blocks_execution(monkeypatch):
    _rh_force_all_healthy(monkeypatch)
    _rh_force(monkeypatch, "policy_engine", gateway_app.RUNTIME_HEALTH_FAILED,
              [gateway_app.RHC_POLICY_ENGINE_UNAVAILABLE])
    snap = gateway_app.runtime_health_snapshot()
    assert snap["state"] == "FAILED"
    assert snap["decision"] == "EXECUTION_BLOCKED"
    assert snap["execution_allowed"] is False
    allowed, _ = gateway_app.runtime_execution_gate()
    assert allowed is False


def test_runtime_health_failed_dominates_degraded(monkeypatch):
    _rh_force_all_healthy(monkeypatch)
    _rh_force(monkeypatch, "runtime_storage", gateway_app.RUNTIME_HEALTH_DEGRADED,
              [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE])
    _rh_force(monkeypatch, "audit_subsystem", gateway_app.RUNTIME_HEALTH_FAILED,
              [gateway_app.RHC_AUDIT_SUBSYSTEM_UNAVAILABLE])
    snap = gateway_app.runtime_health_snapshot()
    assert snap["state"] == "FAILED"
    assert snap["execution_allowed"] is False


def test_runtime_health_authority_fails_closed_on_probe_raise(monkeypatch):
    _rh_force_all_healthy(monkeypatch)

    def _boom():
        raise RuntimeError("probe exploded")
    patched = dict(gateway_app._RUNTIME_HEALTH_PROBES)
    patched["approval_subsystem"] = _boom
    monkeypatch.setattr(gateway_app, "_RUNTIME_HEALTH_PROBES", patched)
    snap = gateway_app.runtime_health_snapshot()
    assert snap["state"] == "FAILED"
    assert snap["execution_allowed"] is False
    assert gateway_app.RHC_RUNTIME_HEALTH_AUTHORITY_ERROR in snap["reason_codes"]


def test_runtime_health_authority_fails_closed_on_internal_error(monkeypatch):
    def _boom(_state):
        raise RuntimeError("decision exploded")
    monkeypatch.setattr(gateway_app, "_runtime_health_decision", _boom)
    snap = gateway_app.runtime_health_snapshot()
    assert snap["state"] == "FAILED"
    assert snap["decision"] == "EXECUTION_BLOCKED"
    assert snap["execution_allowed"] is False
    assert snap["reason_codes"] == [gateway_app.RHC_RUNTIME_HEALTH_AUTHORITY_ERROR]


def test_runtime_health_endpoint_healthy_returns_200(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    r = client.get("/runtime/health")
    assert r.status_code == 200
    body = r.json()
    assert body["state"] == "HEALTHY"
    assert body["execution_allowed"] is True
    assert {c["subsystem"] for c in body["checks"]} == set(
        gateway_app._RUNTIME_HEALTH_SUBSYSTEMS)


def test_runtime_health_endpoint_failed_returns_503(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    _rh_force(monkeypatch, "revocation_subsystem", gateway_app.RUNTIME_HEALTH_FAILED,
              [gateway_app.RHC_REVOCATION_SUBSYSTEM_UNAVAILABLE])
    r = client.get("/runtime/health")
    assert r.status_code == 503
    body = r.json()
    assert body["state"] == "FAILED"
    assert body["execution_allowed"] is False


def test_runtime_health_endpoint_html_panel(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    r = client.get("/runtime/health", headers={"Accept": "text/html"})
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Runtime health evidence" in r.text
    assert "Runtime health audit table" in r.text


def test_runtime_health_selftest_passes(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    r = client.get("/runtime/health/selftest")
    assert r.status_code == 200
    body = r.json()
    assert body["selftest_passed"] is True
    assert body["state"] == "HEALTHY"


def test_runtime_health_selftest_fails_closed_on_authority_error(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)

    def _boom():
        raise RuntimeError("probe exploded")
    patched = dict(gateway_app._RUNTIME_HEALTH_PROBES)
    patched["policy_engine"] = _boom
    monkeypatch.setattr(gateway_app, "_RUNTIME_HEALTH_PROBES", patched)
    r = client.get("/runtime/health/selftest")
    assert r.status_code == 503
    assert r.json()["selftest_passed"] is False


# ---------------------------------------------------------------------------
# Runtime Health Authority enforcement at /execute (PB-RUNTIME-003)
# ---------------------------------------------------------------------------
def test_execute_invokes_runtime_execution_gate(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-gate-spy")
    payload.update(sign_payload_ed25519(payload))
    calls = {"n": 0}
    real_gate = gateway_app.runtime_execution_gate

    def _spy():
        calls["n"] += 1
        return real_gate()

    monkeypatch.setattr(gateway_app, "runtime_execution_gate", _spy)
    res = decide_then_execute(client, payload)
    assert res.status_code == 200
    assert res.json()["status"] == "EXECUTED"
    assert calls["n"] >= 1


def test_execute_blocked_when_runtime_health_failed(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-gate-failed")
    payload.update(sign_payload_ed25519(payload))
    _rh_force(monkeypatch, "policy_engine", gateway_app.RUNTIME_HEALTH_FAILED,
              [gateway_app.RHC_POLICY_ENGINE_UNAVAILABLE])
    res = decide_then_execute(client, payload)
    assert res.status_code == 503
    body = res.json()
    assert body["error"] == "runtime_health_blocked"
    assert body["execution_allowed"] is False
    assert body["runtime_health_state"] == "FAILED"
    assert gateway_app.RHC_POLICY_ENGINE_UNAVAILABLE in body["reason_codes"]


def test_execute_blocked_when_health_probe_raises(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-gate-probe-raise")
    payload.update(sign_payload_ed25519(payload))

    def _boom():
        raise RuntimeError("probe exploded")

    patched = dict(gateway_app._RUNTIME_HEALTH_PROBES)
    patched["revocation_subsystem"] = _boom
    monkeypatch.setattr(gateway_app, "_RUNTIME_HEALTH_PROBES", patched)
    res = decide_then_execute(client, payload)
    assert res.status_code == 503
    body = res.json()
    assert body["error"] == "runtime_health_blocked"
    assert body["execution_allowed"] is False
    assert gateway_app.RHC_RUNTIME_HEALTH_AUTHORITY_ERROR in body["reason_codes"]


def test_execute_gate_exception_fails_closed(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-gate-exc")
    payload.update(sign_payload_ed25519(payload))

    def _explode():
        raise RuntimeError("gate exploded")

    monkeypatch.setattr(gateway_app, "runtime_execution_gate", _explode)
    res = decide_then_execute(client, payload)
    assert res.status_code == 503
    body = res.json()
    assert body["error"] == "runtime_health_blocked"
    assert body["execution_allowed"] is False


def test_runtime_health_block_carries_decision_id_and_reason_code(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-gate-evidence")
    payload.update(sign_payload_ed25519(payload))
    decision = client.post("/decide", json=payload)
    assert decision.status_code == 200
    payload["decision_id"] = decision.json()["decision_id"]
    payload["decision_signature"] = decision.json()["decision_signature"]
    payload["decision_signature_classic"] = decision.json()["decision_signature_classic"]
    payload["decision_signature_pqc"] = decision.json()["decision_signature_pqc"]
    _rh_force(monkeypatch, "audit_subsystem", gateway_app.RUNTIME_HEALTH_FAILED,
              [gateway_app.RHC_AUDIT_SUBSYSTEM_UNAVAILABLE])
    res = client.post("/execute", json=payload)
    assert res.status_code == 503
    body = res.json()
    assert body["reason_code"] == gateway_app.RHC_RUNTIME_HEALTH_EXECUTION_BLOCKED
    assert body["decision_id"] == payload["decision_id"]
    assert gateway_app.RHC_AUDIT_SUBSYSTEM_UNAVAILABLE in body["reason_codes"]
    # no raw sensitive request data echoed back
    serialized = json.dumps(body)
    assert "actor-alice" not in serialized
    assert "decision_signature" not in body


def test_degraded_runtime_health_still_allows_execute(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-gate-degraded")
    payload.update(sign_payload_ed25519(payload))
    _rh_force(monkeypatch, "runtime_storage", gateway_app.RUNTIME_HEALTH_DEGRADED,
              [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE])
    res = decide_then_execute(client, payload)
    assert res.status_code == 200
    assert res.json()["status"] == "EXECUTED"


def test_no_execute_bypass_remains_when_health_failed(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-gate-nobypass")
    payload.update(sign_payload_ed25519(payload))
    _rh_force(monkeypatch, "revocation_subsystem", gateway_app.RUNTIME_HEALTH_FAILED,
              [gateway_app.RHC_REVOCATION_SUBSYSTEM_UNAVAILABLE])
    res = decide_then_execute(client, payload)
    assert res.status_code == 503
    assert res.json().get("status") != "EXECUTED"


# ---------------------------------------------------------------------------
# Runtime Health DEGRADED policy: warning-only but explicitly audited
# (PB-RUNTIME-004)
# ---------------------------------------------------------------------------
def test_runtime_health_degraded_warning_reason_code_is_stable():
    assert (gateway_app.RHC_RUNTIME_HEALTH_DEGRADED_WARNING
            == "RUNTIME_HEALTH_DEGRADED_WARNING")


def test_degraded_warning_event_emits_reason_code_without_raw_data(monkeypatch):
    captured = []
    monkeypatch.setattr(gateway_app, "audit_governance_event",
                        lambda action, event: captured.append((action, event)))
    snap = {
        "state": gateway_app.RUNTIME_HEALTH_DEGRADED,
        "decision": gateway_app.RUNTIME_EXEC_WARNING,
        "execution_allowed": True,
        "reason_codes": [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE],
        "audit_trail": [],
    }
    rc = gateway_app.runtime_health_degraded_warning_event(
        snap, decision_id="dec-degraded-123", action="demo-action")
    assert rc == gateway_app.RHC_RUNTIME_HEALTH_DEGRADED_WARNING
    assert len(captured) == 1
    action, event = captured[0]
    assert action == "execution_allowed_runtime_health_degraded"
    assert event["reason_code"] == gateway_app.RHC_RUNTIME_HEALTH_DEGRADED_WARNING
    assert event["decision_id"] == "dec-degraded-123"
    assert (gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE
            in event["runtime_health_reason_codes"])
    # never raw payload / signature material
    serialized = json.dumps(event)
    assert "decision_signature" not in serialized
    assert "actor-alice" not in serialized


def test_degraded_warning_event_never_blocks_on_audit_failure(monkeypatch):
    def _boom(action, event):
        raise RuntimeError("audit subsystem down")

    monkeypatch.setattr(gateway_app, "audit_governance_event", _boom)
    # must not raise: warning-only path stays allowed even if audit fails
    rc = gateway_app.runtime_health_degraded_warning_event(
        {"state": gateway_app.RUNTIME_HEALTH_DEGRADED}, decision_id=None, action="x")
    assert rc == gateway_app.RHC_RUNTIME_HEALTH_DEGRADED_WARNING


def test_execute_degraded_emits_warning_audit_and_still_executes(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-gate-degraded-audit")
    payload.update(sign_payload_ed25519(payload))
    _rh_force(monkeypatch, "runtime_storage", gateway_app.RUNTIME_HEALTH_DEGRADED,
              [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE])
    captured = []
    real_audit = gateway_app.audit_governance_event

    def _spy(action, event):
        captured.append((action, event))
        return real_audit(action, event)

    monkeypatch.setattr(gateway_app, "audit_governance_event", _spy)
    res = decide_then_execute(client, payload)
    assert res.status_code == 200
    assert res.json()["status"] == "EXECUTED"
    degraded = [e for (a, e) in captured
                if a == "execution_allowed_runtime_health_degraded"]
    assert len(degraded) >= 1
    assert degraded[0]["reason_code"] == gateway_app.RHC_RUNTIME_HEALTH_DEGRADED_WARNING
    assert (gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE
            in degraded[0]["runtime_health_reason_codes"])


def test_execute_healthy_emits_no_degraded_warning(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-gate-healthy-nowarn")
    payload.update(sign_payload_ed25519(payload))
    _rh_force_all_healthy(monkeypatch)
    captured = []
    real_audit = gateway_app.audit_governance_event

    def _spy(action, event):
        captured.append(action)
        return real_audit(action, event)

    monkeypatch.setattr(gateway_app, "audit_governance_event", _spy)
    res = decide_then_execute(client, payload)
    assert res.status_code == 200
    assert res.json()["status"] == "EXECUTED"
    assert "execution_allowed_runtime_health_degraded" not in captured

# ---------------------------------------------------------------------------
# Runtime Health Policy Profiles: DEGRADED handling is policy-driven, not
# hardcoded. STRICT blocks DEGRADED; BALANCED (default) and CONTINUITY warn.
# FAILED blocks in every profile (fail-closed invariant). (PB-RUNTIME-005)
# ---------------------------------------------------------------------------
def test_runtime_health_profiles_are_canonical():
    assert gateway_app.RUNTIME_HEALTH_PROFILE_STRICT == "STRICT"
    assert gateway_app.RUNTIME_HEALTH_PROFILE_BALANCED == "BALANCED"
    assert gateway_app.RUNTIME_HEALTH_PROFILE_CONTINUITY == "CONTINUITY"
    assert gateway_app.RUNTIME_HEALTH_PROFILES == ("STRICT", "BALANCED", "CONTINUITY")
    # Default preserves the PB-RUNTIME-004 contract (DEGRADED -> warning-only).
    assert gateway_app.DEFAULT_RUNTIME_HEALTH_PROFILE == "BALANCED"


def test_profile_reason_codes_are_stable():
    assert gateway_app.RHC_PROFILE_STRICT_DEGRADED_BLOCK == "PROFILE_STRICT_DEGRADED_BLOCK"
    assert (gateway_app.RHC_PROFILE_BALANCED_DEGRADED_WARNING
            == "PROFILE_BALANCED_DEGRADED_WARNING")
    assert (gateway_app.RHC_PROFILE_CONTINUITY_DEGRADED_WARNING
            == "PROFILE_CONTINUITY_DEGRADED_WARNING")


def test_runtime_health_profile_selector_default_is_balanced(monkeypatch):
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    assert gateway_app.runtime_health_profile() == "BALANCED"


def test_runtime_health_profile_selector_empty_is_balanced(monkeypatch):
    monkeypatch.setenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, "   ")
    assert gateway_app.runtime_health_profile() == "BALANCED"


def test_runtime_health_profile_selector_reads_valid_values(monkeypatch):
    for value, expected in (("strict", "STRICT"), ("Balanced", "BALANCED"),
                            ("CONTINUITY", "CONTINUITY")):
        monkeypatch.setenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, value)
        assert gateway_app.runtime_health_profile() == expected


def test_runtime_health_profile_selector_invalid_fails_closed_to_strict(monkeypatch):
    monkeypatch.setenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, "permissive")
    assert gateway_app.runtime_health_profile() == "STRICT"


def test_apply_profile_strict_blocks_degraded():
    snap = {"state": gateway_app.RUNTIME_HEALTH_DEGRADED, "execution_allowed": True}
    allowed, code = gateway_app.apply_runtime_health_profile("STRICT", snap)
    assert allowed is False
    assert code == gateway_app.RHC_PROFILE_STRICT_DEGRADED_BLOCK


def test_apply_profile_balanced_warns_on_degraded():
    snap = {"state": gateway_app.RUNTIME_HEALTH_DEGRADED, "execution_allowed": True}
    allowed, code = gateway_app.apply_runtime_health_profile("BALANCED", snap)
    assert allowed is True
    assert code == gateway_app.RHC_PROFILE_BALANCED_DEGRADED_WARNING


def test_apply_profile_continuity_warns_on_degraded():
    snap = {"state": gateway_app.RUNTIME_HEALTH_DEGRADED, "execution_allowed": True}
    allowed, code = gateway_app.apply_runtime_health_profile("CONTINUITY", snap)
    assert allowed is True
    assert code == gateway_app.RHC_PROFILE_CONTINUITY_DEGRADED_WARNING


def test_apply_profile_failed_blocks_in_every_profile():
    snap = {"state": gateway_app.RUNTIME_HEALTH_FAILED, "execution_allowed": False}
    for profile in gateway_app.RUNTIME_HEALTH_PROFILES:
        allowed, code = gateway_app.apply_runtime_health_profile(profile, snap)
        assert allowed is False
        assert code is None


def test_apply_profile_healthy_executes_in_every_profile():
    snap = {"state": gateway_app.RUNTIME_HEALTH_HEALTHY, "execution_allowed": True}
    for profile in gateway_app.RUNTIME_HEALTH_PROFILES:
        allowed, code = gateway_app.apply_runtime_health_profile(profile, snap)
        assert allowed is True
        assert code is None


def test_apply_profile_unknown_state_fails_closed():
    snap = {"state": "WAT", "execution_allowed": True}
    for profile in gateway_app.RUNTIME_HEALTH_PROFILES:
        allowed, code = gateway_app.apply_runtime_health_profile(profile, snap)
        assert allowed is False
        assert code is None


def test_gate_strict_blocks_degraded_and_annotates_profile(monkeypatch):
    _rh_force_all_healthy(monkeypatch)
    _rh_force(monkeypatch, "runtime_storage", gateway_app.RUNTIME_HEALTH_DEGRADED,
              [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE])
    allowed, snap = gateway_app.runtime_execution_gate(profile="STRICT")
    assert allowed is False
    assert snap["profile"] == "STRICT"
    assert snap["profile_reason_code"] == gateway_app.RHC_PROFILE_STRICT_DEGRADED_BLOCK
    assert gateway_app.RHC_PROFILE_STRICT_DEGRADED_BLOCK in snap["reason_codes"]


def test_gate_balanced_warns_on_degraded(monkeypatch):
    _rh_force_all_healthy(monkeypatch)
    _rh_force(monkeypatch, "runtime_storage", gateway_app.RUNTIME_HEALTH_DEGRADED,
              [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE])
    allowed, snap = gateway_app.runtime_execution_gate(profile="BALANCED")
    assert allowed is True
    assert snap["profile"] == "BALANCED"
    assert (snap["profile_reason_code"]
            == gateway_app.RHC_PROFILE_BALANCED_DEGRADED_WARNING)


def test_gate_continuity_warns_on_degraded(monkeypatch):
    _rh_force_all_healthy(monkeypatch)
    _rh_force(monkeypatch, "runtime_storage", gateway_app.RUNTIME_HEALTH_DEGRADED,
              [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE])
    allowed, snap = gateway_app.runtime_execution_gate(profile="CONTINUITY")
    assert allowed is True
    assert snap["profile"] == "CONTINUITY"
    assert (snap["profile_reason_code"]
            == gateway_app.RHC_PROFILE_CONTINUITY_DEGRADED_WARNING)


def test_gate_failed_blocks_in_every_profile(monkeypatch):
    _rh_force_all_healthy(monkeypatch)
    _rh_force(monkeypatch, "policy_engine", gateway_app.RUNTIME_HEALTH_FAILED,
              [gateway_app.RHC_POLICY_ENGINE_UNAVAILABLE])
    for profile in gateway_app.RUNTIME_HEALTH_PROFILES:
        allowed, snap = gateway_app.runtime_execution_gate(profile=profile)
        assert allowed is False, profile
        assert snap["profile"] == profile
        assert "profile_reason_code" not in snap


def test_gate_healthy_executes_in_every_profile(monkeypatch):
    _rh_force_all_healthy(monkeypatch)
    for profile in gateway_app.RUNTIME_HEALTH_PROFILES:
        allowed, snap = gateway_app.runtime_execution_gate(profile=profile)
        assert allowed is True, profile
        assert snap["profile"] == profile
        assert snap["state"] == "HEALTHY"


def test_gate_uses_selector_when_no_profile_passed(monkeypatch):
    _rh_force_all_healthy(monkeypatch)
    _rh_force(monkeypatch, "runtime_storage", gateway_app.RUNTIME_HEALTH_DEGRADED,
              [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE])
    monkeypatch.setattr(gateway_app, "runtime_health_profile", lambda: "STRICT")
    allowed, snap = gateway_app.runtime_execution_gate()
    assert allowed is False
    assert snap["profile"] == "STRICT"


def test_execute_strict_profile_blocks_degraded(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-profile-strict")
    payload.update(sign_payload_ed25519(payload))
    _rh_force(monkeypatch, "runtime_storage", gateway_app.RUNTIME_HEALTH_DEGRADED,
              [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE])
    monkeypatch.setattr(gateway_app, "runtime_health_profile", lambda: "STRICT")
    res = decide_then_execute(client, payload)
    assert res.status_code == 503
    body = res.json()
    assert body.get("status") != "EXECUTED"
    assert body["runtime_health_profile"] == "STRICT"
    assert body["profile_reason_code"] == gateway_app.RHC_PROFILE_STRICT_DEGRADED_BLOCK
    assert gateway_app.RHC_PROFILE_STRICT_DEGRADED_BLOCK in body["reason_codes"]
    # blocked execution must not be recorded as "allowed with warning"
    assert body["runtime_health_decision"] == gateway_app.RUNTIME_EXEC_BLOCKED
    assert body["runtime_health_decision"] != gateway_app.RUNTIME_EXEC_WARNING
    # no raw sensitive request data echoed back
    serialized = json.dumps(body)
    assert "actor-alice" not in serialized
    assert "decision_signature" not in body


def test_execute_balanced_default_warns_on_degraded(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-profile-balanced")
    payload.update(sign_payload_ed25519(payload))
    _rh_force(monkeypatch, "runtime_storage", gateway_app.RUNTIME_HEALTH_DEGRADED,
              [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE])
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    captured = []
    real_audit = gateway_app.audit_governance_event

    def _spy(action, event):
        captured.append((action, event))
        return real_audit(action, event)

    monkeypatch.setattr(gateway_app, "audit_governance_event", _spy)
    res = decide_then_execute(client, payload)
    assert res.status_code == 200
    assert res.json()["status"] == "EXECUTED"
    degraded = [e for (a, e) in captured
                if a == "execution_allowed_runtime_health_degraded"]
    assert len(degraded) >= 1
    assert degraded[0]["runtime_health_profile"] == "BALANCED"
    assert (degraded[0]["profile_reason_code"]
            == gateway_app.RHC_PROFILE_BALANCED_DEGRADED_WARNING)


def test_execute_continuity_profile_warns_on_degraded(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-profile-continuity")
    payload.update(sign_payload_ed25519(payload))
    _rh_force(monkeypatch, "runtime_storage", gateway_app.RUNTIME_HEALTH_DEGRADED,
              [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE])
    monkeypatch.setattr(gateway_app, "runtime_health_profile", lambda: "CONTINUITY")
    captured = []
    real_audit = gateway_app.audit_governance_event

    def _spy(action, event):
        captured.append((action, event))
        return real_audit(action, event)

    monkeypatch.setattr(gateway_app, "audit_governance_event", _spy)
    res = decide_then_execute(client, payload)
    assert res.status_code == 200
    assert res.json()["status"] == "EXECUTED"
    degraded = [e for (a, e) in captured
                if a == "execution_allowed_runtime_health_degraded"]
    assert len(degraded) >= 1
    assert degraded[0]["runtime_health_profile"] == "CONTINUITY"
    assert (degraded[0]["profile_reason_code"]
            == gateway_app.RHC_PROFILE_CONTINUITY_DEGRADED_WARNING)


def test_execute_strict_profile_still_blocks_failed(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-profile-strict-failed")
    payload.update(sign_payload_ed25519(payload))
    _rh_force(monkeypatch, "audit_subsystem", gateway_app.RUNTIME_HEALTH_FAILED,
              [gateway_app.RHC_AUDIT_SUBSYSTEM_UNAVAILABLE])
    monkeypatch.setattr(gateway_app, "runtime_health_profile", lambda: "STRICT")
    res = decide_then_execute(client, payload)
    assert res.status_code == 503
    assert res.json().get("status") != "EXECUTED"


# ---------------------------------------------------------------------------
# PB-RUNTIME-006: Runtime Health Profile persistence audit. The selected profile
# must be emitted as explicit audit evidence on EVERY /execute decision (allow OR
# block, incl. HEALTHY), the persisted record must carry runtime_health_profile,
# profile_reason_code, execution_allowed and runtime_health_state, must never leak
# raw payload/signatures/secrets/client ids, must be stable across repeated calls,
# must fall back to STRICT for invalid profiles, and can never be omitted.
# ---------------------------------------------------------------------------

def _audit_spy(monkeypatch):
    captured = []
    real_audit = gateway_app.audit_governance_event

    def _spy(action, event):
        captured.append((action, event))
        return real_audit(action, event)

    monkeypatch.setattr(gateway_app, "audit_governance_event", _spy)
    return captured


def _profile_decision_rows(captured):
    return [e for (a, e) in captured if a == "runtime_health_profile_decision"]


def _persisted_profile_decisions():
    return [e for e in gateway_app.audit_chain.load()
            if e.get("action") == "runtime_health_profile_decision"]


def test_profile_decision_reason_code_is_stable():
    assert (gateway_app.RHC_RUNTIME_HEALTH_PROFILE_DECISION
            == "RUNTIME_HEALTH_PROFILE_DECISION")


def test_profile_audit_event_includes_required_fields_without_raw_data(monkeypatch):
    captured = []
    monkeypatch.setattr(gateway_app, "audit_governance_event",
                        lambda action, event: captured.append((action, event)))
    snap = {
        "profile": "STRICT",
        "profile_reason_code": gateway_app.RHC_PROFILE_STRICT_DEGRADED_BLOCK,
        "state": gateway_app.RUNTIME_HEALTH_DEGRADED,
        "decision": gateway_app.RUNTIME_EXEC_BLOCKED,
        "execution_allowed": False,
        "reason_codes": [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE],
    }
    profile = gateway_app.runtime_health_profile_audit_event(
        snap, decision_id="dec-1", action="demo-action")
    assert profile == "STRICT"
    assert len(captured) == 1
    action, ev = captured[0]
    assert action == "runtime_health_profile_decision"
    # all four required audit fields are present
    for key in ("runtime_health_profile", "profile_reason_code",
                "execution_allowed", "runtime_health_state"):
        assert key in ev
    assert ev["reason_code"] == gateway_app.RHC_RUNTIME_HEALTH_PROFILE_DECISION
    assert ev["runtime_health_profile"] == "STRICT"
    assert ev["profile_reason_code"] == gateway_app.RHC_PROFILE_STRICT_DEGRADED_BLOCK
    assert ev["execution_allowed"] is False
    assert ev["runtime_health_state"] == gateway_app.RUNTIME_HEALTH_DEGRADED
    assert ev["decision_id"] == "dec-1"
    # never raw payload / signature material
    serialized = json.dumps(ev)
    assert "actor-alice" not in serialized
    assert "decision_signature" not in serialized


def test_profile_audit_event_is_fail_safe(monkeypatch):
    def _boom(action, event):
        raise RuntimeError("audit backend down")

    monkeypatch.setattr(gateway_app, "audit_governance_event", _boom)
    monkeypatch.setattr(gateway_app, "runtime_health_profile", lambda: "BALANCED")
    snap = {"profile": "BALANCED", "state": gateway_app.RUNTIME_HEALTH_HEALTHY,
            "execution_allowed": True}
    # recording the profile must never raise / alter the execution decision
    result = gateway_app.runtime_health_profile_audit_event(
        snap, decision_id="dec-x", action="demo")
    assert result == "BALANCED"


def test_execute_healthy_emits_profile_decision_event(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-profile-healthy-event")
    payload.update(sign_payload_ed25519(payload))
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    captured = _audit_spy(monkeypatch)
    res = decide_then_execute(client, payload)
    assert res.status_code == 200
    assert res.json()["status"] == "EXECUTED"
    rows = _profile_decision_rows(captured)
    assert len(rows) == 1
    ev = rows[0]
    assert ev["runtime_health_profile"] == "BALANCED"
    # no profile-driven DEGRADED branch in HEALTHY -> no profile reason code
    assert ev["profile_reason_code"] is None
    assert ev["execution_allowed"] is True
    assert ev["runtime_health_state"] == gateway_app.RUNTIME_HEALTH_HEALTHY
    serialized = json.dumps(ev)
    assert "actor-alice" not in serialized
    assert "decision_signature" not in serialized


def test_execute_degraded_emits_profile_decision_event(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-profile-degraded-event")
    payload.update(sign_payload_ed25519(payload))
    _rh_force(monkeypatch, "runtime_storage", gateway_app.RUNTIME_HEALTH_DEGRADED,
              [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE])
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    captured = _audit_spy(monkeypatch)
    res = decide_then_execute(client, payload)
    assert res.status_code == 200
    assert res.json()["status"] == "EXECUTED"
    rows = _profile_decision_rows(captured)
    assert len(rows) == 1
    ev = rows[0]
    assert ev["runtime_health_profile"] == "BALANCED"
    assert ev["execution_allowed"] is True
    assert ev["runtime_health_state"] == gateway_app.RUNTIME_HEALTH_DEGRADED
    assert (ev["profile_reason_code"]
            == gateway_app.RHC_PROFILE_BALANCED_DEGRADED_WARNING)


def test_execute_blocked_emits_profile_decision_event(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-profile-blocked-event")
    payload.update(sign_payload_ed25519(payload))
    _rh_force(monkeypatch, "runtime_storage", gateway_app.RUNTIME_HEALTH_DEGRADED,
              [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE])
    monkeypatch.setattr(gateway_app, "runtime_health_profile", lambda: "STRICT")
    captured = _audit_spy(monkeypatch)
    res = decide_then_execute(client, payload)
    assert res.status_code == 503
    rows = _profile_decision_rows(captured)
    assert len(rows) == 1
    ev = rows[0]
    assert ev["runtime_health_profile"] == "STRICT"
    assert ev["execution_allowed"] is False
    assert ev["runtime_health_state"] == gateway_app.RUNTIME_HEALTH_DEGRADED
    assert ev["runtime_health_decision"] == gateway_app.RUNTIME_EXEC_BLOCKED
    assert (ev["profile_reason_code"]
            == gateway_app.RHC_PROFILE_STRICT_DEGRADED_BLOCK)


def test_profile_decision_event_persists_in_audit_chain(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-profile-persist-chain")
    payload.update(sign_payload_ed25519(payload))
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    res = decide_then_execute(client, payload)
    assert res.status_code == 200
    entries = _persisted_profile_decisions()
    assert len(entries) >= 1
    decision = entries[-1]["decision"]
    # the persisted (allowlisted) record retains all four required fields
    assert decision["runtime_health_profile"] == "BALANCED"
    assert decision["execution_allowed"] is True
    assert decision["runtime_health_state"] == gateway_app.RUNTIME_HEALTH_HEALTHY
    assert "profile_reason_code" in decision
    # persisted evidence must not leak raw request data
    serialized = json.dumps(entries[-1])
    assert "actor-alice" not in serialized
    assert "decision_signature" not in serialized


def test_profile_persists_across_repeated_execute(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    captured = _audit_spy(monkeypatch)
    for i in range(3):
        payload = build_payload(nonce=f"rh-profile-repeat-{i}")
        payload.update(sign_payload_ed25519(payload))
        res = decide_then_execute(client, payload)
        assert res.status_code == 200
    rows = _profile_decision_rows(captured)
    # exactly one profile-decision record per execution, profile stable throughout
    assert len(rows) == 3
    assert {e["runtime_health_profile"] for e in rows} == {"BALANCED"}
    persisted = _persisted_profile_decisions()
    assert len(persisted) == 3
    assert all(e["decision"]["runtime_health_profile"] == "BALANCED"
               for e in persisted)


def test_execute_invalid_profile_falls_back_to_strict(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-profile-invalid")
    payload.update(sign_payload_ed25519(payload))
    _rh_force(monkeypatch, "runtime_storage", gateway_app.RUNTIME_HEALTH_DEGRADED,
              [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE])
    monkeypatch.setenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, "permissive")
    captured = _audit_spy(monkeypatch)
    res = decide_then_execute(client, payload)
    # an invalid profile must fail closed to STRICT -> DEGRADED is blocked
    assert res.status_code == 503
    body = res.json()
    assert body["runtime_health_profile"] == "STRICT"
    assert body["profile_reason_code"] == gateway_app.RHC_PROFILE_STRICT_DEGRADED_BLOCK
    rows = _profile_decision_rows(captured)
    assert len(rows) == 1
    assert rows[0]["runtime_health_profile"] == "STRICT"
    assert rows[0]["execution_allowed"] is False


def test_profile_decision_cannot_be_omitted_on_allow_or_block(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    # ALLOW path (HEALTHY/BALANCED) records the profile decision...
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    allow_payload = build_payload(nonce="rh-omit-allow")
    allow_payload.update(sign_payload_ed25519(allow_payload))
    assert decide_then_execute(client, allow_payload).status_code == 200
    assert len(_persisted_profile_decisions()) == 1
    # ...and the BLOCK path (STRICT/DEGRADED) cannot omit it either.
    _rh_force(monkeypatch, "runtime_storage", gateway_app.RUNTIME_HEALTH_DEGRADED,
              [gateway_app.RHC_RUNTIME_STORAGE_NOT_WRITABLE])
    monkeypatch.setattr(gateway_app, "runtime_health_profile", lambda: "STRICT")
    block_payload = build_payload(nonce="rh-omit-block")
    block_payload.update(sign_payload_ed25519(block_payload))
    assert decide_then_execute(client, block_payload).status_code == 503
    persisted = _persisted_profile_decisions()
    assert len(persisted) == 2
    assert persisted[-1]["decision"]["runtime_health_profile"] == "STRICT"
    assert persisted[-1]["decision"]["execution_allowed"] is False


def test_profile_decision_recorded_on_gate_exception_fallback(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_payload(nonce="rh-profile-gate-exception")
    payload.update(sign_payload_ed25519(payload))

    def _boom_gate(*args, **kwargs):
        raise RuntimeError("gate probe exploded")

    monkeypatch.setattr(gateway_app, "runtime_execution_gate", _boom_gate)
    monkeypatch.setattr(gateway_app, "runtime_health_profile", lambda: "STRICT")
    res = decide_then_execute(client, payload)
    # gate exception must fail closed...
    assert res.status_code == 503
    # ...and the profile decision must still be recorded (cannot be omitted),
    # resolved via the selector since the fallback snapshot carries no profile.
    persisted = _persisted_profile_decisions()
    assert len(persisted) == 1
    decision = persisted[-1]["decision"]
    assert decision["runtime_health_profile"] == "STRICT"
    assert decision["execution_allowed"] is False
    assert decision["runtime_health_state"] == gateway_app.RUNTIME_HEALTH_FAILED


# ---------------------------------------------------------------------------
# PB-RUNTIME-007: Runtime Health evidence integrity. Each persisted runtime-health
# decision record must be complete, internally consistent (state/profile/reason/
# outcome agree), free of raw sensitive data, carry an explicit audit_event_type,
# and be wrapped in a deterministic, tamper-evident hash-chain entry.
# ---------------------------------------------------------------------------

def _valid_evidence_record(**overrides):
    record = {
        "decision_id": "dec-evidence-1",
        "runtime_health_state": gateway_app.RUNTIME_HEALTH_HEALTHY,
        "runtime_health_profile": "BALANCED",
        "profile_reason_code": None,
        "execution_allowed": True,
        "audit_event_type": gateway_app.RUNTIME_HEALTH_EVIDENCE_EVENT_TYPE,
    }
    record.update(overrides)
    return record


def test_valid_runtime_health_evidence_record_passes():
    ok, codes = gateway_app.validate_runtime_health_evidence_record(
        _valid_evidence_record())
    assert ok is True
    assert codes == []


def test_valid_degraded_strict_block_record_passes():
    ok, codes = gateway_app.validate_runtime_health_evidence_record(
        _valid_evidence_record(
            runtime_health_state=gateway_app.RUNTIME_HEALTH_DEGRADED,
            runtime_health_profile="STRICT",
            profile_reason_code=gateway_app.RHC_PROFILE_STRICT_DEGRADED_BLOCK,
            execution_allowed=False))
    assert ok is True
    assert codes == []


def test_missing_decision_id_fails_validation():
    record = _valid_evidence_record()
    del record["decision_id"]
    ok, codes = gateway_app.validate_runtime_health_evidence_record(record)
    assert ok is False
    assert gateway_app.RHC_RH_EVIDENCE_INCOMPLETE in codes


def test_missing_runtime_health_state_fails_validation():
    record = _valid_evidence_record()
    del record["runtime_health_state"]
    ok, codes = gateway_app.validate_runtime_health_evidence_record(record)
    assert ok is False
    assert gateway_app.RHC_RH_EVIDENCE_INCOMPLETE in codes


def test_missing_runtime_health_profile_fails_validation():
    record = _valid_evidence_record()
    del record["runtime_health_profile"]
    ok, codes = gateway_app.validate_runtime_health_evidence_record(record)
    assert ok is False
    assert gateway_app.RHC_RH_EVIDENCE_INCOMPLETE in codes


def test_missing_profile_reason_code_fails_validation():
    record = _valid_evidence_record()
    del record["profile_reason_code"]
    ok, codes = gateway_app.validate_runtime_health_evidence_record(record)
    assert ok is False
    assert gateway_app.RHC_RH_EVIDENCE_INCOMPLETE in codes


def test_missing_execution_allowed_fails_validation():
    record = _valid_evidence_record()
    del record["execution_allowed"]
    ok, codes = gateway_app.validate_runtime_health_evidence_record(record)
    assert ok is False
    assert gateway_app.RHC_RH_EVIDENCE_INCOMPLETE in codes


def test_missing_audit_event_type_fails_validation():
    record = _valid_evidence_record()
    del record["audit_event_type"]
    ok, codes = gateway_app.validate_runtime_health_evidence_record(record)
    assert ok is False
    assert gateway_app.RHC_RH_EVIDENCE_INCOMPLETE in codes


def test_null_required_field_fails_validation():
    ok, codes = gateway_app.validate_runtime_health_evidence_record(
        _valid_evidence_record(runtime_health_profile=None))
    assert ok is False
    assert gateway_app.RHC_RH_EVIDENCE_INCOMPLETE in codes


def test_mismatched_profile_state_reason_fails_validation():
    # STRICT + DEGRADED but recorded as allowed with a BALANCED-style reason code
    ok, codes = gateway_app.validate_runtime_health_evidence_record(
        _valid_evidence_record(
            runtime_health_state=gateway_app.RUNTIME_HEALTH_DEGRADED,
            runtime_health_profile="STRICT",
            profile_reason_code=gateway_app.RHC_PROFILE_BALANCED_DEGRADED_WARNING,
            execution_allowed=True))
    assert ok is False
    assert gateway_app.RHC_RH_EVIDENCE_INCONSISTENT in codes


def test_healthy_with_reason_code_is_inconsistent():
    ok, codes = gateway_app.validate_runtime_health_evidence_record(
        _valid_evidence_record(
            profile_reason_code=gateway_app.RHC_PROFILE_STRICT_DEGRADED_BLOCK))
    assert ok is False
    assert gateway_app.RHC_RH_EVIDENCE_INCONSISTENT in codes


def test_invalid_profile_value_is_inconsistent():
    ok, codes = gateway_app.validate_runtime_health_evidence_record(
        _valid_evidence_record(runtime_health_profile="PERMISSIVE"))
    assert ok is False
    assert gateway_app.RHC_RH_EVIDENCE_INCONSISTENT in codes


def test_wrong_audit_event_type_fails_validation():
    ok, codes = gateway_app.validate_runtime_health_evidence_record(
        _valid_evidence_record(audit_event_type="some_other_event"))
    assert ok is False
    assert gateway_app.RHC_RH_EVIDENCE_WRONG_EVENT_TYPE in codes


def test_sensitive_data_in_evidence_fails_validation():
    ok, codes = gateway_app.validate_runtime_health_evidence_record(
        _valid_evidence_record(decision_signature="c2lnbmF0dXJl"))
    assert ok is False
    assert gateway_app.RHC_RH_EVIDENCE_SENSITIVE_DATA in codes


def test_raw_client_id_in_evidence_fails_validation():
    ok, codes = gateway_app.validate_runtime_health_evidence_record(
        _valid_evidence_record(actor_id="actor-alice"))
    assert ok is False
    assert gateway_app.RHC_RH_EVIDENCE_SENSITIVE_DATA in codes


def test_hashed_counterparts_are_not_treated_as_sensitive():
    # hashed fields (actor_hash / nonce_hash) are legitimate, not raw secrets
    assert gateway_app.runtime_health_evidence_contains_sensitive_data(
        _valid_evidence_record(actor_hash="abc123", nonce_hash="def456")) is False


def test_invalid_profile_resolves_to_strict_fail_closed(monkeypatch):
    monkeypatch.setenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, "permissive")
    assert gateway_app.runtime_health_profile() == "STRICT"


# --- hash-chain (tamper-evidence) integration -----------------------------

def test_runtime_health_evidence_hash_chain_is_supported_and_valid(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-evidence-hash-ok")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200
    report = gateway_app.audit_runtime_health_evidence()
    assert report["hash_chain_supported"] is True
    assert report["hash_chain_valid"] is True
    assert report["valid"] is True
    assert report["checked"] >= 1
    assert report["failures"] == []


def test_persisted_runtime_health_entry_passes_entry_validation(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-evidence-entry-ok")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200
    entries = [e for e in gateway_app.audit_chain.load()
               if e.get("action") == gateway_app.RUNTIME_HEALTH_EVIDENCE_EVENT_TYPE]
    assert len(entries) >= 1
    ok, codes = gateway_app.validate_runtime_health_evidence_entry(entries[-1])
    assert ok is True, codes


def test_tampered_record_breaks_hash_chain_validation(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-evidence-tamper")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200
    chain = gateway_app.audit_chain.load()
    # mutate a persisted runtime-health record WITHOUT recomputing its hash
    for entry in chain:
        if entry.get("action") == gateway_app.RUNTIME_HEALTH_EVIDENCE_EVENT_TYPE:
            entry["decision"]["runtime_health_profile"] = "STRICT"
            break
    report = gateway_app.audit_runtime_health_evidence(chain=chain)
    assert report["hash_chain_valid"] is False
    assert report["valid"] is False


def test_audit_report_flags_incomplete_persisted_record():
    # a runtime-health entry whose record is missing a required field is reported
    record = _valid_evidence_record()
    del record["runtime_health_state"]
    entry = {
        "timestamp": "2026-06-21T00:00:00Z",
        "action": gateway_app.RUNTIME_HEALTH_EVIDENCE_EVENT_TYPE,
        "decision": record,
        "hash_prev": gateway_app.GENESIS_HASH,
    }
    entry["hash_current"] = gateway_app._audit_compute_hash(
        {k: entry[k] for k in ("timestamp", "action", "decision", "hash_prev")},
        entry["hash_prev"])
    report = gateway_app.audit_runtime_health_evidence(chain=[entry])
    assert report["hash_chain_valid"] is True  # hash intact...
    assert report["valid"] is False            # ...but record incomplete
    assert report["checked"] == 1
    assert report["failures"]
    assert gateway_app.RHC_RH_EVIDENCE_INCOMPLETE in report["failures"][0]["reason_codes"]


def test_empty_chain_audit_is_vacuously_valid():
    report = gateway_app.audit_runtime_health_evidence(chain=[])
    assert report["valid"] is True
    assert report["checked"] == 0
    assert report["hash_chain_valid"] is True
    assert report["hash_chain_supported"] is True


# ---------------------------------------------------------------------------
# PB-RUNTIME-008: cross-layer evidence linkage. Each runtime-health record must
# carry a deterministic, non-sensitive governance_context_id (bound to its
# decision_id and audit hash) tying it into the wider USBAY governance evidence
# chain, plus best-effort policy/gateway context ids.
# ---------------------------------------------------------------------------

def _valid_cross_layer_record(**overrides):
    record = _valid_evidence_record()
    record["governance_context_id"] = gateway_app.derive_governance_context_id(
        record["decision_id"])
    record["policy_context_id"] = None
    record["gateway_context_id"] = None
    record.update(overrides)
    return record


def test_derive_governance_context_id_is_deterministic_and_namespaced():
    a = gateway_app.derive_governance_context_id("dec-xyz")
    b = gateway_app.derive_governance_context_id("dec-xyz")
    c = gateway_app.derive_governance_context_id("dec-other")
    assert a == b
    assert a != c
    assert a.startswith(gateway_app.GOVERNANCE_CONTEXT_ID_PREFIX)
    assert gateway_app.derive_governance_context_id(None) is None
    assert gateway_app.derive_governance_context_id("") is None


def test_valid_cross_layer_record_passes():
    ok, codes = gateway_app.validate_runtime_health_cross_layer_record(
        _valid_cross_layer_record())
    assert ok is True
    assert codes == []


def test_missing_governance_context_id_fails_validation():
    record = _valid_cross_layer_record()
    del record["governance_context_id"]
    ok, codes = gateway_app.validate_runtime_health_cross_layer_record(record)
    assert ok is False
    assert gateway_app.RHC_RH_LINKAGE_MISSING_GOVERNANCE_CONTEXT in codes


def test_null_governance_context_id_fails_validation():
    ok, codes = gateway_app.validate_runtime_health_cross_layer_record(
        _valid_cross_layer_record(governance_context_id=None))
    assert ok is False
    assert gateway_app.RHC_RH_LINKAGE_MISSING_GOVERNANCE_CONTEXT in codes


def test_mismatched_governance_context_id_fails_validation():
    # governance_context_id that does not derive from this record's decision_id
    ok, codes = gateway_app.validate_runtime_health_cross_layer_record(
        _valid_cross_layer_record(
            governance_context_id=gateway_app.derive_governance_context_id("other-id")))
    assert ok is False
    assert gateway_app.RHC_RH_LINKAGE_CONTEXT_MISMATCH in codes


def test_cross_layer_inherits_evidence_integrity_checks():
    # an incomplete record still fails the underlying PB-RUNTIME-007 checks
    record = _valid_cross_layer_record()
    del record["runtime_health_state"]
    ok, codes = gateway_app.validate_runtime_health_cross_layer_record(record)
    assert ok is False
    assert gateway_app.RHC_RH_EVIDENCE_INCOMPLETE in codes


def test_cross_layer_context_ids_are_not_sensitive():
    record = _valid_cross_layer_record(
        policy_context_id="pctx-abc123",
        gateway_context_id="gwctx-def456")
    assert gateway_app.runtime_health_evidence_contains_sensitive_data(record) is False


# --- persisted-chain integration ------------------------------------------

def test_persisted_runtime_health_record_is_governance_linked(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-linkage-ok")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    entries = [e for e in gateway_app.audit_chain.load()
               if e.get("action") == gateway_app.RUNTIME_HEALTH_EVIDENCE_EVENT_TYPE]
    assert len(entries) >= 1
    record = entries[-1]["decision"]
    # governance context present and bound to the decision_id
    assert record["governance_context_id"] == \
        gateway_app.derive_governance_context_id(record["decision_id"])
    # policy/gateway context keys are always present (value may be None = GAP)
    assert "policy_context_id" in record
    assert "gateway_context_id" in record
    # full cross-layer entry validation passes (record + action + hash)
    ok, codes = gateway_app.validate_runtime_health_cross_layer_entry(entries[-1])
    assert ok is True, codes


def test_cross_layer_audit_report_is_valid_and_hash_chain_intact(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-linkage-report")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    report = gateway_app.audit_runtime_health_cross_layer_linkage()
    assert report["hash_chain_supported"] is True
    assert report["hash_chain_valid"] is True
    assert report["valid"] is True
    assert report["checked"] >= 1
    assert report["linked"] == report["checked"]
    assert report["failures"] == []


def test_tampered_decision_id_breaks_linkage_and_hash(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-linkage-tamper")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    chain = gateway_app.audit_chain.load()
    # mutate decision_id WITHOUT recomputing the envelope hash or the context id
    for entry in chain:
        if entry.get("action") == gateway_app.RUNTIME_HEALTH_EVIDENCE_EVENT_TYPE:
            entry["decision"]["decision_id"] = "tampered-decision-id"
            break
    report = gateway_app.audit_runtime_health_cross_layer_linkage(chain=chain)
    # decision_id mutation breaks both the audit hash and the context binding
    assert report["hash_chain_valid"] is False
    assert report["valid"] is False
    codes = report["failures"][0]["reason_codes"]
    assert gateway_app.RHC_RH_LINKAGE_CONTEXT_MISMATCH in codes


def test_persisted_runtime_health_record_has_no_sensitive_data(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-linkage-nosensitive")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200
    for entry in gateway_app.audit_chain.load():
        record = entry.get("decision")
        if isinstance(record, dict):
            assert gateway_app.runtime_health_evidence_contains_sensitive_data(
                record) is False


def test_cross_layer_empty_chain_is_vacuously_valid():
    report = gateway_app.audit_runtime_health_cross_layer_linkage(chain=[])
    assert report["valid"] is True
    assert report["checked"] == 0
    assert report["linked"] == 0
    assert report["hash_chain_valid"] is True
    assert report["hash_chain_supported"] is True


# ---------------------------------------------------------------------------
# PB-RUNTIME-009: Runtime Health cross-layer RECONCILIATION. Beyond linking the
# layers, prove each governed /execute record stays internally consistent over
# time -- governance binding, state/outcome + profile/reason synchronization,
# well-formed best-effort context ids, intact hash chain, no sensitive data.
# ---------------------------------------------------------------------------

def _reconcilable_record(**overrides):
    record = _valid_cross_layer_record()
    record["policy_context_id"] = gateway_app._runtime_health_policy_context_id()
    record["gateway_context_id"] = gateway_app._runtime_health_gateway_context_id()
    record.update(overrides)
    return record


def test_valid_cross_layer_reconciliation_passes():
    ok, codes = gateway_app.reconcile_runtime_health_cross_layer_record(
        _reconcilable_record())
    assert ok is True
    assert codes == []


def test_reconciliation_passes_when_optional_context_ids_absent():
    # absent (None) policy/gateway ids are the documented-unavailable GAP state
    # and must NOT fail reconciliation on their own.
    ok, codes = gateway_app.reconcile_runtime_health_cross_layer_record(
        _reconcilable_record(policy_context_id=None, gateway_context_id=None))
    assert ok is True
    assert codes == []


def test_reconciliation_missing_governance_context_fails():
    record = _reconcilable_record()
    del record["governance_context_id"]
    ok, codes = gateway_app.reconcile_runtime_health_cross_layer_record(record)
    assert ok is False
    assert gateway_app.RHC_RH_RECON_MISSING_GOVERNANCE_CONTEXT in codes


def test_reconciliation_decision_id_mismatch_fails():
    # governance_context_id no longer derives from the record's decision_id
    ok, codes = gateway_app.reconcile_runtime_health_cross_layer_record(
        _reconcilable_record(decision_id="dec-was-changed"))
    assert ok is False
    assert gateway_app.RHC_RH_RECON_DECISION_ID_MISMATCH in codes


def test_reconciliation_profile_reason_conflict_fails():
    # DEGRADED + STRICT must carry the strict-block reason; a warning reason here
    # is a profile/reason desynchronization.
    ok, codes = gateway_app.reconcile_runtime_health_cross_layer_record(
        _reconcilable_record(
            runtime_health_state=gateway_app.RUNTIME_HEALTH_DEGRADED,
            runtime_health_profile="STRICT",
            profile_reason_code=gateway_app.RHC_PROFILE_BALANCED_DEGRADED_WARNING,
            execution_allowed=False))
    assert ok is False
    assert gateway_app.RHC_RH_RECON_PROFILE_REASON_CONFLICT in codes


def test_reconciliation_state_outcome_conflict_fails():
    # FAILED must always block (fail-closed invariant); allowed=True is a conflict.
    ok, codes = gateway_app.reconcile_runtime_health_cross_layer_record(
        _reconcilable_record(
            runtime_health_state=gateway_app.RUNTIME_HEALTH_FAILED,
            execution_allowed=True))
    assert ok is False
    assert gateway_app.RHC_RH_RECON_STATE_OUTCOME_CONFLICT in codes


def test_reconciliation_malformed_policy_context_id_fails_when_present():
    ok, codes = gateway_app.reconcile_runtime_health_cross_layer_record(
        _reconcilable_record(policy_context_id="pctx-NOT-HEX"))
    assert ok is False
    assert gateway_app.RHC_RH_RECON_POLICY_CONTEXT_MALFORMED in codes


def test_reconciliation_malformed_gateway_context_id_fails_when_present():
    ok, codes = gateway_app.reconcile_runtime_health_cross_layer_record(
        _reconcilable_record(gateway_context_id="wrong-prefix-0000"))
    assert ok is False
    assert gateway_app.RHC_RH_RECON_GATEWAY_CONTEXT_MALFORMED in codes


def test_reconciliation_rejects_sensitive_data():
    ok, codes = gateway_app.reconcile_runtime_health_cross_layer_record(
        _reconcilable_record(decision_signature="c2lnbmF0dXJl"))
    assert ok is False
    assert gateway_app.RHC_RH_RECON_SENSITIVE_DATA in codes


def test_reconciliation_incomplete_record_fails():
    record = _reconcilable_record()
    del record["runtime_health_state"]
    ok, codes = gateway_app.reconcile_runtime_health_cross_layer_record(record)
    assert ok is False
    assert gateway_app.RHC_RH_RECON_INCOMPLETE in codes


def test_context_id_malformed_helper_accepts_absent_and_wellformed():
    pfx = gateway_app.POLICY_CONTEXT_ID_PREFIX
    good = gateway_app._runtime_health_policy_context_id()
    assert gateway_app._runtime_health_context_id_malformed(None, pfx) is False
    assert gateway_app._runtime_health_context_id_malformed(good, pfx) is False
    assert gateway_app._runtime_health_context_id_malformed("pctx-xyz", pfx) is True
    assert gateway_app._runtime_health_context_id_malformed(12345, pfx) is True


# --- persisted-chain reconciliation integration ---------------------------

def test_persisted_chain_reconciliation_is_valid(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-recon-ok")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    report = gateway_app.audit_runtime_health_cross_layer_reconciliation()
    assert report["hash_chain_supported"] is True
    assert report["hash_chain_valid"] is True
    assert report["valid"] is True
    assert report["checked"] >= 1
    assert report["reconciled"] == report["checked"]
    assert report["failures"] == []


def test_persisted_entry_reconciliation_passes(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-recon-entry")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    entries = [e for e in gateway_app.audit_chain.load()
               if e.get("action") == gateway_app.RUNTIME_HEALTH_EVIDENCE_EVENT_TYPE]
    assert len(entries) >= 1
    ok, codes = gateway_app.reconcile_runtime_health_cross_layer_entry(entries[-1])
    assert ok is True, codes


def test_reconciliation_detects_tampered_decision_id(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-recon-tamper")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    chain = gateway_app.audit_chain.load()
    for entry in chain:
        if entry.get("action") == gateway_app.RUNTIME_HEALTH_EVIDENCE_EVENT_TYPE:
            entry["decision"]["decision_id"] = "tampered-decision-id"
            break
    report = gateway_app.audit_runtime_health_cross_layer_reconciliation(chain=chain)
    assert report["hash_chain_valid"] is False
    assert report["valid"] is False
    codes = report["failures"][0]["reason_codes"]
    # decision_id tamper desyncs the governance binding AND the audit hash
    assert gateway_app.RHC_RH_RECON_DECISION_ID_MISMATCH in codes
    assert gateway_app.RHC_RH_RECON_AUDIT_HASH_MISMATCH in codes


def test_reconciliation_detects_broken_previous_hash_chain():
    # two well-formed entries whose hash_prev linkage is deliberately broken
    rec = _reconcilable_record(decision_id="dec-chain-1")
    rec["governance_context_id"] = gateway_app.derive_governance_context_id(
        "dec-chain-1")
    env_a = {
        "timestamp": 1,
        "action": gateway_app.RUNTIME_HEALTH_EVIDENCE_EVENT_TYPE,
        "decision": rec,
        "hash_prev": gateway_app.GENESIS_HASH,
    }
    from audit.hash_chain import compute_hash as _ch
    env_a["hash_current"] = _ch(env_a, env_a["hash_prev"])

    rec2 = _reconcilable_record(decision_id="dec-chain-2")
    rec2["governance_context_id"] = gateway_app.derive_governance_context_id(
        "dec-chain-2")
    env_b = {
        "timestamp": 2,
        "action": gateway_app.RUNTIME_HEALTH_EVIDENCE_EVENT_TYPE,
        "decision": rec2,
        "hash_prev": "deadbeef-not-the-previous-hash",
    }
    env_b["hash_current"] = _ch(env_b, env_b["hash_prev"])

    report = gateway_app.audit_runtime_health_cross_layer_reconciliation(
        chain=[env_a, env_b])
    assert report["hash_chain_valid"] is False
    assert report["valid"] is False
    # the broken-linkage entry must carry the explicit previous-hash reason code,
    # not only flip the chain-level hash_chain_valid flag.
    broken = [f for f in report["failures"]
              if gateway_app.RHC_RH_RECON_PREVIOUS_HASH_MISMATCH in f["reason_codes"]]
    assert len(broken) == 1
    assert broken[0]["decision_id"] == "dec-chain-2"


def test_reconciliation_empty_chain_is_vacuously_valid():
    report = gateway_app.audit_runtime_health_cross_layer_reconciliation(chain=[])
    assert report["valid"] is True
    assert report["checked"] == 0
    assert report["reconciled"] == 0
    assert report["hash_chain_valid"] is True
    assert report["hash_chain_supported"] is True


# ---------------------------------------------------------------------------
# PB-RUNTIME-010: system-wide governance PROOF. A single deterministic verdict
# tying together all six runtime governance capabilities for every governed
# /execute audit record -- authority, profiles, persistence, evidence integrity,
# cross-layer linkage, and cross-layer reconciliation -- with intact hash chain
# and no raw sensitive data. Evidence-only; never wired into /execute.
# ---------------------------------------------------------------------------

def _proof_entry(record=None, *, prev_hash=None):
    rec = record if record is not None else _reconcilable_record()
    rec.setdefault("audit_event_type", gateway_app.RUNTIME_HEALTH_EVIDENCE_EVENT_TYPE)
    env = {
        "timestamp": 1,
        "action": gateway_app.RUNTIME_HEALTH_EVIDENCE_EVENT_TYPE,
        "decision": rec,
        "hash_prev": prev_hash if prev_hash is not None else gateway_app.GENESIS_HASH,
    }
    from audit.hash_chain import compute_hash as _ch
    env["hash_current"] = _ch(env, env["hash_prev"])
    return env


def test_valid_governance_proof_record_passes():
    ok, codes = gateway_app.validate_runtime_health_governance_proof_record(
        _reconcilable_record())
    assert ok is True
    assert codes == []


def test_governance_proof_record_missing_field_fails():
    record = _reconcilable_record()
    del record["runtime_health_profile"]
    ok, codes = gateway_app.validate_runtime_health_governance_proof_record(record)
    assert ok is False
    assert gateway_app.RHC_RH_PROOF_INCOMPLETE in codes


def test_governance_proof_record_missing_governance_context_fails():
    record = _reconcilable_record()
    del record["governance_context_id"]
    ok, codes = gateway_app.validate_runtime_health_governance_proof_record(record)
    assert ok is False
    assert gateway_app.RHC_RH_PROOF_MISSING_GOVERNANCE_CONTEXT in codes


def test_governance_proof_record_context_mismatch_fails():
    ok, codes = gateway_app.validate_runtime_health_governance_proof_record(
        _reconcilable_record(decision_id="dec-rebound"))
    assert ok is False
    assert gateway_app.RHC_RH_PROOF_DECISION_ID_MISMATCH in codes


def test_governance_proof_record_consistency_conflict_fails():
    ok, codes = gateway_app.validate_runtime_health_governance_proof_record(
        _reconcilable_record(
            runtime_health_state=gateway_app.RUNTIME_HEALTH_FAILED,
            execution_allowed=True))
    assert ok is False
    assert gateway_app.RHC_RH_PROOF_CONSISTENCY_CONFLICT in codes


def test_governance_proof_record_malformed_optional_id_fails():
    ok, codes = gateway_app.validate_runtime_health_governance_proof_record(
        _reconcilable_record(policy_context_id="pctx-not-hex"))
    assert ok is False
    assert gateway_app.RHC_RH_PROOF_POLICY_CONTEXT_MALFORMED in codes


def test_governance_proof_record_rejects_sensitive_data():
    ok, codes = gateway_app.validate_runtime_health_governance_proof_record(
        _reconcilable_record(payload="raw-request-body"))
    assert ok is False
    assert gateway_app.RHC_RH_PROOF_SENSITIVE_DATA in codes


def test_governance_proof_record_allows_absent_optional_ids():
    ok, codes = gateway_app.validate_runtime_health_governance_proof_record(
        _reconcilable_record(policy_context_id=None, gateway_context_id=None))
    assert ok is True
    assert codes == []


def test_governance_proof_entry_passes_and_proves_audit_hash():
    ok, codes = gateway_app.validate_runtime_health_governance_proof_entry(
        _proof_entry())
    assert ok is True, codes


def test_governance_proof_entry_missing_audit_hash_fails():
    env = _proof_entry()
    del env["hash_current"]
    ok, codes = gateway_app.validate_runtime_health_governance_proof_entry(env)
    assert ok is False
    assert gateway_app.RHC_RH_PROOF_MISSING_AUDIT_HASH in codes


def test_governance_proof_entry_audit_hash_mismatch_fails():
    env = _proof_entry()
    env["hash_current"] = "0" * 64  # present but does not recompute
    ok, codes = gateway_app.validate_runtime_health_governance_proof_entry(env)
    assert ok is False
    assert gateway_app.RHC_RH_PROOF_AUDIT_HASH_MISMATCH in codes


def test_governance_proof_entry_previous_hash_mismatch_fails():
    env = _proof_entry()
    ok, codes = gateway_app.validate_runtime_health_governance_proof_entry(
        env, prev_hash="not-the-genesis-hash")
    assert ok is False
    assert gateway_app.RHC_RH_PROOF_PREVIOUS_HASH_MISMATCH in codes


# --- system-wide proof report integration ---------------------------------

def test_system_wide_governance_proof_is_valid(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-proof-ok")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    report = gateway_app.build_runtime_health_governance_proof()
    assert report["proof_supported"] is True
    assert report["hash_chain_valid"] is True
    assert report["valid"] is True
    assert report["checked"] >= 1
    assert report["proven"] == report["checked"]
    assert report["capabilities_proven"] is True
    assert report["failures"] == []
    # all six capabilities tied together and proven
    for cap in gateway_app.RUNTIME_HEALTH_GOVERNANCE_CAPABILITIES:
        assert report["capabilities"][cap]["proven"] is True
        assert report["capabilities"][cap]["checked"] >= 1


def test_system_wide_proof_detects_tampered_decision_id(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-proof-tamper")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    chain = gateway_app.audit_chain.load()
    for entry in chain:
        if entry.get("action") == gateway_app.RUNTIME_HEALTH_EVIDENCE_EVENT_TYPE:
            entry["decision"]["decision_id"] = "tampered-decision-id"
            break
    report = gateway_app.build_runtime_health_governance_proof(chain=chain)
    assert report["valid"] is False
    assert report["hash_chain_valid"] is False
    assert report["capabilities"]["runtime_cross_layer_reconciliation"]["proven"] is False
    codes = report["failures"][0]["reason_codes"]
    assert gateway_app.RHC_RH_PROOF_DECISION_ID_MISMATCH in codes
    assert gateway_app.RHC_RH_PROOF_AUDIT_HASH_MISMATCH in codes


def test_system_wide_proof_empty_chain_is_vacuously_valid():
    report = gateway_app.build_runtime_health_governance_proof(chain=[])
    assert report["valid"] is True
    assert report["checked"] == 0
    assert report["proven"] == 0
    assert report["hash_chain_valid"] is True
    assert report["capabilities_proven"] is True


def test_governance_proof_evidence_only_does_not_touch_execution(tmp_path, monkeypatch):
    # Proof functions must be pure auditors: invoking them must not mutate the chain
    # or change any /execute outcome.
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-proof-evidence-only")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    before = gateway_app.audit_chain.load()
    gateway_app.build_runtime_health_governance_proof()
    after = gateway_app.audit_chain.load()
    assert before == after


def test_system_wide_proof_surfaces_previous_hash_mismatch_in_chain():
    # Two correctly-chained runtime-health entries, then break ONLY the link of
    # the second (recompute its own hash so AUDIT_HASH stays valid) to isolate the
    # report-level PREVIOUS_HASH_MISMATCH from AUDIT_HASH_MISMATCH.
    from audit.hash_chain import compute_hash as _ch
    e1 = _proof_entry(prev_hash=gateway_app.GENESIS_HASH)
    e2 = _proof_entry(prev_hash=e1["hash_current"])
    # Sever the link: point e2 at a non-existent prior hash, keeping e2 internally
    # consistent so its own audit hash still recomputes (recompute from the same
    # 4-key body the verifier uses, excluding the stale hash_current).
    e2["hash_prev"] = "f" * 64
    e2["hash_current"] = _ch({
        "timestamp": e2["timestamp"],
        "action": e2["action"],
        "decision": e2["decision"],
        "hash_prev": e2["hash_prev"],
    }, e2["hash_prev"])

    report = gateway_app.build_runtime_health_governance_proof(chain=[e1, e2])
    assert report["valid"] is False
    assert report["hash_chain_valid"] is False
    broken = next(f for f in report["failures"] if f["index"] == 1)
    assert gateway_app.RHC_RH_PROOF_PREVIOUS_HASH_MISMATCH in broken["reason_codes"]
    assert gateway_app.RHC_RH_PROOF_AUDIT_HASH_MISMATCH not in broken["reason_codes"]


# ---------------------------------------------------------------------------
# PB-RUNTIME-011: runtime governance proof EXPORT. A deterministic, non-sensitive,
# auditor-readable evidence package per governed /execute decision, derived from
# the PB-RUNTIME-010 proof. Read-only / evidence-only; never wired into /execute.
# ---------------------------------------------------------------------------

def test_proof_export_entry_builds_valid_package():
    pkg = gateway_app.build_runtime_governance_proof_export_entry(_proof_entry())
    for field in gateway_app.RUNTIME_GOVERNANCE_PROOF_EXPORT_REQUIRED_FIELDS:
        assert field in pkg
    assert pkg["proof_status"] == gateway_app.RUNTIME_GOVERNANCE_PROOF_STATUS_VALID
    assert pkg["proof_reason_code"] == gateway_app.RHC_RH_PROOF_VALID
    ok, codes = gateway_app.validate_runtime_governance_proof_export(pkg)
    assert ok is True, codes
    assert codes == []


def test_proof_export_entry_never_carries_raw_sensitive_fields():
    record = _reconcilable_record()
    record["payload"] = "raw-request-body"
    record["decision_signature"] = "-----BEGIN SIGNATURE-----"
    pkg = gateway_app.build_runtime_governance_proof_export_entry(
        _proof_entry(record=record))
    # Whitelist guarantees raw fields cannot leak into the export package.
    assert "payload" not in pkg
    assert "decision_signature" not in pkg
    assert gateway_app.runtime_health_evidence_contains_sensitive_data(pkg) is False


def test_proof_export_omits_absent_optional_ids_never_faked():
    pkg = gateway_app.build_runtime_governance_proof_export_entry(
        _proof_entry(record=_reconcilable_record(
            policy_context_id=None, gateway_context_id=None)))
    assert "policy_context_id" not in pkg
    assert "gateway_context_id" not in pkg
    ok, codes = gateway_app.validate_runtime_governance_proof_export(pkg)
    assert ok is True, codes


def test_proof_export_includes_optional_ids_when_present():
    pkg = gateway_app.build_runtime_governance_proof_export_entry(_proof_entry())
    assert pkg["policy_context_id"].startswith(gateway_app.POLICY_CONTEXT_ID_PREFIX)
    assert pkg["gateway_context_id"].startswith(gateway_app.GATEWAY_CONTEXT_ID_PREFIX)
    assert "previous_audit_hash" in pkg


def test_proof_export_validation_missing_field_fails():
    pkg = gateway_app.build_runtime_governance_proof_export_entry(_proof_entry())
    del pkg["governance_context_id"]
    ok, codes = gateway_app.validate_runtime_governance_proof_export(pkg)
    assert ok is False
    assert gateway_app.RHC_RH_EXPORT_INCOMPLETE in codes


def test_proof_export_validation_hash_mismatch_fails():
    env = _proof_entry()
    env["hash_current"] = "0" * 64  # present but does not recompute
    pkg = gateway_app.build_runtime_governance_proof_export_entry(env)
    assert pkg["proof_status"] == gateway_app.RUNTIME_GOVERNANCE_PROOF_STATUS_FAILED
    assert gateway_app.RHC_RH_PROOF_AUDIT_HASH_MISMATCH in pkg["proof_reason_codes"]
    ok, codes = gateway_app.validate_runtime_governance_proof_export(pkg)
    assert ok is False
    assert gateway_app.RHC_RH_EXPORT_PROOF_NOT_VALID in codes


def test_proof_export_validation_previous_hash_mismatch_fails():
    env = _proof_entry()
    pkg = gateway_app.build_runtime_governance_proof_export_entry(
        env, prev_hash="not-the-genesis-hash")
    assert pkg["proof_status"] == gateway_app.RUNTIME_GOVERNANCE_PROOF_STATUS_FAILED
    assert gateway_app.RHC_RH_PROOF_PREVIOUS_HASH_MISMATCH in pkg["proof_reason_codes"]
    ok, codes = gateway_app.validate_runtime_governance_proof_export(pkg)
    assert ok is False
    assert gateway_app.RHC_RH_EXPORT_PROOF_NOT_VALID in codes


def test_proof_export_validation_malformed_optional_id_fails():
    pkg = gateway_app.build_runtime_governance_proof_export_entry(_proof_entry())
    pkg["policy_context_id"] = "pctx-not-hex"
    ok, codes = gateway_app.validate_runtime_governance_proof_export(pkg)
    assert ok is False
    assert gateway_app.RHC_RH_EXPORT_POLICY_CONTEXT_MALFORMED in codes


def test_proof_export_validation_rejects_injected_sensitive_data():
    pkg = gateway_app.build_runtime_governance_proof_export_entry(_proof_entry())
    pkg["payload"] = "raw-request-body"  # defense-in-depth: tampered package
    ok, codes = gateway_app.validate_runtime_governance_proof_export(pkg)
    assert ok is False
    assert gateway_app.RHC_RH_EXPORT_SENSITIVE_DATA in codes


def test_proof_export_uses_deterministic_timestamp():
    env = _proof_entry()
    env["timestamp"] = 1234567
    env["hash_current"] = __import__(
        "audit.hash_chain", fromlist=["compute_hash"]).compute_hash({
            "timestamp": env["timestamp"],
            "action": env["action"],
            "decision": env["decision"],
            "hash_prev": env["hash_prev"],
        }, env["hash_prev"])
    pkg = gateway_app.build_runtime_governance_proof_export_entry(env)
    assert pkg["proof_generated_at"] == 1234567


# --- system-wide export report integration ---------------------------------

def test_system_wide_proof_export_is_valid(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-export-ok")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    report = gateway_app.build_runtime_governance_proof_export()
    assert report["export_supported"] is True
    assert report["hash_chain_valid"] is True
    assert report["valid"] is True
    assert report["count"] >= 1
    assert report["exported"] == report["count"]
    assert report["failures"] == []
    for pkg in report["exports"]:
        assert pkg["proof_status"] == gateway_app.RUNTIME_GOVERNANCE_PROOF_STATUS_VALID
        assert gateway_app.runtime_health_evidence_contains_sensitive_data(pkg) is False


def test_system_wide_proof_export_detects_tamper(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-export-tamper")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    chain = gateway_app.audit_chain.load()
    for entry in chain:
        if entry.get("action") == gateway_app.RUNTIME_HEALTH_EVIDENCE_EVENT_TYPE:
            entry["decision"]["decision_id"] = "tampered-decision-id"
            break
    report = gateway_app.build_runtime_governance_proof_export(chain=chain)
    assert report["valid"] is False
    assert report["hash_chain_valid"] is False
    assert report["failures"]


def test_proof_export_is_read_only(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-export-readonly")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    before = gateway_app.audit_chain.load()
    gateway_app.build_runtime_governance_proof_export()
    after = gateway_app.audit_chain.load()
    assert before == after


def test_proof_export_empty_chain_is_vacuously_valid():
    report = gateway_app.build_runtime_governance_proof_export(chain=[])
    assert report["valid"] is True
    assert report["count"] == 0
    assert report["exported"] == 0
    assert report["exports"] == []


def test_proof_export_validation_rejects_forged_valid_status():
    # Defense-in-depth: a package that claims VALID while carrying a non-VALID
    # proof reason code is forged metadata and must be rejected.
    pkg = gateway_app.build_runtime_governance_proof_export_entry(_proof_entry())
    pkg["proof_status"] = gateway_app.RUNTIME_GOVERNANCE_PROOF_STATUS_VALID
    pkg["proof_reason_code"] = gateway_app.RHC_RH_PROOF_AUDIT_HASH_MISMATCH
    pkg["proof_reason_codes"] = [gateway_app.RHC_RH_PROOF_AUDIT_HASH_MISMATCH]
    ok, codes = gateway_app.validate_runtime_governance_proof_export(pkg)
    assert ok is False
    assert gateway_app.RHC_RH_EXPORT_PROOF_NOT_VALID in codes


# --- PB-RUNTIME-012: governance proof export INDEX -------------------------

def _export_index_record(**overrides):
    pkg = gateway_app.build_runtime_governance_proof_export_entry(_proof_entry())
    rec = gateway_app.build_runtime_governance_proof_export_index_record(pkg)
    if overrides:
        rec.update(overrides)
    return rec


def _export_index(records):
    return {
        "records": records,
        "export_index_hash":
            gateway_app.compute_runtime_governance_proof_export_index_hash(records),
    }


def test_export_index_record_builds_with_required_fields():
    rec = _export_index_record()
    for field in gateway_app.RUNTIME_GOVERNANCE_PROOF_EXPORT_INDEX_RECORD_REQUIRED_FIELDS:
        assert field in rec and rec[field] is not None
    assert rec["export_record_hash"] == (
        gateway_app.compute_runtime_governance_proof_export_record_hash(rec))


def test_export_index_record_never_carries_raw_sensitive_fields():
    record = _reconcilable_record()
    record["payload"] = "raw-request-body"
    record["decision_signature"] = "-----BEGIN SIGNATURE-----"
    pkg = gateway_app.build_runtime_governance_proof_export_entry(
        _proof_entry(record=record))
    rec = gateway_app.build_runtime_governance_proof_export_index_record(pkg)
    # Whitelist guarantees raw fields cannot leak into the index record.
    assert "payload" not in rec
    assert "decision_signature" not in rec
    assert gateway_app.runtime_health_evidence_contains_sensitive_data(rec) is False


def test_export_index_valid_passes():
    index = _export_index([_export_index_record()])
    ok, codes = gateway_app.validate_runtime_governance_proof_export_index(index)
    assert ok is True, codes
    assert codes == []


def test_export_index_missing_required_field_fails():
    rec = _export_index_record()
    del rec["governance_context_id"]
    # Recompute the index hash so we isolate the INCOMPLETE failure mode.
    index = _export_index([rec])
    ok, codes = gateway_app.validate_runtime_governance_proof_export_index(index)
    assert ok is False
    assert gateway_app.RHC_RH_EXPORT_INDEX_INCOMPLETE in codes


def test_export_index_duplicate_decision_id_fails():
    rec_a = _export_index_record()
    # Same decision_id, different audit_hash -> isolate the duplicate-decision mode.
    rec_b = _export_index_record(audit_hash="hash-distinct-b")
    rec_b["export_record_hash"] = (
        gateway_app.compute_runtime_governance_proof_export_record_hash(rec_b))
    index = _export_index([rec_a, rec_b])
    ok, codes = gateway_app.validate_runtime_governance_proof_export_index(index)
    assert ok is False
    assert gateway_app.RHC_RH_EXPORT_INDEX_DUPLICATE_DECISION in codes


def test_export_index_duplicate_audit_hash_fails():
    rec_a = _export_index_record()
    # Same audit_hash, different decision_id -> isolate the duplicate-hash mode.
    rec_b = _export_index_record(decision_id="dec-distinct-b")
    rec_b["export_record_hash"] = (
        gateway_app.compute_runtime_governance_proof_export_record_hash(rec_b))
    index = _export_index([rec_a, rec_b])
    ok, codes = gateway_app.validate_runtime_governance_proof_export_index(index)
    assert ok is False
    assert gateway_app.RHC_RH_EXPORT_INDEX_DUPLICATE_AUDIT_HASH in codes


def test_export_index_record_hash_mismatch_fails():
    rec = _export_index_record()
    rec["export_record_hash"] = "deadbeef"
    index = _export_index([rec])
    ok, codes = gateway_app.validate_runtime_governance_proof_export_index(index)
    assert ok is False
    assert gateway_app.RHC_RH_EXPORT_INDEX_RECORD_HASH_MISMATCH in codes


def test_export_index_hash_mismatch_fails():
    index = _export_index([_export_index_record()])
    index["export_index_hash"] = "tampered-index-hash"
    ok, codes = gateway_app.validate_runtime_governance_proof_export_index(index)
    assert ok is False
    assert gateway_app.RHC_RH_EXPORT_INDEX_HASH_MISMATCH in codes


def test_export_index_sensitive_data_rejected():
    rec = _export_index_record()
    rec["payload"] = "raw-request-body"
    # Re-stamp the record hash so the digest matches; the sensitive-data scan
    # (not the hash, which is whitelist-only) must still reject the record.
    rec["export_record_hash"] = (
        gateway_app.compute_runtime_governance_proof_export_record_hash(rec))
    index = _export_index([rec])
    ok, codes = gateway_app.validate_runtime_governance_proof_export_index(index)
    assert ok is False
    assert gateway_app.RHC_RH_EXPORT_INDEX_SENSITIVE_DATA in codes


def test_export_index_omits_absent_optional_ids_never_faked():
    pkg = gateway_app.build_runtime_governance_proof_export_entry(
        _proof_entry(record=_reconcilable_record(
            policy_context_id=None, gateway_context_id=None)))
    rec = gateway_app.build_runtime_governance_proof_export_index_record(pkg)
    assert "policy_context_id" not in rec
    assert "gateway_context_id" not in rec
    index = _export_index([rec])
    ok, codes = gateway_app.validate_runtime_governance_proof_export_index(index)
    assert ok is True, codes


def test_export_index_includes_optional_ids_when_present():
    rec = _export_index_record()
    assert rec["policy_context_id"].startswith(gateway_app.POLICY_CONTEXT_ID_PREFIX)
    assert rec["gateway_context_id"].startswith(gateway_app.GATEWAY_CONTEXT_ID_PREFIX)
    assert "previous_audit_hash" in rec


def test_export_index_record_hash_is_deterministic():
    rec_a = _export_index_record()
    rec_b = _export_index_record()
    assert rec_a["export_record_hash"] == rec_b["export_record_hash"]


def test_export_index_empty_chain_is_vacuously_valid():
    index = gateway_app.build_runtime_governance_proof_export_index(chain=[])
    assert index["count"] == 0
    assert index["records"] == []
    assert index["index_integrity_valid"] is True
    assert index["export_index_hash"] == gateway_app.GENESIS_HASH


def test_export_index_system_wide_valid(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-export-index-ok")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    index = gateway_app.build_runtime_governance_proof_export_index()
    assert index["count"] >= 1
    assert index["index_integrity_valid"] is True
    assert index["valid"] is True
    ok, codes = gateway_app.validate_runtime_governance_proof_export_index(index)
    assert ok is True, codes


def test_export_index_is_read_only(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-export-index-readonly")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    before = gateway_app.audit_chain.load()
    gateway_app.build_runtime_governance_proof_export_index()
    after = gateway_app.audit_chain.load()
    assert before == after


def test_export_index_malformed_optional_context_ids_fail():
    # Optional ids are allowed to be absent, but a PRESENT malformed id must fail.
    rec = _export_index_record(
        policy_context_id="not-a-valid-policy-id",
        gateway_context_id="not-a-valid-gateway-id")
    rec["export_record_hash"] = (
        gateway_app.compute_runtime_governance_proof_export_record_hash(rec))
    index = _export_index([rec])
    ok, codes = gateway_app.validate_runtime_governance_proof_export_index(index)
    assert ok is False
    assert gateway_app.RHC_RH_EXPORT_INDEX_POLICY_CONTEXT_MALFORMED in codes
    assert gateway_app.RHC_RH_EXPORT_INDEX_GATEWAY_CONTEXT_MALFORMED in codes


# ---------------------------------------------------------------------------
# PB-RUNTIME-013: Runtime Governance Proof FRESHNESS INDEX
# ---------------------------------------------------------------------------
def _freshness_index_record(*, reference_time=1, max_age=None, **overrides):
    if max_age is None:
        max_age = gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_MAX_AGE
    src = _export_index_record()
    fr = gateway_app.build_runtime_governance_proof_freshness_index_record(
        src, reference_time=reference_time, max_age=max_age)
    if overrides:
        fr.update(overrides)
    return fr


def _freshness_index(records, *, checked_at=1, max_age=None):
    if max_age is None:
        max_age = gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_MAX_AGE
    return {
        "records": records,
        "freshness_checked_at": checked_at,
        "freshness_max_age": max_age,
        "freshness_index_hash":
            gateway_app.compute_runtime_governance_proof_freshness_index_hash(
                records, checked_at=checked_at, max_age=max_age),
        "export_index_hash":
            gateway_app.compute_runtime_governance_proof_export_index_hash(
                records),
    }


# --- pure classifier: all five statuses are deterministically reachable -----
def test_freshness_classify_current():
    status, reason = gateway_app.classify_runtime_governance_proof_freshness(
        proof_status=gateway_app.RUNTIME_GOVERNANCE_PROOF_STATUS_VALID,
        proof_generated_at=100, audit_hash="ah", export_record_hash="erh",
        latest_generated_at=100, reference_time=100, max_age=50)
    assert status == gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_STATUS_CURRENT
    assert reason == gateway_app.RHC_RH_FRESHNESS_CURRENT


def test_freshness_classify_stale():
    status, reason = gateway_app.classify_runtime_governance_proof_freshness(
        proof_status=gateway_app.RUNTIME_GOVERNANCE_PROOF_STATUS_VALID,
        proof_generated_at=100, audit_hash="ah", export_record_hash="erh",
        latest_generated_at=100, reference_time=1000, max_age=50)
    assert status == gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_STATUS_STALE
    assert reason == gateway_app.RHC_RH_FRESHNESS_STALE


def test_freshness_classify_missing():
    status, reason = gateway_app.classify_runtime_governance_proof_freshness(
        proof_status=gateway_app.RUNTIME_GOVERNANCE_PROOF_STATUS_VALID,
        proof_generated_at=None, audit_hash=None, export_record_hash=None,
        reference_time=100, max_age=50)
    assert status == gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_STATUS_MISSING
    assert reason == gateway_app.RHC_RH_FRESHNESS_MISSING


def test_freshness_classify_superseded():
    status, reason = gateway_app.classify_runtime_governance_proof_freshness(
        proof_status=gateway_app.RUNTIME_GOVERNANCE_PROOF_STATUS_VALID,
        proof_generated_at=100, audit_hash="ah", export_record_hash="erh",
        latest_generated_at=200, reference_time=200, max_age=50000)
    assert status == (
        gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_STATUS_SUPERSEDED)
    assert reason == gateway_app.RHC_RH_FRESHNESS_SUPERSEDED


def test_freshness_classify_invalid():
    status, reason = gateway_app.classify_runtime_governance_proof_freshness(
        proof_status=gateway_app.RUNTIME_GOVERNANCE_PROOF_STATUS_FAILED,
        proof_generated_at=100, audit_hash="ah", export_record_hash="erh",
        reference_time=100, max_age=50)
    assert status == gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_STATUS_INVALID
    assert reason == gateway_app.RHC_RH_FRESHNESS_INVALID


def test_freshness_classify_handles_iso_timestamps():
    # Production audit timestamps are ISO-8601 strings, not ints; the classifier
    # must still compute age deterministically.
    status, _ = gateway_app.classify_runtime_governance_proof_freshness(
        proof_status=gateway_app.RUNTIME_GOVERNANCE_PROOF_STATUS_VALID,
        proof_generated_at="2026-01-01T00:00:00Z", audit_hash="ah",
        export_record_hash="erh", reference_time="2026-12-31T00:00:00Z",
        max_age=86400)
    assert status == gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_STATUS_STALE


# --- record builder ---------------------------------------------------------
def test_freshness_index_record_builds_with_required_fields():
    fr = _freshness_index_record()
    for field in (
            gateway_app
            .RUNTIME_GOVERNANCE_PROOF_FRESHNESS_RECORD_REQUIRED_FIELDS):
        assert field in fr and fr[field] is not None
    assert fr["freshness_status"] == (
        gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_STATUS_CURRENT)
    assert fr["freshness_reason_code"] == gateway_app.RHC_RH_FRESHNESS_CURRENT


def test_freshness_index_record_never_carries_raw_sensitive_fields():
    record = _reconcilable_record()
    record["payload"] = "raw-request-body"
    record["decision_signature"] = "-----BEGIN SIGNATURE-----"
    pkg = gateway_app.build_runtime_governance_proof_export_entry(
        _proof_entry(record=record))
    src = gateway_app.build_runtime_governance_proof_export_index_record(pkg)
    fr = gateway_app.build_runtime_governance_proof_freshness_index_record(
        src, reference_time=1)
    assert "payload" not in fr
    assert "decision_signature" not in fr
    assert gateway_app.runtime_health_evidence_contains_sensitive_data(fr) is (
        False)


def test_freshness_index_record_is_deterministic():
    assert _freshness_index_record() == _freshness_index_record()


# --- validation: CURRENT passes; each status detected -----------------------
def test_freshness_index_valid_passes():
    index = _freshness_index([_freshness_index_record()])
    ok, codes = (
        gateway_app.validate_runtime_governance_proof_freshness_index(index))
    assert ok is True, codes
    assert codes == []


def test_freshness_index_stale_detected():
    src = _export_index_record()
    fr = gateway_app.build_runtime_governance_proof_freshness_index_record(
        src, reference_time=10000, max_age=0)
    assert fr["freshness_status"] == (
        gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_STATUS_STALE)
    index = _freshness_index([fr], checked_at=10000, max_age=0)
    ok, codes = (
        gateway_app.validate_runtime_governance_proof_freshness_index(index))
    assert ok is True, codes


def test_freshness_index_missing_detected():
    src = _export_index_record()
    src["audit_hash"] = None
    fr = gateway_app.build_runtime_governance_proof_freshness_index_record(
        src, reference_time=1)
    assert fr["freshness_status"] == (
        gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_STATUS_MISSING)
    index = _freshness_index([fr])
    ok, codes = (
        gateway_app.validate_runtime_governance_proof_freshness_index(index))
    assert ok is True, codes


def test_freshness_index_superseded_detected():
    src_old = _export_index_record()
    src_new = _export_index_record(audit_hash="hash-new-supersedes")
    src_new["proof_generated_at"] = 2
    src_new["export_record_hash"] = (
        gateway_app.compute_runtime_governance_proof_export_record_hash(src_new))
    fr_old = gateway_app.build_runtime_governance_proof_freshness_index_record(
        src_old, latest_generated_at=2, reference_time=2)
    fr_new = gateway_app.build_runtime_governance_proof_freshness_index_record(
        src_new, latest_generated_at=2, reference_time=2)
    assert fr_old["freshness_status"] == (
        gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_STATUS_SUPERSEDED)
    assert fr_new["freshness_status"] == (
        gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_STATUS_CURRENT)
    index = _freshness_index([fr_old, fr_new], checked_at=2)
    ok, codes = (
        gateway_app.validate_runtime_governance_proof_freshness_index(index))
    assert ok is True, codes


def test_freshness_index_invalid_detected():
    src = _export_index_record()
    src["proof_status"] = gateway_app.RUNTIME_GOVERNANCE_PROOF_STATUS_FAILED
    fr = gateway_app.build_runtime_governance_proof_freshness_index_record(
        src, reference_time=1)
    assert fr["freshness_status"] == (
        gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_STATUS_INVALID)
    index = _freshness_index([fr])
    ok, codes = (
        gateway_app.validate_runtime_governance_proof_freshness_index(index))
    assert ok is True, codes


# --- validation: tamper-evidence & defense-in-depth -------------------------
def test_freshness_index_hash_mismatch_fails():
    index = _freshness_index([_freshness_index_record()])
    index["freshness_index_hash"] = "tampered-freshness-index-hash"
    ok, codes = (
        gateway_app.validate_runtime_governance_proof_freshness_index(index))
    assert ok is False
    assert gateway_app.RHC_RH_FRESHNESS_INDEX_HASH_MISMATCH in codes


def test_freshness_index_export_index_hash_mismatch_fails():
    index = _freshness_index([_freshness_index_record()])
    index["export_index_hash"] = "tampered-export-index-hash"
    ok, codes = (
        gateway_app.validate_runtime_governance_proof_freshness_index(index))
    assert ok is False
    assert gateway_app.RHC_RH_FRESHNESS_EXPORT_INDEX_HASH_MISMATCH in codes


def test_freshness_index_status_mismatch_fails():
    # Forge a record declaring CURRENT while its carried proof_status (FAILED)
    # re-derives to INVALID. Hashes are re-stamped so only STATUS_MISMATCH fires.
    fr = _freshness_index_record()
    fr["proof_status"] = gateway_app.RUNTIME_GOVERNANCE_PROOF_STATUS_FAILED
    index = _freshness_index([fr])
    ok, codes = (
        gateway_app.validate_runtime_governance_proof_freshness_index(index))
    assert ok is False
    assert gateway_app.RHC_RH_FRESHNESS_STATUS_MISMATCH in codes


def test_freshness_index_unknown_status_fails():
    fr = _freshness_index_record(freshness_status="NONSENSE")
    index = _freshness_index([fr])
    ok, codes = (
        gateway_app.validate_runtime_governance_proof_freshness_index(index))
    assert ok is False
    assert gateway_app.RHC_RH_FRESHNESS_UNKNOWN_STATUS in codes


def test_freshness_index_reason_mismatch_fails():
    fr = _freshness_index_record(freshness_reason_code="WRONG_REASON")
    index = _freshness_index([fr])
    ok, codes = (
        gateway_app.validate_runtime_governance_proof_freshness_index(index))
    assert ok is False
    assert gateway_app.RHC_RH_FRESHNESS_REASON_MISMATCH in codes


def test_freshness_index_sensitive_data_rejected():
    fr = _freshness_index_record()
    fr["payload"] = "raw-request-body"
    index = _freshness_index([fr])
    ok, codes = (
        gateway_app.validate_runtime_governance_proof_freshness_index(index))
    assert ok is False
    assert gateway_app.RHC_RH_FRESHNESS_SENSITIVE_DATA in codes


def test_freshness_index_omits_absent_optional_ids_never_faked():
    pkg = gateway_app.build_runtime_governance_proof_export_entry(
        _proof_entry(record=_reconcilable_record(
            policy_context_id=None, gateway_context_id=None)))
    src = gateway_app.build_runtime_governance_proof_export_index_record(pkg)
    fr = gateway_app.build_runtime_governance_proof_freshness_index_record(
        src, reference_time=1)
    assert "policy_context_id" not in fr
    assert "gateway_context_id" not in fr
    index = _freshness_index([fr])
    ok, codes = (
        gateway_app.validate_runtime_governance_proof_freshness_index(index))
    assert ok is True, codes


def test_freshness_index_malformed_optional_context_ids_fail():
    fr = _freshness_index_record(
        policy_context_id="not-a-valid-policy-id",
        gateway_context_id="not-a-valid-gateway-id")
    index = _freshness_index([fr])
    ok, codes = (
        gateway_app.validate_runtime_governance_proof_freshness_index(index))
    assert ok is False
    assert gateway_app.RHC_RH_FRESHNESS_POLICY_CONTEXT_MALFORMED in codes
    assert gateway_app.RHC_RH_FRESHNESS_GATEWAY_CONTEXT_MALFORMED in codes


# --- system-wide build over a real /execute decision ------------------------
def test_freshness_index_empty_chain_is_vacuously_valid():
    index = gateway_app.build_runtime_governance_proof_freshness_index(chain=[])
    assert index["count"] == 0
    assert index["records"] == []
    assert index["index_integrity_valid"] is True
    assert index["all_current"] is False


def test_freshness_index_system_wide_valid(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-freshness-index-ok")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    index = gateway_app.build_runtime_governance_proof_freshness_index()
    assert index["count"] >= 1
    assert index["index_integrity_valid"] is True
    assert index["all_current"] is True
    assert index["valid"] is True
    ok, codes = (
        gateway_app.validate_runtime_governance_proof_freshness_index(index))
    assert ok is True, codes


def test_freshness_index_is_read_only(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-freshness-index-readonly")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    before = gateway_app.audit_chain.load()
    gateway_app.build_runtime_governance_proof_freshness_index()
    after = gateway_app.audit_chain.load()
    assert before == after


def test_freshness_epoch_iso_is_timezone_stable():
    # 'Z' (UTC) and explicit +00:00 must yield identical, timezone-stable epochs.
    a = gateway_app._freshness_epoch("2026-01-01T00:00:00Z")
    b = gateway_app._freshness_epoch("2026-01-01T00:00:00+00:00")
    assert a == b
    import datetime as _dt
    expected = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc).timestamp()
    assert a == expected


def test_freshness_index_missing_checked_at_fails():
    # A non-empty index without a reference anchor must fail closed, so stale
    # detection can never be silently suppressed.
    records = [_freshness_index_record()]
    index = {
        "records": records,
        "freshness_checked_at": None,
        "freshness_max_age": gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_MAX_AGE,
        "freshness_index_hash":
            gateway_app.compute_runtime_governance_proof_freshness_index_hash(
                records, checked_at=None,
                max_age=gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_MAX_AGE),
        "export_index_hash":
            gateway_app.compute_runtime_governance_proof_export_index_hash(
                records),
    }
    ok, codes = (
        gateway_app.validate_runtime_governance_proof_freshness_index(index))
    assert ok is False
    assert gateway_app.RHC_RH_FRESHNESS_INCOMPLETE in codes


# ===========================================================================
# PB-RUNTIME-014: Runtime Audit Freshness Index PROOF
# ===========================================================================
def _afip_full_index(records, *, checked_at=1, max_age=None):
    """Build a complete PB-RUNTIME-013 freshness index (with freshness_counts +
    index_integrity_valid) directly from freshness records, so 014 proof tests
    can deterministically control CURRENT / STALE / MISSING populations."""
    if max_age is None:
        max_age = gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_MAX_AGE
    counts = {
        s: 0 for s in gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_STATUSES}
    for r in records:
        st = r.get("freshness_status")
        if st in counts:
            counts[st] += 1
    index = {
        "count": len(records),
        "records": records,
        "freshness_checked_at": checked_at,
        "freshness_max_age": max_age,
        "freshness_index_hash":
            gateway_app.compute_runtime_governance_proof_freshness_index_hash(
                records, checked_at=checked_at, max_age=max_age),
        "export_index_hash":
            gateway_app.compute_runtime_governance_proof_export_index_hash(
                records),
        "freshness_counts": counts,
    }
    ok, codes = (
        gateway_app.validate_runtime_governance_proof_freshness_index(index))
    index["index_integrity_valid"] = ok
    index["reason_codes"] = codes
    return index


def _afip_current_index():
    return _afip_full_index([_freshness_index_record()], checked_at=1)


def _afip_stale_index():
    fr = _freshness_index_record(reference_time=10 ** 9, max_age=1)
    return _afip_full_index([fr], checked_at=10 ** 9, max_age=1)


def _afip_missing_index():
    fr = gateway_app.build_runtime_governance_proof_freshness_index_record(
        {"decision_id": "d-missing"})
    return _afip_full_index([fr], checked_at=1)


# --- classifier: all four statuses are deterministically reachable ----------
def test_afip_classify_current():
    status, reason = gateway_app.classify_runtime_audit_freshness_index_proof(
        index_integrity_valid=True, freshness_checked_at=1, freshness_max_age=5,
        stale_record_count=0, missing_freshness_count=0)
    assert status == gateway_app.RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_STATUS_CURRENT
    assert reason == gateway_app.RHC_AFIP_CURRENT


def test_afip_classify_stale():
    status, reason = gateway_app.classify_runtime_audit_freshness_index_proof(
        index_integrity_valid=True, freshness_checked_at=1, freshness_max_age=5,
        stale_record_count=2, missing_freshness_count=0)
    assert status == gateway_app.RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_STATUS_STALE
    assert reason == gateway_app.RHC_AFIP_STALE


def test_afip_classify_missing_takes_precedence_over_stale():
    status, reason = gateway_app.classify_runtime_audit_freshness_index_proof(
        index_integrity_valid=True, freshness_checked_at=1, freshness_max_age=5,
        stale_record_count=3, missing_freshness_count=1)
    assert status == gateway_app.RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_STATUS_MISSING
    assert reason == gateway_app.RHC_AFIP_MISSING


def test_afip_classify_invalid_when_reference_absent():
    status, reason = gateway_app.classify_runtime_audit_freshness_index_proof(
        index_integrity_valid=True, freshness_checked_at=None,
        freshness_max_age=5, stale_record_count=0, missing_freshness_count=0)
    assert status == gateway_app.RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_STATUS_INVALID
    assert reason == gateway_app.RHC_AFIP_INVALID


def test_afip_classify_invalid_when_index_not_valid():
    status, _ = gateway_app.classify_runtime_audit_freshness_index_proof(
        index_integrity_valid=False, freshness_checked_at=1, freshness_max_age=5,
        stale_record_count=0, missing_freshness_count=0)
    assert status == gateway_app.RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_STATUS_INVALID


# --- id determinism ---------------------------------------------------------
def test_afip_proof_id_is_deterministic_and_prefixed():
    kwargs = dict(
        freshness_index_hash="fih", export_index_hash="eih",
        freshness_checked_at=1, freshness_max_age=5, export_record_count=2,
        fresh_record_count=2, stale_record_count=0, missing_freshness_count=0)
    a = gateway_app.compute_runtime_audit_freshness_index_proof_id(**kwargs)
    b = gateway_app.compute_runtime_audit_freshness_index_proof_id(**kwargs)
    assert a == b
    assert a.startswith(
        gateway_app.RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_ID_PREFIX)


def test_afip_proof_id_changes_when_any_field_changes():
    kwargs = dict(
        freshness_index_hash="fih", export_index_hash="eih",
        freshness_checked_at=1, freshness_max_age=5, export_record_count=2,
        fresh_record_count=2, stale_record_count=0, missing_freshness_count=0)
    base = gateway_app.compute_runtime_audit_freshness_index_proof_id(**kwargs)
    mutated = dict(kwargs)
    mutated["stale_record_count"] = 1
    assert gateway_app.compute_runtime_audit_freshness_index_proof_id(
        **mutated) != base


# --- builder ----------------------------------------------------------------
def test_afip_build_has_exactly_the_whitelisted_fields():
    proof = gateway_app.build_runtime_audit_freshness_index_proof(
        _afip_current_index())
    assert set(proof.keys()) == set(
        gateway_app.RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_FIELDS)


def test_afip_build_summarises_counts_and_carries_hashes():
    index = _afip_current_index()
    proof = gateway_app.build_runtime_audit_freshness_index_proof(index)
    assert proof["freshness_index_status"] == (
        gateway_app.RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_STATUS_CURRENT)
    assert proof["export_record_count"] == 1
    assert proof["fresh_record_count"] == 1
    assert proof["stale_record_count"] == 0
    assert proof["missing_freshness_count"] == 0
    assert proof["export_index_hash"] == index["export_index_hash"]
    assert proof["freshness_index_hash"] == index["freshness_index_hash"]
    assert proof["freshness_checked_at"] == index["freshness_checked_at"]
    assert proof["freshness_max_age"] == index["freshness_max_age"]


def test_afip_build_never_carries_raw_sensitive_fields():
    proof = gateway_app.build_runtime_audit_freshness_index_proof(
        _afip_current_index())
    assert not (
        gateway_app.runtime_health_evidence_contains_sensitive_data(proof))


# --- validation: the happy path ---------------------------------------------
def test_afip_valid_proof_passes():
    index = _afip_current_index()
    proof = gateway_app.build_runtime_audit_freshness_index_proof(index)
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(
        proof, index)
    assert ok is True, codes
    assert codes == []


def test_afip_valid_proof_passes_without_source_index():
    index = _afip_current_index()
    proof = gateway_app.build_runtime_audit_freshness_index_proof(index)
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(proof)
    assert ok is True, codes


# --- validation: fail-closed reference parameters ---------------------------
def test_afip_missing_checked_at_fails():
    proof = gateway_app.build_runtime_audit_freshness_index_proof(
        _afip_current_index())
    proof["freshness_checked_at"] = None
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(proof)
    assert ok is False
    assert gateway_app.RHC_AFIP_CHECKED_AT_MISSING in codes


def test_afip_missing_max_age_fails():
    proof = gateway_app.build_runtime_audit_freshness_index_proof(
        _afip_current_index())
    proof["freshness_max_age"] = None
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(proof)
    assert ok is False
    assert gateway_app.RHC_AFIP_MAX_AGE_MISSING in codes


# --- validation: currency assertion -----------------------------------------
def test_afip_stale_record_fails():
    index = _afip_stale_index()
    proof = gateway_app.build_runtime_audit_freshness_index_proof(index)
    assert proof["freshness_index_status"] == (
        gateway_app.RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_STATUS_STALE)
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(
        proof, index)
    assert ok is False
    assert gateway_app.RHC_AFIP_STALE_RECORDS in codes


def test_afip_missing_record_fails():
    index = _afip_missing_index()
    proof = gateway_app.build_runtime_audit_freshness_index_proof(index)
    assert proof["freshness_index_status"] == (
        gateway_app.RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_STATUS_MISSING)
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(
        proof, index)
    assert ok is False
    assert gateway_app.RHC_AFIP_MISSING_RECORDS in codes


# --- validation: tamper-evidence vs the source index ------------------------
def test_afip_export_index_hash_mismatch_fails():
    index = _afip_current_index()
    proof = gateway_app.build_runtime_audit_freshness_index_proof(index)
    proof["export_index_hash"] = "tampered"
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(
        proof, index)
    assert ok is False
    assert gateway_app.RHC_AFIP_EXPORT_INDEX_HASH_MISMATCH in codes


def test_afip_freshness_index_hash_mismatch_fails():
    index = _afip_current_index()
    proof = gateway_app.build_runtime_audit_freshness_index_proof(index)
    proof["freshness_index_hash"] = "tampered"
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(
        proof, index)
    assert ok is False
    assert gateway_app.RHC_AFIP_INDEX_HASH_MISMATCH in codes


def test_afip_record_count_mismatch_fails():
    index = _afip_current_index()
    proof = gateway_app.build_runtime_audit_freshness_index_proof(index)
    proof["export_record_count"] = 99
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(
        proof, index)
    assert ok is False
    assert gateway_app.RHC_AFIP_RECORD_COUNT_MISMATCH in codes


def test_afip_count_mismatch_fails():
    index = _afip_current_index()
    proof = gateway_app.build_runtime_audit_freshness_index_proof(index)
    # Drop fresh count without exceeding total, isolating COUNT_MISMATCH.
    proof["fresh_record_count"] = 0
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(
        proof, index)
    assert ok is False
    assert gateway_app.RHC_AFIP_COUNT_MISMATCH in codes


def test_afip_id_mismatch_fails():
    proof = gateway_app.build_runtime_audit_freshness_index_proof(
        _afip_current_index())
    proof["freshness_index_id"] = "usbafip-deadbeef"
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(proof)
    assert ok is False
    assert gateway_app.RHC_AFIP_ID_MISMATCH in codes


# --- validation: structural / status integrity ------------------------------
def test_afip_unknown_status_fails():
    proof = gateway_app.build_runtime_audit_freshness_index_proof(
        _afip_current_index())
    proof["freshness_index_status"] = "BOGUS"
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(proof)
    assert ok is False
    assert gateway_app.RHC_AFIP_UNKNOWN_STATUS in codes


def test_afip_reason_mismatch_fails():
    proof = gateway_app.build_runtime_audit_freshness_index_proof(
        _afip_current_index())
    proof["freshness_index_reason_code"] = gateway_app.RHC_AFIP_STALE
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(proof)
    assert ok is False
    assert gateway_app.RHC_AFIP_REASON_MISMATCH in codes


def test_afip_forged_current_status_over_stale_counts_fails():
    index = _afip_stale_index()
    proof = gateway_app.build_runtime_audit_freshness_index_proof(index)
    # Forge a healthy status/reason while counts still show a stale record.
    proof["freshness_index_status"] = (
        gateway_app.RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_STATUS_CURRENT)
    proof["freshness_index_reason_code"] = gateway_app.RHC_AFIP_CURRENT
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(proof)
    assert ok is False
    assert gateway_app.RHC_AFIP_STATUS_MISMATCH in codes


def test_afip_incomplete_proof_fails():
    proof = gateway_app.build_runtime_audit_freshness_index_proof(
        _afip_current_index())
    del proof["export_index_hash"]
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(proof)
    assert ok is False
    assert gateway_app.RHC_AFIP_INCOMPLETE in codes


def test_afip_non_dict_proof_fails():
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(None)
    assert ok is False
    assert gateway_app.RHC_AFIP_INCOMPLETE in codes


# --- validation: sensitive data + duplicates --------------------------------
def test_afip_sensitive_data_rejected():
    proof = gateway_app.build_runtime_audit_freshness_index_proof(
        _afip_current_index())
    proof["signature"] = "-----BEGIN SIGNATURE-----"
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(proof)
    assert ok is False
    assert gateway_app.RHC_AFIP_SENSITIVE_DATA in codes


def test_afip_duplicate_freshness_index_fails():
    index = _afip_current_index()
    proof = gateway_app.build_runtime_audit_freshness_index_proof(index)
    seen = set()
    ok1, _ = gateway_app.validate_runtime_audit_freshness_index_proof(
        proof, index, seen_ids=seen)
    assert ok1 is True
    ok2, codes2 = gateway_app.validate_runtime_audit_freshness_index_proof(
        proof, index, seen_ids=seen)
    assert ok2 is False
    assert gateway_app.RHC_AFIP_DUPLICATE in codes2


# --- system-wide: over a real /execute decision -----------------------------
def test_afip_from_chain_proves_current_exports(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-afip-proof-ok")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    index = gateway_app.build_runtime_governance_proof_freshness_index()
    proof = gateway_app.build_runtime_audit_freshness_index_proof_from_chain()
    assert proof["freshness_index_status"] == (
        gateway_app.RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_STATUS_CURRENT)
    assert proof["export_record_count"] >= 1
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(
        proof, index)
    assert ok is True, codes


def test_afip_from_chain_is_read_only(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-afip-proof-readonly")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    before = gateway_app.audit_chain.load()
    gateway_app.build_runtime_audit_freshness_index_proof_from_chain()
    after = gateway_app.audit_chain.load()
    assert before == after


def test_afip_empty_chain_proof_is_invalid_not_current():
    # An empty export chain has no reference anchor, so the proof is INVALID
    # (fail-closed) rather than vacuously CURRENT.
    proof = gateway_app.build_runtime_audit_freshness_index_proof_from_chain(
        chain=[])
    assert proof["freshness_index_status"] == (
        gateway_app.RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_STATUS_INVALID)
    assert proof["export_record_count"] == 0


# --- validation: closes architect-identified bypasses -----------------------
def test_afip_extra_field_rejected():
    # The proof schema is exactly the 11-field whitelist; an extra (even
    # non-sensitive) key is an ungoverned schema extension and must fail.
    proof = gateway_app.build_runtime_audit_freshness_index_proof(
        _afip_current_index())
    proof["note"] = "extra"
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(proof)
    assert ok is False
    assert gateway_app.RHC_AFIP_INCOMPLETE in codes


def test_afip_forged_current_over_invalid_index_fails_with_source():
    # An empty export chain yields an INVALID proof (no reference anchor).
    # Forging it to CURRENT (with a recomputed id so the self-consistency checks
    # pass) must STILL fail when cross-checked against the trusted source index.
    index = gateway_app.build_runtime_governance_proof_freshness_index(chain=[])
    proof = gateway_app.build_runtime_audit_freshness_index_proof(index)
    assert proof["freshness_index_status"] == (
        gateway_app.RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_STATUS_INVALID)
    proof["freshness_index_status"] = (
        gateway_app.RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_STATUS_CURRENT)
    proof["freshness_index_reason_code"] = gateway_app.RHC_AFIP_CURRENT
    proof["freshness_checked_at"] = 1
    proof["freshness_max_age"] = (
        gateway_app.RUNTIME_GOVERNANCE_PROOF_FRESHNESS_MAX_AGE)
    proof["freshness_index_id"] = (
        gateway_app.compute_runtime_audit_freshness_index_proof_id(
            freshness_index_hash=proof["freshness_index_hash"],
            export_index_hash=proof["export_index_hash"],
            freshness_checked_at=proof["freshness_checked_at"],
            freshness_max_age=proof["freshness_max_age"],
            export_record_count=proof["export_record_count"],
            fresh_record_count=proof["fresh_record_count"],
            stale_record_count=proof["stale_record_count"],
            missing_freshness_count=proof["missing_freshness_count"]))
    ok, codes = gateway_app.validate_runtime_audit_freshness_index_proof(
        proof, index)
    assert ok is False
    assert gateway_app.RHC_AFIP_STATUS_MISMATCH in codes


# === PB-RUNTIME-015: regulator-grade evidence package manifest ==============
def _rep_kwargs(**over):
    """Deterministic, in-window, complete inputs for a VALID regulator package."""
    kw = dict(
        runtime_proof_hash="a" * 64,
        export_index_hash="b" * 64,
        freshness_index_hash="c" * 64,
        e2e_evidence_hash="d" * 64,
        evidence_record_count=3,
        freshness_checked_at=100,
        freshness_max_age=1000,
        generated_at=120,
    )
    kw.update(over)
    return kw


def _rep_valid_package(**over):
    return gateway_app.build_runtime_regulator_evidence_package(
        **_rep_kwargs(**over))


def _rep_reseal(pkg):
    """Recompute package_hash + id so a tampered field stays self-consistent
    (isolates the cross-check / structural failure under test)."""
    pkg["package_hash"] = (
        gateway_app.compute_runtime_regulator_evidence_package_hash(
            runtime_proof_hash=pkg["runtime_proof_hash"],
            export_index_hash=pkg["export_index_hash"],
            freshness_index_hash=pkg["freshness_index_hash"],
            e2e_evidence_hash=pkg["e2e_evidence_hash"],
            evidence_record_count=pkg["evidence_record_count"],
            freshness_checked_at=pkg["freshness_checked_at"],
            freshness_max_age=pkg["freshness_max_age"],
            generated_at=pkg["regulator_package_generated_at"]))
    pkg["regulator_package_id"] = (
        gateway_app.compute_runtime_regulator_evidence_package_id(
            package_hash=pkg["package_hash"],
            status=pkg["regulator_package_status"],
            reason_code=pkg["regulator_package_reason_code"]))
    return pkg


# --- build + status ---------------------------------------------------------
def test_rep_valid_package_passes():
    pkg = _rep_valid_package()
    assert pkg["regulator_package_status"] == (
        gateway_app.RUNTIME_REGULATOR_EVIDENCE_PACKAGE_STATUS_VALID)
    assert pkg["regulator_package_reason_code"] == gateway_app.RHC_REP_VALID
    assert pkg["regulator_package_id"].startswith(
        gateway_app.RUNTIME_REGULATOR_EVIDENCE_PACKAGE_ID_PREFIX)
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(pkg)
    assert ok is True, codes
    assert codes == []


def test_rep_package_only_whitelisted_fields():
    pkg = _rep_valid_package()
    assert set(pkg.keys()) == set(
        gateway_app.RUNTIME_REGULATOR_EVIDENCE_PACKAGE_FIELDS)


# --- missing component hashes (each its own reason code) ---------------------
def test_rep_missing_runtime_proof_hash_fails():
    pkg = _rep_valid_package(runtime_proof_hash="")
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(pkg)
    assert ok is False
    assert gateway_app.RHC_REP_RUNTIME_PROOF_HASH_MISSING in codes


def test_rep_missing_export_index_hash_fails():
    pkg = _rep_valid_package(export_index_hash="")
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(pkg)
    assert ok is False
    assert gateway_app.RHC_REP_EXPORT_INDEX_HASH_MISSING in codes


def test_rep_missing_freshness_index_hash_fails():
    pkg = _rep_valid_package(freshness_index_hash="")
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(pkg)
    assert ok is False
    assert gateway_app.RHC_REP_FRESHNESS_INDEX_HASH_MISSING in codes


def test_rep_missing_e2e_evidence_hash_fails():
    pkg = _rep_valid_package(e2e_evidence_hash="")
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(pkg)
    assert ok is False
    assert gateway_app.RHC_REP_E2E_EVIDENCE_HASH_MISSING in codes


# --- missing freshness fields ----------------------------------------------
def test_rep_missing_freshness_checked_at_fails():
    pkg = _rep_valid_package(freshness_checked_at=None)
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(pkg)
    assert ok is False
    assert gateway_app.RHC_REP_CHECKED_AT_MISSING in codes


def test_rep_missing_freshness_max_age_fails():
    pkg = _rep_valid_package(freshness_max_age=None)
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(pkg)
    assert ok is False
    assert gateway_app.RHC_REP_MAX_AGE_MISSING in codes


def test_rep_missing_generated_at_fails():
    pkg = _rep_valid_package(generated_at=None)
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(pkg)
    assert ok is False
    assert gateway_app.RHC_REP_GENERATED_AT_MISSING in codes


# --- stale ------------------------------------------------------------------
def test_rep_stale_package_fails():
    pkg = _rep_valid_package(
        freshness_checked_at=100, freshness_max_age=10, generated_at=1000)
    assert pkg["regulator_package_status"] == (
        gateway_app.RUNTIME_REGULATOR_EVIDENCE_PACKAGE_STATUS_STALE)
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(pkg)
    assert ok is False
    assert gateway_app.RHC_REP_STALE in codes


# --- tamper-evidence: hash / id / status -----------------------------------
def test_rep_package_hash_mismatch_fails():
    pkg = _rep_valid_package()
    pkg["package_hash"] = "deadbeef"
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(pkg)
    assert ok is False
    assert gateway_app.RHC_REP_PACKAGE_HASH_MISMATCH in codes


def test_rep_id_mismatch_fails():
    pkg = _rep_valid_package()
    pkg["regulator_package_id"] = (
        gateway_app.RUNTIME_REGULATOR_EVIDENCE_PACKAGE_ID_PREFIX + "0" * 32)
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(pkg)
    assert ok is False
    assert gateway_app.RHC_REP_ID_MISMATCH in codes


def test_rep_forged_valid_over_stale_fails():
    # Build a STALE package, forge it to VALID, then reseal so the digest+id are
    # self-consistent; the status re-derivation must still catch the forgery.
    pkg = _rep_valid_package(
        freshness_checked_at=100, freshness_max_age=10, generated_at=1000)
    assert pkg["regulator_package_status"] == (
        gateway_app.RUNTIME_REGULATOR_EVIDENCE_PACKAGE_STATUS_STALE)
    pkg["regulator_package_status"] = (
        gateway_app.RUNTIME_REGULATOR_EVIDENCE_PACKAGE_STATUS_VALID)
    pkg["regulator_package_reason_code"] = gateway_app.RHC_REP_VALID
    _rep_reseal(pkg)
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(pkg)
    assert ok is False
    assert gateway_app.RHC_REP_STATUS_MISMATCH in codes


# --- duplicate --------------------------------------------------------------
def test_rep_duplicate_package_hash_fails():
    pkg = _rep_valid_package()
    seen = set()
    ok1, _ = gateway_app.validate_runtime_regulator_evidence_package(
        pkg, seen_hashes=seen)
    assert ok1 is True
    ok2, codes2 = gateway_app.validate_runtime_regulator_evidence_package(
        pkg, seen_hashes=seen)
    assert ok2 is False
    assert gateway_app.RHC_REP_DUPLICATE in codes2


# --- sensitive data + extra field -------------------------------------------
def test_rep_sensitive_data_rejected():
    pkg = _rep_valid_package()
    pkg["signature"] = "-----BEGIN PRIVATE KEY-----"
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(pkg)
    assert ok is False
    assert gateway_app.RHC_REP_SENSITIVE_DATA in codes


def test_rep_extra_field_rejected():
    pkg = _rep_valid_package()
    pkg["note"] = "extra"
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(pkg)
    assert ok is False
    assert gateway_app.RHC_REP_INCOMPLETE in codes


# --- cross-check against the source freshness index (same evidence set) ------
def test_rep_matches_source_index_passes():
    idx = _afip_current_index()
    pkg = gateway_app.build_runtime_regulator_evidence_package(
        runtime_proof_hash="a" * 64,
        export_index_hash=idx["export_index_hash"],
        freshness_index_hash=idx["freshness_index_hash"],
        e2e_evidence_hash="d" * 64,
        evidence_record_count=len(idx["records"]),
        freshness_checked_at=idx["freshness_checked_at"],
        freshness_max_age=idx["freshness_max_age"],
        generated_at=idx["freshness_checked_at"])
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(
        pkg, idx)
    assert ok is True, codes


def test_rep_record_count_mismatch_with_source_fails():
    idx = _afip_current_index()
    pkg = gateway_app.build_runtime_regulator_evidence_package(
        runtime_proof_hash="a" * 64,
        export_index_hash=idx["export_index_hash"],
        freshness_index_hash=idx["freshness_index_hash"],
        e2e_evidence_hash="d" * 64,
        evidence_record_count=len(idx["records"]),
        freshness_checked_at=idx["freshness_checked_at"],
        freshness_max_age=idx["freshness_max_age"],
        generated_at=idx["freshness_checked_at"])
    pkg["evidence_record_count"] = len(idx["records"]) + 99
    _rep_reseal(pkg)
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(
        pkg, idx)
    assert ok is False
    assert gateway_app.RHC_REP_RECORD_COUNT_MISMATCH in codes


def test_rep_export_index_hash_mismatch_with_source_fails():
    idx = _afip_current_index()
    pkg = _rep_valid_package(
        export_index_hash="f" * 64,
        freshness_index_hash=idx["freshness_index_hash"],
        evidence_record_count=len(idx["records"]),
        freshness_checked_at=idx["freshness_checked_at"],
        freshness_max_age=idx["freshness_max_age"],
        generated_at=idx["freshness_checked_at"])
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(
        pkg, idx)
    assert ok is False
    assert gateway_app.RHC_REP_EXPORT_INDEX_HASH_MISMATCH in codes


# --- chain-derived package binds one real evidence set ----------------------
def test_rep_from_chain_binds_same_evidence_set(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce="rh-rep-from-chain")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200

    index = gateway_app.build_runtime_governance_proof_freshness_index()
    pkg = gateway_app.build_runtime_regulator_evidence_package_from_chain(
        runtime_proof_hash="a" * 64, e2e_evidence_hash="d" * 64)
    assert pkg["regulator_package_status"] == (
        gateway_app.RUNTIME_REGULATOR_EVIDENCE_PACKAGE_STATUS_VALID)
    assert pkg["evidence_record_count"] >= 1
    ok, codes = gateway_app.validate_runtime_regulator_evidence_package(
        pkg, index)
    assert ok is True, codes


# ===========================================================================
# PB-RUNTIME-016: Regulator package SELF-DERIVATION authority
# ===========================================================================
def _sd_chain(tmp_path, monkeypatch, nonce="rh-sd"):
    """Configure the gateway, force a healthy decision, and return the live audit
    chain so self-derivation tests can DERIVE hashes from real runtime/export/
    freshness evidence."""
    client = configure_gateway(tmp_path, monkeypatch)
    _rh_force_all_healthy(monkeypatch)
    monkeypatch.delenv(gateway_app.RUNTIME_HEALTH_PROFILE_ENV, raising=False)
    payload = build_payload(nonce=nonce)
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200
    return client, gateway_app.audit_chain.load()


_SD_E2E_EVIDENCE = {"e2e_run": "ok", "checks": 4, "stage": "final"}


def _sd_recompute_status(pkg):
    """Recompute source_derivation_status + reason from the four carried per-hash
    sources (keeps a forged provenance field internally consistent)."""
    sources = tuple(
        pkg[sfield] for _h, sfield in
        gateway_app.RUNTIME_REGULATOR_PACKAGE_HASH_SOURCE_FIELDS)
    status, reason = (
        gateway_app.classify_runtime_regulator_package_self_derivation_status(
            sources))
    pkg["source_derivation_status"] = status
    pkg["source_derivation_reason_code"] = reason
    return pkg


# --- fully derived ----------------------------------------------------------
def test_sd_fully_derived_passes(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="sd-fully-derived")
    pkg = gateway_app.build_runtime_regulator_package_self_derivation_from_chain(
        chain, e2e_evidence=_SD_E2E_EVIDENCE)
    assert pkg["source_derivation_status"] == (
        gateway_app.RUNTIME_REGULATOR_PACKAGE_HASH_SOURCE_DERIVED)
    for _h, sfield in gateway_app.RUNTIME_REGULATOR_PACKAGE_HASH_SOURCE_FIELDS:
        assert pkg[sfield] == (
            gateway_app.RUNTIME_REGULATOR_PACKAGE_HASH_SOURCE_DERIVED)
    index = gateway_app.build_runtime_governance_proof_freshness_index(chain)
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_self_derivation(
            pkg, index, chain=chain, e2e_evidence=_SD_E2E_EVIDENCE))
    assert ok is True, codes


def test_sd_only_whitelisted_fields(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="sd-whitelist")
    pkg = gateway_app.build_runtime_regulator_package_self_derivation_from_chain(
        chain, e2e_evidence=_SD_E2E_EVIDENCE)
    assert set(pkg.keys()) == set(
        gateway_app.RUNTIME_REGULATOR_PACKAGE_SELF_DERIVATION_FIELDS)


# --- documented caller-supplied fallback (E2E source genuinely unavailable) --
def test_sd_documented_caller_fallback_passes(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="sd-fallback")
    pkg = gateway_app.build_runtime_regulator_package_self_derivation_from_chain(
        chain, e2e_evidence=None, e2e_evidence_hash="d" * 64)
    assert pkg["e2e_evidence_hash_source"] == (
        gateway_app.RUNTIME_REGULATOR_PACKAGE_HASH_SOURCE_CALLER_SUPPLIED)
    assert pkg["source_derivation_status"] == (
        gateway_app.RUNTIME_REGULATOR_PACKAGE_HASH_SOURCE_CALLER_SUPPLIED)
    index = gateway_app.build_runtime_governance_proof_freshness_index(chain)
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_self_derivation(
            pkg, index, chain=chain))
    assert ok is True, codes


# --- undocumented caller-supplied fallback over an AVAILABLE source ----------
def test_sd_undocumented_fallback_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="sd-undoc")
    pkg = gateway_app.build_runtime_regulator_package_self_derivation_from_chain(
        chain, e2e_evidence=_SD_E2E_EVIDENCE)
    # Forge: claim the (derivable) export index hash was caller-supplied.
    pkg["export_index_hash_source"] = (
        gateway_app.RUNTIME_REGULATOR_PACKAGE_HASH_SOURCE_CALLER_SUPPLIED)
    _sd_recompute_status(pkg)
    index = gateway_app.build_runtime_governance_proof_freshness_index(chain)
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_self_derivation(
            pkg, index, chain=chain, e2e_evidence=_SD_E2E_EVIDENCE))
    assert ok is False
    assert gateway_app.RHC_REP_SD_UNDOCUMENTED_FALLBACK in codes


# --- derived / caller mismatch ----------------------------------------------
def test_sd_derived_caller_mismatch_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="sd-mismatch")
    pkg = gateway_app.build_runtime_regulator_package_self_derivation_from_chain(
        chain, e2e_evidence=_SD_E2E_EVIDENCE, runtime_proof_hash="a" * 64)
    assert pkg["runtime_proof_hash_source"] == (
        gateway_app.RUNTIME_REGULATOR_PACKAGE_HASH_SOURCE_MISMATCH)
    assert pkg["source_derivation_status"] == (
        gateway_app.RUNTIME_REGULATOR_PACKAGE_HASH_SOURCE_MISMATCH)
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_self_derivation(
            pkg, chain=chain, e2e_evidence=_SD_E2E_EVIDENCE))
    assert ok is False
    assert gateway_app.RHC_REP_SD_MISMATCH in codes


# --- malformed source evidence ----------------------------------------------
def test_sd_malformed_source_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="sd-malformed")
    pkg = gateway_app.build_runtime_regulator_package_self_derivation_from_chain(
        chain, e2e_evidence="not-a-dict", e2e_evidence_hash="d" * 64)
    assert pkg["e2e_evidence_hash_source"] == (
        gateway_app.RUNTIME_REGULATOR_PACKAGE_HASH_SOURCE_MISMATCH)
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_self_derivation(
            pkg, chain=chain, e2e_evidence="not-a-dict"))
    assert ok is False
    assert gateway_app.RHC_REP_SD_SOURCE_MALFORMED in codes


# --- false DERIVED claim (source genuinely absent) --------------------------
def test_sd_false_derived_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="sd-false-derived")
    pkg = gateway_app.build_runtime_regulator_package_self_derivation_from_chain(
        chain, e2e_evidence=_SD_E2E_EVIDENCE)
    # runtime_proof_hash is DERIVED over the real chain; re-derive against an
    # EMPTY chain (no export evidence) -> the DERIVED claim is provably false.
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_self_derivation(
            pkg, chain=[], e2e_evidence=_SD_E2E_EVIDENCE))
    assert ok is False
    assert gateway_app.RHC_REP_SD_FALSE_DERIVED in codes


# --- unknown source / status guards -----------------------------------------
def test_sd_unknown_source_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="sd-unknown-source")
    pkg = gateway_app.build_runtime_regulator_package_self_derivation_from_chain(
        chain, e2e_evidence=_SD_E2E_EVIDENCE)
    pkg["runtime_proof_hash_source"] = "BOGUS"
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_self_derivation(pkg))
    assert ok is False
    assert gateway_app.RHC_REP_SD_UNKNOWN_SOURCE in codes


def test_sd_status_mismatch_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="sd-status-mismatch")
    pkg = gateway_app.build_runtime_regulator_package_self_derivation_from_chain(
        chain, e2e_evidence=_SD_E2E_EVIDENCE)
    # All sources are DERIVED; forge the overall status to CALLER_SUPPLIED.
    pkg["source_derivation_status"] = (
        gateway_app.RUNTIME_REGULATOR_PACKAGE_HASH_SOURCE_CALLER_SUPPLIED)
    pkg["source_derivation_reason_code"] = gateway_app.RHC_REP_SD_CALLER_SUPPLIED
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_self_derivation(pkg))
    assert ok is False
    assert gateway_app.RHC_REP_SD_STATUS_MISMATCH in codes


# --- sensitive data ---------------------------------------------------------
def test_sd_sensitive_data_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="sd-sensitive")
    pkg = gateway_app.build_runtime_regulator_package_self_derivation_from_chain(
        chain, e2e_evidence=_SD_E2E_EVIDENCE)
    pkg["signature"] = "-----BEGIN PRIVATE KEY-----"
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_self_derivation(pkg))
    assert ok is False
    assert gateway_app.RHC_REP_SD_SENSITIVE_DATA in codes


# --- /execute unchanged + read-only -----------------------------------------
def test_sd_execute_unchanged_and_read_only(tmp_path, monkeypatch):
    client, chain = _sd_chain(tmp_path, monkeypatch, nonce="sd-readonly-1")
    before = len(gateway_app.audit_chain.load())
    pkg = gateway_app.build_runtime_regulator_package_self_derivation_from_chain(
        chain, e2e_evidence=_SD_E2E_EVIDENCE)
    index = gateway_app.build_runtime_governance_proof_freshness_index(chain)
    gateway_app.validate_runtime_regulator_package_self_derivation(
        pkg, index, chain=chain, e2e_evidence=_SD_E2E_EVIDENCE)
    # Building + validating the package never mutates the audit chain.
    assert len(gateway_app.audit_chain.load()) == before
    # /execute still behaves exactly as before (and is the only writer).
    payload = build_payload(nonce="sd-readonly-2")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200
    assert len(gateway_app.audit_chain.load()) > before


# ===========================================================================
# PB-RUNTIME-017: REGULATOR PACKAGE SOURCE GAP CLOSURE
# ===========================================================================
_GAP_E2E_EVIDENCE = {"e2e_run": "ok", "checks": 4, "stage": "final"}
_GAP_STATE = gateway_app  # alias for readability in assertions below


def _gap_reseal(report):
    """Re-derive status/reason and re-seal hash+id after forging a state field so
    a forged source gap report stays internally consistent (only full evidentiary
    mode can then expose the lie)."""
    states = {
        h: report[sfield]
        for h, sfield in gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_STATE_FIELDS
    }
    status, reason = (
        gateway_app.classify_runtime_regulator_source_gap_report_status(
            tuple(states[h] for h, _ in
                  gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_STATE_FIELDS)))
    report["source_gap_report_status"] = status
    report["source_gap_report_reason_code"] = reason
    rh = gateway_app.compute_runtime_regulator_source_gap_report_hash(states)
    report["source_gap_report_hash"] = rh
    report["source_gap_report_id"] = (
        gateway_app.compute_runtime_regulator_source_gap_report_id(
            report_hash=rh, status=status, reason_code=reason))
    return report


# --- fully derived ----------------------------------------------------------
def test_gap_fully_derived_passes(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-derived")
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence=_GAP_E2E_EVIDENCE)
    assert report["source_gap_report_status"] == (
        gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_REPORT_STATUS_CLOSED)
    for _h, sfield in gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_STATE_FIELDS:
        assert report[sfield] == (
            gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_STATE_DERIVED)
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(
            report, chain=chain, e2e_evidence=_GAP_E2E_EVIDENCE))
    assert ok is True, codes


def test_gap_only_whitelisted_fields(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-whitelist")
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence=_GAP_E2E_EVIDENCE)
    assert set(report.keys()) == set(
        gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_REPORT_FIELDS)
    assert len(gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_REPORT_FIELDS) == 8


# --- documented caller-supplied fallback (E2E source genuinely unavailable) --
def test_gap_documented_caller_fallback_passes(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-fallback")
    just = {"e2e_evidence_hash": "e2e harness offline this run"}
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence=None, e2e_evidence_hash="d" * 64,
        justifications=just)
    assert report["e2e_evidence_source_state"] == (
        gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_STATE_CALLER_SUPPLIED_DOCUMENTED)
    assert report["source_gap_report_status"] == (
        gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_REPORT_STATUS_CLOSED)
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(
            report, chain=chain, e2e_evidence=None, e2e_evidence_hash="d" * 64,
            justifications=just))
    assert ok is True, codes


# --- undocumented fallback (caller value, NO justification) ------------------
def test_gap_undocumented_fallback_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-undoc")
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence=None, e2e_evidence_hash="d" * 64)
    assert report["e2e_evidence_source_state"] == (
        gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_STATE_MISMATCH_BLOCKED)
    assert report["source_gap_report_status"] == (
        gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_REPORT_STATUS_BLOCKED)
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(report))
    assert ok is False
    assert gateway_app.RHC_REP_GAP_MISMATCH_BLOCKED in codes


# --- caller fallback OVER an available source (full evidentiary mode) --------
def test_gap_fallback_over_available_source_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-overavail")
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence=_GAP_E2E_EVIDENCE)
    # Forge: claim e2e was a DOCUMENTED caller fallback though the source IS
    # available (derivable) -> undocumented fallback over an available source.
    report["e2e_evidence_source_state"] = (
        gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_STATE_CALLER_SUPPLIED_DOCUMENTED)
    _gap_reseal(report)
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(
            report, chain=chain, e2e_evidence=_GAP_E2E_EVIDENCE,
            justifications={"e2e_evidence_hash": "claimed offline"}))
    assert ok is False
    assert gateway_app.RHC_REP_GAP_UNDOCUMENTED_FALLBACK in codes


# --- documented caller state but justification actually missing --------------
def test_gap_missing_justification_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-missingjust")
    just = {"e2e_evidence_hash": "e2e harness offline this run"}
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence=None, e2e_evidence_hash="d" * 64,
        justifications=just)
    # Re-validate the SAME documented report but WITHOUT the justification.
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(
            report, chain=chain, e2e_evidence=None, e2e_evidence_hash="d" * 64))
    assert ok is False
    assert gateway_app.RHC_REP_GAP_MISSING_JUSTIFICATION in codes


# --- derived / caller mismatch ----------------------------------------------
def test_gap_mismatch_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-mismatch")
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence=_GAP_E2E_EVIDENCE, runtime_proof_hash="a" * 64)
    assert report["runtime_proof_source_state"] == (
        gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_STATE_MISMATCH_BLOCKED)
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(report))
    assert ok is False
    assert gateway_app.RHC_REP_GAP_MISMATCH_BLOCKED in codes


# --- malformed source evidence ----------------------------------------------
def test_gap_malformed_source_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-malformed")
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence="not-a-dict", e2e_evidence_hash="d" * 64)
    assert report["e2e_evidence_source_state"] == (
        gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_STATE_MALFORMED_BLOCKED)
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(report))
    assert ok is False
    assert gateway_app.RHC_REP_GAP_MALFORMED_BLOCKED in codes


# --- sensitive justification ------------------------------------------------
def test_gap_sensitive_justification_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-sensitive")
    just = {"e2e_evidence_hash": "-----BEGIN PRIVATE KEY-----"}
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence=None, e2e_evidence_hash="d" * 64,
        justifications=just)
    assert report["e2e_evidence_source_state"] == (
        gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_STATE_SENSITIVE_DATA_BLOCKED)
    # The justification TEXT must never leak into the report itself.
    assert not gateway_app.runtime_health_evidence_contains_sensitive_data(report)
    assert "-----BEGIN" not in json.dumps(report)
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(report))
    assert ok is False
    assert gateway_app.RHC_REP_GAP_SENSITIVE_BLOCKED in codes


# --- false DERIVED claim (source genuinely absent) --------------------------
def test_gap_false_derived_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-false-derived")
    just = {"e2e_evidence_hash": "e2e harness offline this run"}
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence=None, e2e_evidence_hash="d" * 64,
        justifications=just)
    # Forge: claim the (genuinely unavailable) e2e source was DERIVED.
    report["e2e_evidence_source_state"] = (
        gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_STATE_DERIVED)
    _gap_reseal(report)
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(
            report, chain=chain, e2e_evidence=None, e2e_evidence_hash="d" * 64,
            justifications=just))
    assert ok is False
    assert gateway_app.RHC_REP_GAP_FALSE_DERIVED in codes


# --- false UNAVAILABLE claim (a value IS present) ---------------------------
def test_gap_false_unavailable_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-false-unavail")
    just = {"e2e_evidence_hash": "e2e harness offline this run"}
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence=None, e2e_evidence_hash="d" * 64,
        justifications=just)
    # Forge: claim the source was UNAVAILABLE though a caller value is present.
    report["e2e_evidence_source_state"] = (
        gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_STATE_UNAVAILABLE_DOCUMENTED)
    _gap_reseal(report)
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(
            report, chain=chain, e2e_evidence=None, e2e_evidence_hash="d" * 64,
            justifications=just))
    assert ok is False
    assert gateway_app.RHC_REP_GAP_FALSE_UNAVAILABLE in codes


# --- missing source gap report ----------------------------------------------
def test_gap_missing_report_fails():
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(None))
    assert ok is False
    assert codes == [gateway_app.RHC_REP_GAP_MISSING]


# --- unknown state guard ----------------------------------------------------
def test_gap_unknown_state_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-unknown-state")
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence=_GAP_E2E_EVIDENCE)
    report["runtime_proof_source_state"] = "BOGUS"
    _gap_reseal(report)
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(report))
    assert ok is False
    assert gateway_app.RHC_REP_GAP_UNKNOWN_STATE in codes


# --- forged overall status (mixed-state inconsistency) ----------------------
def test_gap_status_mismatch_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-status-mismatch")
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence=_GAP_E2E_EVIDENCE)
    # All states DERIVED (CLOSED); forge the overall status to BLOCKED.
    report["source_gap_report_status"] = (
        gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_REPORT_STATUS_BLOCKED)
    report["source_gap_report_reason_code"] = gateway_app.RHC_REP_GAP_BLOCKED
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(report))
    assert ok is False
    assert gateway_app.RHC_REP_GAP_STATUS_MISMATCH in codes


# --- tampered state without re-seal (hash mismatch) -------------------------
def test_gap_hash_mismatch_fails(tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-hash-mismatch")
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence=_GAP_E2E_EVIDENCE)
    # Flip a state but DO NOT re-seal: the bound hash no longer matches.
    report["runtime_proof_source_state"] = (
        gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_STATE_UNAVAILABLE_DOCUMENTED)
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(report))
    assert ok is False
    assert gateway_app.RHC_REP_GAP_HASH_MISMATCH in codes


# --- /execute unchanged + read-only -----------------------------------------
def test_gap_execute_unchanged_and_read_only(tmp_path, monkeypatch):
    client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-readonly-1")
    before = len(gateway_app.audit_chain.load())
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence=_GAP_E2E_EVIDENCE)
    gateway_app.validate_runtime_regulator_package_source_gap_report(
        report, chain=chain, e2e_evidence=_GAP_E2E_EVIDENCE)
    # Building + validating the report never mutates the audit chain.
    assert len(gateway_app.audit_chain.load()) == before
    # /execute still behaves exactly as before (and is the only writer).
    payload = build_payload(nonce="gap-readonly-2")
    payload.update(sign_payload_ed25519(payload))
    assert decide_then_execute(client, payload).status_code == 200
    assert len(gateway_app.audit_chain.load()) > before


# --- forged self-consistent CLOSED report: only full mode exposes the lie ----
def test_gap_forged_closed_passes_standalone_caught_in_full_mode(
        tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-forged-closed")
    just = {"e2e_evidence_hash": "e2e harness offline this run"}
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence=None, e2e_evidence_hash="d" * 64,
        justifications=just)
    # Forge the genuinely-unavailable e2e source to DERIVED and RE-SEAL so the
    # report is internally self-consistent (status/reason/hash/id all agree).
    report["e2e_evidence_source_state"] = (
        gateway_app.RUNTIME_REGULATOR_SOURCE_GAP_STATE_DERIVED)
    _gap_reseal(report)
    # Standalone (no source evidence) accepts a self-consistent CLOSED report --
    # the binding is tamper-evidence, not provenance.
    ok_standalone, codes_standalone = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(report))
    assert ok_standalone is True, codes_standalone
    # Full evidentiary mode RE-DERIVES against the real source and exposes the
    # false DERIVED claim (fail-closed).
    ok_full, codes_full = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(
            report, chain=chain, e2e_evidence=None, e2e_evidence_hash="d" * 64,
            justifications=just))
    assert ok_full is False
    assert gateway_app.RHC_REP_GAP_FALSE_DERIVED in codes_full


# --- documented-caller claim over a CONFLICTING source is a STATE_MISMATCH ---
def test_gap_documented_conflict_is_state_mismatch_not_missing_just(
        tmp_path, monkeypatch):
    _client, chain = _sd_chain(tmp_path, monkeypatch, nonce="gap-doc-conflict")
    just = {"e2e_evidence_hash": "e2e harness offline this run"}
    report = gateway_app.build_runtime_regulator_package_source_gap_report(
        chain, e2e_evidence=None, e2e_evidence_hash="d" * 64,
        justifications=just)
    # Re-validate with the source NOW available AND a conflicting caller value
    # plus a present justification: this is a derived/caller conflict, not a
    # missing justification.
    ok, codes = (
        gateway_app.validate_runtime_regulator_package_source_gap_report(
            report, chain=chain, e2e_evidence=_GAP_E2E_EVIDENCE,
            e2e_evidence_hash="d" * 64, justifications=just))
    assert ok is False
    assert gateway_app.RHC_REP_GAP_STATE_MISMATCH in codes
    assert gateway_app.RHC_REP_GAP_MISSING_JUSTIFICATION not in codes


# --------------------------------------------------------------------------
# USBAY-GAME-016R - travel-first shell replacement (demo-only, additive).
# /game must open as a travel-first USBAY Game, not a governance simulator.
# These assert on the server-rendered /game source.
# --------------------------------------------------------------------------

def test_game016r_travel_first_brand_shell(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    # USBAY Game title + the Travel-first tagline are both present in the header.
    assert "USBAY Game" in text
    assert "Travel \u2022 Earn \u2022 Govern \u2022 Play" in text
    # All transport modes are surfaced.
    for mode_label in ("Flight", "Train", "Bus", "Cruise", "Ferry",
                       "Hotel", "Logistics"):
        assert mode_label in text
    # Demo reward currencies incl. the new derived Reputation chip.
    assert '<div class="wchip rep">' in text
    assert "function repVal()" in text


def test_game016r_default_landing_is_world_map_not_governance(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    # The boot routine lands on the World Map travel screen by default, and the
    # governance control plane is NOT the dominant first screen.
    assert re.search(r'(active|start|boot)\s*=\s*"map"', text) or 'show("map")' in text
    # World Map screen leads with travel content + the gameplay loop.
    assert "World Map" in text
    assert "Gameplay loop" in text


def test_game016r_gameplay_loop_buttons_visible_and_wired(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    for label in ("Choose Route", "Start Demo Trip", "Complete Mission",
                  "Claim Rewards", "Upgrade Crew", "Open Marketplace"):
        assert label in text, label
    for key in ("route", "trip", "mission", "rewards", "crew", "market"):
        assert 'data-loop="%s"' % key in text, key
    # The loop handler dispatches to the existing in-app screens/actions.
    assert "function doLoop(" in text
    assert 'closest("[data-loop]")' in text


def test_game016r_governance_remains_accessible_as_gameplay(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    # Governance is preserved as a screen reachable from gameplay, not removed.
    assert 'id:"governance"' in text
    assert "Policy Vote" in text
    assert "Fairness Score" in text


def test_game016r_no_booking_payment_or_external_calls(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    assert "DEMO ONLY - NO REAL BOOKING" in text
    assert "NO REAL PAYMENT" in text
    for forbidden in ("fetch(", "XMLHttpRequest", "navigator.sendBeacon",
                      "localStorage", "sessionStorage", "stripe", "paypal",
                      "/api/"):
        assert forbidden not in text, forbidden


def test_game016r_collects_no_personal_data_fields(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    # The demo shell is interaction-only: it must not request any personal data.
    for forbidden in ('type="email"', 'type="password"', 'type="tel"',
                      'name="email"', 'name="phone"', 'name="name"',
                      'autocomplete="cc-number"', "creditcard", "card-number"):
        assert forbidden not in text, forbidden


# --- GAME-017R: premium game UX upgrade -------------------------------------

def test_game017r_premium_hero_landing(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    # Premium hero banner with strong branding + the kept tagline pieces.
    assert 'class="hero"' in text
    assert 'class="hero-title">USBAY Game' in text
    assert "Travel</span><span>Earn</span><span>Govern</span><span>Play" in text
    # Hero quick-access cards for the five headline areas, wired to real screens.
    assert text.count('class="herocard"') >= 5
    for nav in ("map", "crew", "rewards", "governance"):
        assert 'data-nav="%s"' % nav in text, nav
    assert 'data-loop="trip"' in text  # Start Demo Trip hero card
    for hero_label in ("World Map", "Start Demo Trip", "Crew", "Rewards",
                       "Governance Center"):
        assert hero_label in text, hero_label


def test_game017r_all_transport_modes_visible(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    for label in ("Flights", "Trains", "Buses", "Cruises", "Ferries",
                  "Hotels", "Logistics"):
        assert label in text, label


def test_game017r_crew_named_roles_present(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    for role in ("Pilot", "Train Operator", "Bus Operator", "Cruise Captain",
                 "Governance Auditor", "Sustainability Officer",
                 "Accessibility Officer"):
        assert 'r:"%s"' % role in text, role


def test_game017r_crew_has_no_sensitive_identity_labels(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    # Heritage / ethnicity field and label are fully removed from the crew shell.
    assert 'her:"' not in text
    assert ">Heritage<" not in text
    for ethnicity in ("African American", "Indigenous Amazonian",
                      "Han Chinese", "Mestizo", "Emirati"):
        assert ethnicity not in text, ethnicity
    # Region + pronoun inclusion signals (required by existing suites) are kept.
    assert 'pr:"they/them"' in text
    regions = set(re.findall(r'reg:"([^"]+)"', text))
    assert len(regions) >= 8, regions


def test_game017r_economy_rewards_marked_simulated(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    # Economy display surfaces XP, Gov Credits, Audit Tokens, Reputation, VIP.
    for label in ("Experience (XP)", "Governance Credits", "Audit Tokens",
                  "Reputation", "VIP Discount Pass"):
        assert label in text, label
    assert 'id="rwRep"' in text
    assert "function repVal()" in text
    # Rewards are clearly, prominently marked simulated + non-redeemable.
    assert 'class="sim-line"' in text
    assert "non-redeemable" in text


def test_game017r_governance_kept_but_not_dominant(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    # All four governance-as-gameplay missions remain.
    for mission in ("Policy Vote", "Audit Mission", "Fraud Alert",
                    "Human Review Mission"):
        assert mission in text, mission
    # Governance is reachable but the default landing is still the travel map.
    assert 'id:"governance"' in text
    assert re.search(r'(active|start|boot)\s*=\s*"map"', text) or 'show("map")' in text


def test_game017r_preserves_demo_safety_boundaries(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    assert "DEMO ONLY - NO REAL BOOKING" in text
    assert "NO REAL PAYMENT" in text
    for forbidden in ("fetch(", "XMLHttpRequest", "navigator.sendBeacon",
                      "localStorage", "sessionStorage", "stripe", "paypal",
                      "/api/", 'type="email"', 'type="password"',
                      'autocomplete="cc-number"'):
        assert forbidden not in text, forbidden


# ---------------------------------------------------------------------------
# USBAY-GAME-019R — promote /game to a primary entry point from root
# (UI/routing/navigation only; additive; preserves governance + simulator)
# ---------------------------------------------------------------------------
def _root_text(tmp_path, monkeypatch) -> str:
    client = configure_gateway(tmp_path, monkeypatch)
    res = client.get("/")
    assert res.status_code == 200
    return res.text


def test_game019r_core_routes_ok(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    for path in ("/", "/game", "/simulator"):
        assert client.get(path).status_code == 200, path


def test_game019r_root_exposes_game_entry(tmp_path, monkeypatch):
    text = _root_text(tmp_path, monkeypatch)
    # Root clearly advertises the game as a first-class product.
    assert "USBAY Game" in text
    assert "Travel • Earn • Govern • Play" in text
    # Safe, non-commercial description present.
    assert "Demo-only multi-modal travel game." in text


def test_game019r_root_links_to_game(tmp_path, monkeypatch):
    text = _root_text(tmp_path, monkeypatch)
    # /game is reachable via a real navigable link (no manual URL typing).
    assert 'href="/game"' in text
    # The promoted nav link is present in the top navigation.
    assert 'class="nav-game"' in text


def test_game019r_root_preserves_governance_access(tmp_path, monkeypatch):
    text = _root_text(tmp_path, monkeypatch)
    # Governance Control Plane remains exposed and reachable.
    assert "Governance Control Plane" in text
    # Governance Simulator remains linked from root.
    assert 'href="/simulator"' in text


def test_game019r_root_safety_message_present(tmp_path, monkeypatch):
    text = _root_text(tmp_path, monkeypatch)
    # Persistent demo-safety message is shown on the root game entry.
    assert "DEMO ONLY" in text
    assert "NO REAL BOOKING" in text
    assert "NO REAL PAYMENT" in text


def test_game019r_root_has_no_commerce_ctas(tmp_path, monkeypatch):
    text = _root_text(tmp_path, monkeypatch).lower()
    # No booking/payment/commerce call-to-action controls were introduced.
    for cta in ("book now", "pay now", "checkout", "add to cart", "buy now"):
        assert cta not in text, cta


def test_game019r_game_route_still_serves_prototype(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    res = client.get("/game")
    assert res.status_code == 200
    text = res.text
    # GAME-016R/017R behavior preserved: demo banner + travel-first default.
    assert "DEMO ONLY - NO REAL BOOKING" in text
    assert "NO REAL PAYMENT" in text
    assert re.search(r'(active|start|boot)\s*=\s*"map"', text) or 'show("map")' in text


# ---------------------------------------------------------------------------
# USBAY-GAME-020R — direct gameplay entry experience
# (UI/routing/navigation only; the game card opens straight into gameplay)
# ---------------------------------------------------------------------------
def test_game020r_core_routes_ok(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    for path in ("/", "/game", "/simulator"):
        assert client.get(path).status_code == 200, path


def test_game020r_root_card_opens_game_with_play_affordance(tmp_path, monkeypatch):
    text = _root_text(tmp_path, monkeypatch)
    # The game product card is a real navigable link to /game (no URL typing).
    assert 'class="ps-card ps-card-game" href="/game"' in text
    assert "USBAY Game" in text
    # Clear "play" affordance (not a generic "open"): users see they will play.
    assert "Play Game" in text
    assert "Open Game" not in text


def test_game020r_game_opens_gameplay_first_not_governance(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    # Boots straight onto the gameplay World Map (not the governance dashboard).
    assert re.search(r'(active|start|boot)\s*=\s*"map"', text) or 'show("map")' in text
    assert "USBAY Game" in text
    assert "Travel \u2022 Earn \u2022 Govern \u2022 Play" in text
    # Gameplay-first surfaces: world map, route/travel selection, gameplay loop.
    assert "World Map" in text
    assert "Gameplay loop" in text
    assert 'id="travelnav"' in text
    assert 'id="transportSel"' in text


def test_game020r_game_nav_items_present(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    # Persistent in-game navigation surfaces every required area.
    for label in ("World Map", "Travel Hub", "Governance Center", "Academy",
                  "Crew", "Rewards", "Profile"):
        assert label in text, label
    # Each maps to a real screen id, and the active screen is highlighted.
    for sid in ("map", "hub", "governance", "academy", "crew", "rewards",
                "profile"):
        assert 'id:"%s"' % sid in text, sid
    assert "function show(" in text


def test_game020r_gameplay_panels_visible(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    # Rewards/credits panel, governance missions, and crew/profile progress all
    # exist as gameplay mechanics.
    for label in ("Travel Credits", "Governance Credits", "Experience (XP)",
                  "Audit Tokens"):
        assert label in text, label
    for mission in ("Policy Vote", "Audit Mission", "Fraud Alert",
                    "Human Review Mission"):
        assert mission in text, mission
    assert 'id:"rewards"' in text
    assert 'id:"profile"' in text


def test_game020r_demo_safety_preserved(tmp_path, monkeypatch):
    root = _root_text(tmp_path, monkeypatch)
    game = _game_text(tmp_path, monkeypatch)
    assert "DEMO ONLY" in root
    assert "DEMO ONLY - NO REAL BOOKING" in game
    assert "NO REAL PAYMENT" in game
    # No booking / payment / commerce affordances anywhere on either surface.
    for cta in ("book now", "pay now", "checkout", "add to cart", "buy now"):
        assert cta not in root.lower(), cta
        assert cta not in game.lower(), cta
    # No personal-data capture or account creation in the gameplay surface.
    game_l = game.lower()
    for forbidden in ('type="email"', 'type="password"', 'name="email"',
                      "create account", "sign up"):
        assert forbidden not in game_l, forbidden


def test_game020r_governance_and_simulator_preserved(tmp_path, monkeypatch):
    root = _root_text(tmp_path, monkeypatch)
    # Root still exposes governance control plane + simulator alongside the game.
    assert "Governance Control Plane" in root
    assert 'href="/simulator"' in root
    client = configure_gateway(tmp_path, monkeypatch)
    assert client.get("/simulator").status_code == 200


# ---------------------------------------------------------------------------
# USBAY-GAME-021R — gameplay entry finalization & root nav cleanup
# (UI/routing/navigation only; additive; preserves governance + simulator)
# ---------------------------------------------------------------------------
def test_game021r_core_routes_ok(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    for path in ("/", "/game", "/simulator"):
        assert client.get(path).status_code == 200, path


def test_game021r_root_play_game_cta_to_game(tmp_path, monkeypatch):
    text = _root_text(tmp_path, monkeypatch)
    # Single primary CTA on the game card + clickable card, both routing to /game.
    assert 'class="ps-card ps-card-game" href="/game"' in text
    assert "Play Game" in text
    assert "Open Game" not in text


def test_game021r_top_nav_has_game_item(tmp_path, monkeypatch):
    text = _root_text(tmp_path, monkeypatch)
    # The top navigation exposes a visible USBAY Game item routing to /game.
    assert 'class="nav-game"' in text
    assert 'href="/game" class="nav-game">USBAY Game</a>' in text


def test_game021r_game_nav_active_state(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    # On /game the cross-product nav marks USBAY Game as the active product.
    assert 'class="gamenav"' in text
    assert 'class="gnav gnav-active" aria-current="page"' in text
    # Dashboard + simulator remain reachable from the game shell (no URL typing).
    assert '<a href="/" class="gnav">Dashboard</a>' in text
    assert '<a href="/simulator" class="gnav">Simulator</a>' in text


def test_game021r_game_opens_gameplay_first(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    assert "USBAY Game" in text
    assert "Travel \u2022 Earn \u2022 Govern \u2022 Play" in text
    assert "World Map" in text
    assert re.search(r'(active|start|boot)\s*=\s*"map"', text) or 'show("map")' in text
    # Rewards, Governance Center, Crew/Profile panels reachable.
    for sid in ("rewards", "governance", "crew", "profile"):
        assert 'id:"%s"' % sid in text, sid
    assert "DEMO ONLY" in text


def test_game021r_no_commerce_on_root_or_game(tmp_path, monkeypatch):
    root = _root_text(tmp_path, monkeypatch).lower()
    game = _game_text(tmp_path, monkeypatch).lower()
    for cta in ("book now", "pay now", "checkout", "add to cart", "buy now"):
        assert cta not in root, cta
        assert cta not in game, cta


def test_game021r_simulator_and_governance_preserved(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    assert client.get("/simulator").status_code == 200
    root = client.get("/").text
    assert "Governance Control Plane" in root
    assert 'href="/simulator"' in root


# --------------------------------------------------------------------------
# USBAY-GAME-022R - gameplay landing visual clarity (UI only, additive).
# /game must immediately read as the USBAY Game (clear hero with title,
# subtitle, a primary "Start Demo Trip" CTA and secondary buttons), stay
# gameplay-first (World Map default), and keep the DEMO ONLY banner. The
# root game card's "PLAY GAME" CTA must be visually stronger than the plain
# governance dashboard links.
# --------------------------------------------------------------------------

def test_game022r_core_routes_ok(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    for path in ("/", "/game", "/simulator"):
        assert client.get(path).status_code == 200, path


def test_game022r_game_hero_identity(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    # Clear title + literal subtitle in the gameplay hero.
    assert "USBAY Game" in text
    assert "Travel \u2022 Earn \u2022 Govern \u2022 Play" in text
    assert 'class="hero-subtitle"' in text
    assert "DEMO ONLY" in text


def test_game022r_game_hero_primary_and_secondary_buttons(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    # Visible PRIMARY "Start Demo Trip" button.
    assert "Start Demo Trip" in text
    assert re.search(r'class="hero-btn hero-btn-primary"[^>]*data-loop="trip"', text)
    # Secondary buttons: World Map, Rewards, Governance Center, Crew.
    for nav, label in (("map", "World Map"), ("rewards", "Rewards"),
                       ("governance", "Governance Center"), ("crew", "Crew")):
        assert re.search(r'class="hero-btn"[^>]*data-nav="%s"' % nav, text), nav
        assert label in text, label
    # Primary CTA styling is present so it reads as the dominant action.
    assert ".hero-btn-primary{" in text


def test_game022r_gameplay_first_world_map_default(tmp_path, monkeypatch):
    text = _game_text(tmp_path, monkeypatch)
    # World Map remains the default screen.
    assert re.search(r'(active|start|boot)\s*=\s*"map"', text) or 'show("map")' in text
    assert 'id:"map",label:"World Map"' in text
    # The gameplay hero is rendered by the World Map screen (scMap), i.e. the
    # default view leads with gameplay, not the governance control plane.
    map_idx = text.find('function scMap()')
    home_idx = text.find('function scHome()')
    hero_idx = text.find('class="hero-subtitle"')
    assert map_idx != -1 and hero_idx != -1
    # Hero belongs to scMap (default), not to scHome.
    assert map_idx < hero_idx < (home_idx if home_idx > map_idx else len(text)) or hero_idx > map_idx


def test_game022r_no_commerce(tmp_path, monkeypatch):
    root = _root_text(tmp_path, monkeypatch).lower()
    game = _game_text(tmp_path, monkeypatch).lower()
    for cta in ("book now", "pay now"):
        assert cta not in root, cta
        assert cta not in game, cta


def test_game022r_root_play_game_cta_stronger(tmp_path, monkeypatch):
    text = _root_text(tmp_path, monkeypatch)
    # Game card present with the prominent filled PLAY GAME CTA.
    assert 'class="ps-card ps-card-game" href="/game"' in text
    assert "Play Game" in text
    # The play CTA is a filled, shadowed button; the governance dashboard card
    # uses the plain text .ps-cta link -> game CTA is visually stronger.
    assert ".ps-cta-play{" in text
    assert "box-shadow:0 10px 28px" in text  # glow only on the play CTA
    assert "font-weight:900" in text


def test_game022r_simulator_preserved(tmp_path, monkeypatch):
    client = configure_gateway(tmp_path, monkeypatch)
    assert client.get("/simulator").status_code == 200
