import base64
import hashlib
import json
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
