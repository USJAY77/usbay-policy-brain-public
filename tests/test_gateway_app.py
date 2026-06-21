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
