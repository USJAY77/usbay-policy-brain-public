"""Bypass matrix for the Enterprise Pilot Final Security Gate.

Proves no pilot-context execution can bypass: human approval, tenant and
environment binding, device enrollment, verifier enrollment, challenge
validation, attestation, policy validation, production sync, evidence
integrity, and runtime health. Also proves the onboarding API surfaces
deny unauthenticated/unauthorized/cross-tenant access.

All positive cases use TEST fixtures only — no fake production identity.
"""
from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

import gateway.app as ga
from governance import deployment_sync
from governance import pilot_onboarding as po
from security.nonce_store import NonceStore
from tests.request_signing_helpers import configure_request_signing, sign_payload_ed25519

DEVICE = "d" * 64
VERIFIER = "v" * 64
FUTURE = 4_000_000_000

_ENV = (
    "USBAY_PILOT_CONTRACT_JSON",
    "USBAY_PILOT_HUMAN_APPROVAL_JSON",
    "USBAY_ENROLLED_DEVICE_FINGERPRINTS",
    "USBAY_ENROLLED_VERIFIER_IDS",
    "USBAY_REVOKED_PILOT_IDS",
    "USBAY_DEVICE_CHALLENGE_PACKET_JSON",
    "USBAY_EXPECTED_GIT_COMMIT",
)

HEALTHY = {"state": "HEALTHY"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for var in _ENV:
        monkeypatch.delenv(var, raising=False)
    deployment_sync._reset_runtime_commit_pin_for_tests()
    yield
    deployment_sync._reset_runtime_commit_pin_for_tests()


def _policy_hash():
    _, _, registry = ga.policy_runtime_state()
    return str(registry.get("policy_hash", "")) if registry else ""


def _contract(**overrides):
    base = {
        "pilot_id": "pilot-sec-001",
        "tenant_id": "tenant-sec",
        "environment_id": "env-sec",
        "device_id": DEVICE,
        "verifier_id": VERIFIER,
        "human_approval_reference": "APPR-SEC-1",
        "policy_reference": _policy_hash(),
        "issued_at": 0,
        "expires_at": FUTURE,
        "status": "VERIFIED",
    }
    base.update(overrides)
    return base


def _approval(contract, **overrides):
    base = {
        "human_approval_reference": contract["human_approval_reference"],
        "decision": "APPROVED",
        "approved_at": "2026-08-06T00:00:00Z",
        "approver_kind": "human",
        "approved_pilot_id": contract["pilot_id"],
        "approved_tenant_id": contract["tenant_id"],
        "approved_environment_id": contract["environment_id"],
        "approved_device_id": contract["device_id"],
        "approved_verifier_id": contract["verifier_id"],
    }
    base.update(overrides)
    return base


def _enroll_valid(monkeypatch, contract=None, approval=None, *, devices=DEVICE, verifiers=VERIFIER):
    contract = contract or _contract()
    monkeypatch.setenv("USBAY_PILOT_CONTRACT_JSON", json.dumps(contract))
    monkeypatch.setenv(
        "USBAY_PILOT_HUMAN_APPROVAL_JSON",
        json.dumps(approval if approval is not None else _approval(contract)),
    )
    if devices:
        monkeypatch.setenv("USBAY_ENROLLED_DEVICE_FINGERPRINTS", devices)
    if verifiers:
        monkeypatch.setenv("USBAY_ENROLLED_VERIFIER_IDS", verifiers)
    monkeypatch.setattr(
        ga,
        "device_identity_lifecycle_snapshot",
        lambda **kw: {
            "verified": True,
            "identity_state": "IDENTITY_VERIFIED",
            "device_lifecycle_status": "VERIFIED",
            "audit_evidence": {"device_id_fingerprint": DEVICE},
        },
    )
    monkeypatch.setattr(
        ga,
        "remote_challenge_response_snapshot",
        lambda **kw: {
            "verified": True,
            "challenge_state": "CHALLENGE_RESPONSE_VALID",
            "reason_code": "OK",
        },
    )
    monkeypatch.setenv("USBAY_DEVICE_CHALLENGE_PACKET_JSON", '{"present": true}')
    monkeypatch.setenv(
        "USBAY_EXPECTED_GIT_COMMIT", deployment_sync.current_runtime_commit()
    )
    return contract


def _pilot_payload(contract):
    return {
        "pilot_id": contract["pilot_id"],
        "tenant_id": contract["tenant_id"],
        "environment_id": contract["environment_id"],
    }


def _authz(payload, runtime=HEALTHY):
    return ga.pilot_execution_authorization(payload, runtime)


# --- bypass matrix -----------------------------------------------------------

def test_01_direct_execution_without_enrollment_blocks():
    allowed, reason, _ = _authz({"pilot_id": "pilot-sec-001"})
    assert allowed is False
    assert reason == po.REASON_NO_CONTRACT


def test_02_no_alternate_execution_route_exists():
    # /execute is the ONLY route that can reach route_execution; the new
    # detail endpoint is read-only and every other route is GET.
    post_routes = sorted(
        r.path for r in ga.app.routes if hasattr(r, "methods") and "POST" in (r.methods or set())
    )
    # Only /execute can execute; /decide only records decisions, the /api
    # catch-all is a read-only report proxy, and the detail endpoint is
    # read-only. No other execution-capable route exists.
    assert "/execute" in post_routes
    assert set(post_routes) <= {
        "/execute",
        "/decide",
        "/api/governance/pilot-onboarding/detail",
        "/api/{api_path:path}",
    }
    src = open("gateway/app.py").read()
    # route_execution is invoked exactly once (inside /execute).
    assert src.count("route_execution(payload") == 1


def test_03_missing_approval_blocks(monkeypatch):
    contract = _enroll_valid(monkeypatch)
    monkeypatch.setenv("USBAY_PILOT_HUMAN_APPROVAL_JSON", "")
    allowed, reason, _ = _authz(_pilot_payload(contract))
    assert allowed is False
    assert reason == po.REASON_MISSING_HUMAN_APPROVAL


def test_04_forged_approval_reference_blocks(monkeypatch):
    contract = _enroll_valid(monkeypatch)
    payload = {**_pilot_payload(contract), "human_approval_reference": "FORGED-REF"}
    allowed, reason, _ = _authz(payload)
    assert allowed is False
    assert reason == po.REASON_APPROVAL_REFERENCE_MISMATCH


def test_05_wrong_tenant_blocks(monkeypatch):
    contract = _enroll_valid(monkeypatch)
    payload = {**_pilot_payload(contract), "tenant_id": "other-tenant"}
    allowed, reason, _ = _authz(payload)
    assert allowed is False
    assert reason == po.REASON_PILOT_BINDING_MISMATCH


def test_06_wrong_environment_blocks(monkeypatch):
    contract = _enroll_valid(monkeypatch)
    payload = {**_pilot_payload(contract), "environment_id": "other-env"}
    allowed, reason, _ = _authz(payload)
    assert allowed is False
    assert reason == po.REASON_PILOT_BINDING_MISMATCH


def test_07_unknown_device_blocks(monkeypatch):
    contract = _enroll_valid(monkeypatch, devices="")
    allowed, reason, _ = _authz(_pilot_payload(contract))
    assert allowed is False
    assert reason == po.REASON_UNKNOWN_DEVICE


def test_08_revoked_device_blocks(monkeypatch):
    contract = _enroll_valid(monkeypatch)
    monkeypatch.setattr(
        ga,
        "device_identity_lifecycle_snapshot",
        lambda **kw: {
            "verified": False,
            "identity_state": "IDENTITY_REVOKED",
            "device_lifecycle_status": "DEGRADED",
            "audit_evidence": {"device_id_fingerprint": DEVICE},
        },
    )
    allowed, reason, _ = _authz(_pilot_payload(contract))
    assert allowed is False
    assert reason == po.REASON_DEVICE_IDENTITY_INVALID


def test_09_unknown_verifier_blocks(monkeypatch):
    contract = _enroll_valid(monkeypatch, verifiers="")
    allowed, reason, _ = _authz(_pilot_payload(contract))
    assert allowed is False
    assert reason == po.REASON_UNKNOWN_VERIFIER


def test_10_revoked_verifier_blocks(monkeypatch):
    # Revocation removes the verifier from the enrolled registry.
    contract = _enroll_valid(monkeypatch, verifiers="w" * 64)
    allowed, reason, _ = _authz(_pilot_payload(contract))
    assert allowed is False
    assert reason == po.REASON_UNKNOWN_VERIFIER


def test_11_invalid_signature_blocks(monkeypatch):
    contract = _enroll_valid(monkeypatch)
    monkeypatch.setattr(
        ga,
        "device_identity_lifecycle_snapshot",
        lambda **kw: {
            "verified": False,
            "identity_state": "IDENTITY_SIGNATURE_INVALID",
            "device_lifecycle_status": "DEGRADED",
            "audit_evidence": {"device_id_fingerprint": DEVICE},
        },
    )
    allowed, reason, _ = _authz(_pilot_payload(contract))
    assert allowed is False
    assert reason == po.REASON_DEVICE_IDENTITY_INVALID


def _challenge_failure(monkeypatch, contract, reason):
    monkeypatch.setattr(
        ga,
        "remote_challenge_response_snapshot",
        lambda **kw: {"verified": False, "challenge_state": "CHALLENGE_INVALID", "reason_code": reason},
    )
    return _authz(_pilot_payload(contract))


def test_12_expired_challenge_blocks(monkeypatch):
    contract = _enroll_valid(monkeypatch)
    allowed, reason, _ = _challenge_failure(monkeypatch, contract, "CHALLENGE_EXPIRED")
    assert allowed is False
    assert reason == po.REASON_CHALLENGE_INVALID


def test_13_replayed_nonce_blocks(monkeypatch):
    contract = _enroll_valid(monkeypatch)
    allowed, reason, _ = _challenge_failure(monkeypatch, contract, "NONCE_REPLAYED")
    assert allowed is False
    assert reason == po.REASON_CHALLENGE_INVALID


def test_14_invalid_attestation_blocks(monkeypatch):
    contract = _enroll_valid(monkeypatch)
    allowed, reason, _ = _challenge_failure(monkeypatch, contract, "ATTESTATION_INVALID")
    assert allowed is False
    assert reason == po.REASON_CHALLENGE_INVALID


def test_15_policy_mismatch_blocks(monkeypatch):
    contract = _enroll_valid(monkeypatch, contract=_contract(policy_reference="not-the-hash"))
    allowed, reason, _ = _authz(_pilot_payload(contract))
    assert allowed is False
    assert reason == po.REASON_POLICY_MISMATCH


def test_16_production_sync_drift_blocks(monkeypatch):
    contract = _enroll_valid(monkeypatch)
    monkeypatch.setenv("USBAY_EXPECTED_GIT_COMMIT", "0" * 40)
    allowed, reason, _ = _authz(_pilot_payload(contract))
    assert allowed is False
    assert reason == po.REASON_SYNC_DRIFT


def test_17_evidence_integrity_failure_blocks(monkeypatch):
    contract = _enroll_valid(monkeypatch)
    import governance.evidence_chain_verifier as ecv

    class _Broken:
        state = "EVIDENCE_INVALID"

    monkeypatch.setattr(ecv, "verify_governance_evidence", lambda root: _Broken())
    allowed, reason, _ = _authz(_pilot_payload(contract))
    assert allowed is False
    assert reason == po.REASON_EVIDENCE_INVALID


@pytest.mark.parametrize("state", ["STARTING", "VERIFYING", "FAILED"])
def test_18_19_20_runtime_not_healthy_blocks(monkeypatch, state):
    contract = _enroll_valid(monkeypatch)
    allowed, reason, _ = _authz(_pilot_payload(contract), runtime={"state": state})
    assert allowed is False
    assert reason == po.REASON_PILOT_RUNTIME_NOT_READY


# --- onboarding API authentication/authorization (21-23) --------------------

@pytest.fixture()
def client(monkeypatch, tmp_path):
    configure_request_signing(tmp_path, monkeypatch, ga)
    monkeypatch.setattr(ga, "nonce_store", NonceStore(tmp_path / "used_nonces.json"))
    return TestClient(ga.app)


GRANTS = {
    "test_request_key": {
        "actor_ids": ["governance-operator"],
        "tenant_ids": ["tenant-sec"],
        "environment_ids": ["env-sec"],
    }
}


def _grant(monkeypatch, grants=GRANTS):
    monkeypatch.setenv("USBAY_GOVERNANCE_READ_GRANTS_JSON", json.dumps(grants))


def _signed_detail_payload(**overrides):
    payload = {
        "type": "pilot_onboarding_read",
        "actor_id": "governance-operator",
        "nonce": f"n-{time.time_ns()}",
        "timestamp": int(time.time()),
    }
    payload.update(overrides)
    return sign_payload_ed25519(payload)


def test_21_authenticated_but_unauthorized_denied(client, monkeypatch):
    _grant(monkeypatch)
    # Valid signature but not a governance principal (wrong type / no actor).
    bad_type = _signed_detail_payload(type="execution")
    r = client.post("/api/governance/pilot-onboarding/detail", json=bad_type)
    assert r.status_code == 403
    no_actor = _signed_detail_payload(actor_id="")
    r = client.post("/api/governance/pilot-onboarding/detail", json=no_actor)
    assert r.status_code == 403
    # Valid signature, ungranted actor -> deny (key possession is not authz).
    wrong_actor = _signed_detail_payload(
        actor_id="rogue-actor", tenant_id="tenant-sec", environment_id="env-sec"
    )
    r = client.post("/api/governance/pilot-onboarding/detail", json=wrong_actor)
    assert r.status_code == 403


def test_21b_no_grants_configured_denies_everyone(client, monkeypatch):
    monkeypatch.delenv("USBAY_GOVERNANCE_READ_GRANTS_JSON", raising=False)
    ok = _signed_detail_payload(tenant_id="tenant-sec", environment_id="env-sec")
    r = client.post("/api/governance/pilot-onboarding/detail", json=ok)
    assert r.status_code == 403


def test_21c_malformed_grants_registry_denies(client, monkeypatch):
    monkeypatch.setenv("USBAY_GOVERNANCE_READ_GRANTS_JSON", "{broken")
    ok = _signed_detail_payload(tenant_id="tenant-sec", environment_id="env-sec")
    r = client.post("/api/governance/pilot-onboarding/detail", json=ok)
    assert r.status_code == 403


def test_21d_no_enrolled_contract_denies_detail(client, monkeypatch):
    _grant(monkeypatch)
    ok = _signed_detail_payload(tenant_id="tenant-sec", environment_id="env-sec")
    r = client.post("/api/governance/pilot-onboarding/detail", json=ok)
    assert r.status_code == 403
    assert r.json()["error"] == "not_enrolled"


def test_22_unauthenticated_denied(client):
    r = client.post("/api/governance/pilot-onboarding/detail", json={})
    assert r.status_code == 401
    unsigned = {
        "type": "pilot_onboarding_read",
        "actor_id": "x",
        "nonce": "n-unsigned",
        "timestamp": int(time.time()),
        "signature": "AAAA",
        "signature_alg": "ed25519",
        "pubkey_id": "request_key_2026_01",
    }
    r = client.post("/api/governance/pilot-onboarding/detail", json=unsigned)
    assert r.status_code == 401


def test_23_cross_tenant_access_denied(client, monkeypatch):
    contract = _enroll_valid(monkeypatch)
    _grant(monkeypatch, {
        "test_request_key": {
            "actor_ids": ["governance-operator"],
            "tenant_ids": ["attacker-tenant", contract["tenant_id"]],
            "environment_ids": ["attacker-env", contract["environment_id"]],
        }
    })
    wrong_tenant = _signed_detail_payload(
        tenant_id="attacker-tenant", environment_id=contract["environment_id"]
    )
    r = client.post("/api/governance/pilot-onboarding/detail", json=wrong_tenant)
    assert r.status_code == 403
    wrong_env = _signed_detail_payload(
        tenant_id=contract["tenant_id"], environment_id="attacker-env"
    )
    r = client.post("/api/governance/pilot-onboarding/detail", json=wrong_env)
    assert r.status_code == 403


def test_23b_replayed_detail_nonce_denied(client, monkeypatch):
    contract = _enroll_valid(monkeypatch)
    _grant(monkeypatch)
    ok = _signed_detail_payload(
        tenant_id=contract["tenant_id"], environment_id=contract["environment_id"]
    )
    first = client.post("/api/governance/pilot-onboarding/detail", json=ok)
    assert first.status_code == 200
    replay = client.post("/api/governance/pilot-onboarding/detail", json=ok)
    assert replay.status_code == 401


def test_23c_authorized_detail_reveals_hashes_only(client, monkeypatch):
    contract = _enroll_valid(monkeypatch)
    _grant(monkeypatch)
    ok = _signed_detail_payload(
        tenant_id=contract["tenant_id"], environment_id=contract["environment_id"]
    )
    r = client.post("/api/governance/pilot-onboarding/detail", json=ok)
    assert r.status_code == 200
    serialized = r.text
    assert contract["pilot_id"] not in serialized
    assert contract["human_approval_reference"] not in serialized
    for forbidden in ("-----BEGIN", "private", "secret", "password"):
        assert forbidden not in serialized


def test_public_endpoint_reveals_minimal_state(client, monkeypatch):
    contract = _enroll_valid(monkeypatch)
    r = client.get("/api/governance/pilot-onboarding")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"enrollment_state", "readiness", "execution_gate", "commit_match"}
    serialized = r.text
    assert contract["pilot_id"] not in serialized
    assert contract["tenant_id"] not in serialized
    assert contract["human_approval_reference"] not in serialized
    # No evidence hashes on the public surface.
    assert "pilot_id_hash" not in serialized


# --- 24: complete valid TEST fixture -> execution eligible -------------------

def test_24_complete_valid_fixture_is_execution_eligible(monkeypatch):
    contract = _enroll_valid(monkeypatch)
    allowed, reason, evidence = _authz(_pilot_payload(contract))
    assert allowed is True
    assert reason == po.REASON_OK
    assert evidence["enrollment_state"] == po.ENROLL_VERIFIED


def test_24b_degraded_runtime_blocks_even_when_fully_enrolled(monkeypatch):
    contract = _enroll_valid(monkeypatch)
    allowed, reason, _ = _authz(_pilot_payload(contract), runtime={"state": "DEGRADED"})
    assert allowed is False
    assert reason == po.REASON_PILOT_RUNTIME_NOT_READY


def test_pilot_context_detection_is_fail_closed(monkeypatch):
    assert ga.pilot_execution_request_context({"pilot_id": "x"}) is True
    assert ga.pilot_execution_request_context({"pilot_context": True}) is True
    assert ga.pilot_execution_request_context({"action": "run"}) is False
    contract = _contract()
    monkeypatch.setenv("USBAY_PILOT_CONTRACT_JSON", json.dumps(contract))
    assert ga.pilot_execution_request_context({"tenant_id": "any"}) is True
    assert ga.pilot_execution_request_context("not-a-dict") is False


def test_toctou_gate_and_binding_use_one_contract_parse(monkeypatch):
    contract = _enroll_valid(monkeypatch)
    calls = {"n": 0}
    real = ga._pilot_contract_from_env

    def counting():
        calls["n"] += 1
        return real()

    monkeypatch.setattr(ga, "_pilot_contract_from_env", counting)
    allowed, reason, _ = _authz(_pilot_payload(contract))
    assert allowed is True
    # Exactly one contract read for the whole authorization decision.
    assert calls["n"] == 1


def test_toctou_snapshot_override_ignores_env_swap(monkeypatch):
    contract = _enroll_valid(monkeypatch)
    # Env swapped to a different contract AFTER parse: snapshot must evaluate
    # the passed contract, not the swapped one.
    swapped = _contract(pilot_id="pilot-swapped")
    monkeypatch.setenv("USBAY_PILOT_CONTRACT_JSON", json.dumps(swapped))
    snap = ga.pilot_onboarding_snapshot(contract_override=contract)
    # Approval binds to the ORIGINAL contract ids, so the override contract
    # verifies; had the swapped env contract been read, approval pilot-id
    # binding would have blocked it.
    assert snap["onboarding"]["enrollment_state"] == po.ENROLL_VERIFIED
    swapped_snap = ga.pilot_onboarding_snapshot()
    assert swapped_snap["onboarding"]["enrollment_state"] == po.ENROLL_BLOCKED
