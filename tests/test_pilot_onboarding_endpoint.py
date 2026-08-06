"""Integration tests for pilot_onboarding_snapshot() / the API surface.

Exercises the real gateway composition path (env parsing, identity
fingerprint extraction from audit evidence, policy-hash pinning,
redaction) with monkeypatched device-trust snapshots — no forged
crypto, fixtures only.
"""
from __future__ import annotations

import json

import pytest

import gateway.app as ga
from governance import deployment_sync
from governance import pilot_onboarding as po

DEVICE = "d" * 64
VERIFIER = "v" * 64
NOW_ISH = 4_000_000_000  # far future expiry for fixture contracts

_ENV = (
    "USBAY_PILOT_CONTRACT_JSON",
    "USBAY_PILOT_HUMAN_APPROVAL_JSON",
    "USBAY_ENROLLED_DEVICE_FINGERPRINTS",
    "USBAY_ENROLLED_VERIFIER_IDS",
    "USBAY_REVOKED_PILOT_IDS",
    "USBAY_DEVICE_CHALLENGE_PACKET_JSON",
    "USBAY_EXPECTED_GIT_COMMIT",
    "GITHUB_MAIN_SHA",
)


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
        "pilot_id": "pilot-int-001",
        "tenant_id": "tenant-int",
        "environment_id": "env-int",
        "device_id": DEVICE,
        "verifier_id": VERIFIER,
        "human_approval_reference": "APPR-INT-1",
        "policy_reference": _policy_hash(),
        "issued_at": 0,
        "expires_at": NOW_ISH,
        "status": "VERIFIED",
    }
    base.update(overrides)
    return base


def _approval(contract):
    return {
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


def _wire_valid_device_trust(monkeypatch):
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


def _pin_sync(monkeypatch):
    monkeypatch.setenv(
        "USBAY_EXPECTED_GIT_COMMIT", deployment_sync.current_runtime_commit()
    )


def test_full_valid_env_backed_enrollment_authorizes(monkeypatch):
    contract = _contract()
    monkeypatch.setenv("USBAY_PILOT_CONTRACT_JSON", json.dumps(contract))
    monkeypatch.setenv(
        "USBAY_PILOT_HUMAN_APPROVAL_JSON", json.dumps(_approval(contract))
    )
    monkeypatch.setenv("USBAY_ENROLLED_DEVICE_FINGERPRINTS", DEVICE)
    monkeypatch.setenv("USBAY_ENROLLED_VERIFIER_IDS", VERIFIER)
    _wire_valid_device_trust(monkeypatch)
    _pin_sync(monkeypatch)
    snap = ga.pilot_onboarding_snapshot()
    assert snap["onboarding"]["enrollment_state"] == po.ENROLL_VERIFIED
    assert snap["execution_gate"]["execution_authorized"] is True
    assert snap["readiness"]["pilot_enrolled"] is True
    assert snap["readiness"]["full_production_ready"] is False


def test_policy_version_label_does_not_satisfy_policy_pin(monkeypatch):
    _, _, registry = ga.policy_runtime_state()
    version = str(registry.get("version", "")) if registry else "v1"
    contract = _contract(policy_reference=version)
    monkeypatch.setenv("USBAY_PILOT_CONTRACT_JSON", json.dumps(contract))
    monkeypatch.setenv(
        "USBAY_PILOT_HUMAN_APPROVAL_JSON", json.dumps(_approval(contract))
    )
    monkeypatch.setenv("USBAY_ENROLLED_DEVICE_FINGERPRINTS", DEVICE)
    monkeypatch.setenv("USBAY_ENROLLED_VERIFIER_IDS", VERIFIER)
    _wire_valid_device_trust(monkeypatch)
    _pin_sync(monkeypatch)
    snap = ga.pilot_onboarding_snapshot()
    assert snap["execution_gate"]["execution_authorized"] is False
    assert snap["execution_gate"]["reason_code"] == po.REASON_POLICY_MISMATCH


def test_malformed_contract_json_fails_closed(monkeypatch):
    monkeypatch.setenv("USBAY_PILOT_CONTRACT_JSON", "{not json")
    _pin_sync(monkeypatch)
    snap = ga.pilot_onboarding_snapshot()
    assert snap["onboarding"]["enrollment_state"] in (po.ENROLL_BLOCKED,)
    assert snap["execution_gate"]["execution_authorized"] is False


def test_malformed_approval_json_fails_closed(monkeypatch):
    contract = _contract()
    monkeypatch.setenv("USBAY_PILOT_CONTRACT_JSON", json.dumps(contract))
    monkeypatch.setenv("USBAY_PILOT_HUMAN_APPROVAL_JSON", "[broken")
    monkeypatch.setenv("USBAY_ENROLLED_DEVICE_FINGERPRINTS", DEVICE)
    monkeypatch.setenv("USBAY_ENROLLED_VERIFIER_IDS", VERIFIER)
    _wire_valid_device_trust(monkeypatch)
    _pin_sync(monkeypatch)
    snap = ga.pilot_onboarding_snapshot()
    assert snap["execution_gate"]["execution_authorized"] is False
    assert snap["onboarding"]["reason_code"] == po.REASON_MISSING_HUMAN_APPROVAL


def test_no_enrollment_reports_onboarding_ready_but_never_authorizes(monkeypatch):
    _pin_sync(monkeypatch)
    snap = ga.pilot_onboarding_snapshot()
    assert snap["onboarding"]["enrollment_state"] == po.ENROLL_NOT_ENROLLED
    assert snap["execution_gate"]["execution_authorized"] is False
    assert snap["readiness"]["pilot_enrolled"] is False
    assert snap["readiness"]["failclosed_suite"] == "release_gated"


def test_endpoint_surface_redacts_approval_reference(monkeypatch):
    contract = _contract()
    monkeypatch.setenv("USBAY_PILOT_CONTRACT_JSON", json.dumps(contract))
    monkeypatch.setenv(
        "USBAY_PILOT_HUMAN_APPROVAL_JSON", json.dumps(_approval(contract))
    )
    monkeypatch.setenv("USBAY_ENROLLED_DEVICE_FINGERPRINTS", DEVICE)
    monkeypatch.setenv("USBAY_ENROLLED_VERIFIER_IDS", VERIFIER)
    _wire_valid_device_trust(monkeypatch)
    _pin_sync(monkeypatch)
    serialized = json.dumps(ga.api_governance_pilot_onboarding())
    assert "APPR-INT-1" not in serialized
    assert contract["pilot_id"] not in serialized
    for forbidden in ("-----BEGIN", "secret", "password", "token"):
        assert forbidden not in serialized
