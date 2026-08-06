"""Fail-closed tests for the enterprise pilot onboarding control.

Covers the required negative matrix: every missing/invalid control
blocks; only a complete, human-approved, attested enrollment becomes
eligible for runtime authorization. No fake production identities —
fixtures only.
"""
from __future__ import annotations

import pytest

from governance import pilot_onboarding as po

NOW = 1_800_000_000.0
DEVICE = "d" * 64
VERIFIER = "v" * 64

CONTRACT = {
    "pilot_id": "pilot-test-001",
    "tenant_id": "tenant-test",
    "environment_id": "env-test",
    "device_id": DEVICE,
    "verifier_id": VERIFIER,
    "human_approval_reference": "APPR-TEST-1",
    "policy_reference": "policyhash",
    "issued_at": NOW - 100,
    "expires_at": NOW + 10_000,
    "status": "VERIFIED",
}

APPROVAL = {
    "human_approval_reference": "APPR-TEST-1",
    "decision": "APPROVED",
    "approved_at": "2026-08-06T00:00:00Z",
    "approver_kind": "human",
    "approved_pilot_id": "pilot-test-001",
    "approved_tenant_id": "tenant-test",
    "approved_environment_id": "env-test",
    "approved_device_id": DEVICE,
    "approved_verifier_id": VERIFIER,
}


def evaluate(**overrides):
    kwargs = dict(
        contract=CONTRACT,
        approval=APPROVAL,
        identity_verified=True,
        identity_device_fingerprint=DEVICE,
        challenge_present=True,
        challenge_verified=True,
        challenge_reason="",
        known_device_fingerprints={DEVICE},
        known_verifier_ids={VERIFIER},
        revoked_pilot_ids=set(),
        now=NOW,
    )
    kwargs.update(overrides)
    return po.evaluate_pilot_onboarding(**kwargs)


# --- negative matrix -------------------------------------------------------

def test_1_no_customer_enrollment_blocks():
    result = evaluate(contract=None)
    assert result.state == po.ENROLL_NOT_ENROLLED
    assert not result.verified


def test_2_missing_human_approval_blocks():
    result = evaluate(approval=None)
    assert result.state == po.ENROLL_BLOCKED
    assert result.reason_code == po.REASON_MISSING_HUMAN_APPROVAL


def test_2b_ai_self_approval_blocks():
    result = evaluate(approval={**APPROVAL, "approver_kind": "ai"})
    assert result.state == po.ENROLL_BLOCKED
    assert result.reason_code == po.REASON_APPROVAL_NOT_HUMAN


def test_3_unknown_device_blocks():
    result = evaluate(known_device_fingerprints=set())
    assert result.state == po.ENROLL_BLOCKED
    assert result.reason_code == po.REASON_UNKNOWN_DEVICE


def test_4_unknown_verifier_blocks():
    result = evaluate(known_verifier_ids=set())
    assert result.state == po.ENROLL_BLOCKED
    assert result.reason_code == po.REASON_UNKNOWN_VERIFIER


def test_5_invalid_identity_signature_blocks():
    result = evaluate(identity_verified=False)
    assert result.state == po.ENROLL_BLOCKED
    assert result.reason_code == po.REASON_DEVICE_IDENTITY_INVALID


def test_6_expired_or_invalid_challenge_blocks():
    result = evaluate(challenge_verified=False, challenge_reason="CHALLENGE_EXPIRED")
    assert result.state == po.ENROLL_BLOCKED
    assert result.reason_code == po.REASON_CHALLENGE_INVALID
    assert result.evidence.get("challenge_failure_reason") == "CHALLENGE_EXPIRED"


def test_7_replayed_nonce_blocks():
    result = evaluate(challenge_verified=False, challenge_reason="NONCE_REPLAYED")
    assert result.state == po.ENROLL_BLOCKED
    assert result.reason_code == po.REASON_CHALLENGE_INVALID


def test_8_revoked_enrollment_blocks():
    assert evaluate(revoked_pilot_ids={"pilot-test-001"}).reason_code == po.REASON_ENROLLMENT_REVOKED
    assert evaluate(contract={**CONTRACT, "status": "REVOKED"}).reason_code == po.REASON_ENROLLMENT_REVOKED


def test_9_expired_enrollment_blocks():
    result = evaluate(contract={**CONTRACT, "expires_at": NOW - 1})
    assert result.state == po.ENROLL_BLOCKED
    assert result.reason_code == po.REASON_ENROLLMENT_EXPIRED


def test_10_wrong_tenant_blocks():
    result = evaluate(approval={**APPROVAL, "approved_tenant_id": "other-tenant"})
    assert result.state == po.ENROLL_BLOCKED
    assert result.reason_code == po.REASON_APPROVAL_TENANT_MISMATCH


def test_11_wrong_environment_blocks():
    result = evaluate(approval={**APPROVAL, "approved_environment_id": "other-env"})
    assert result.state == po.ENROLL_BLOCKED
    assert result.reason_code == po.REASON_APPROVAL_ENVIRONMENT_MISMATCH


def test_11b_wrong_device_or_verifier_in_approval_blocks():
    assert evaluate(approval={**APPROVAL, "approved_device_id": "x"}).reason_code == po.REASON_APPROVAL_DEVICE_MISMATCH
    assert evaluate(approval={**APPROVAL, "approved_verifier_id": "x"}).reason_code == po.REASON_APPROVAL_VERIFIER_MISMATCH


def test_12_policy_mismatch_blocks_at_gate():
    result = evaluate()
    gate = po.enterprise_execution_gate(
        onboarding_result=result,
        policy_valid=True,
        policy_reference_matches=False,
        production_sync_match=True,
        evidence_chain_valid=True,
    )
    assert gate == {"execution_authorized": False, "reason_code": po.REASON_POLICY_MISMATCH}


def test_13_production_sync_drift_blocks_at_gate():
    gate = po.enterprise_execution_gate(
        onboarding_result=evaluate(),
        policy_valid=True,
        policy_reference_matches=True,
        production_sync_match=False,
        evidence_chain_valid=True,
    )
    assert gate["execution_authorized"] is False
    assert gate["reason_code"] == po.REASON_SYNC_DRIFT


def test_14_missing_evidence_integrity_blocks_at_gate():
    gate = po.enterprise_execution_gate(
        onboarding_result=evaluate(),
        policy_valid=True,
        policy_reference_matches=True,
        production_sync_match=True,
        evidence_chain_valid=False,
    )
    assert gate["execution_authorized"] is False
    assert gate["reason_code"] == po.REASON_EVIDENCE_INVALID


def test_15_valid_complete_enrollment_is_eligible():
    result = evaluate()
    assert result.state == po.ENROLL_VERIFIED
    assert result.verified
    gate = po.enterprise_execution_gate(
        onboarding_result=result,
        policy_valid=True,
        policy_reference_matches=True,
        production_sync_match=True,
        evidence_chain_valid=True,
    )
    assert gate == {"execution_authorized": True, "reason_code": po.REASON_OK}


# --- state machine progression --------------------------------------------

def test_pending_without_approval_is_waiting_not_authorized():
    result = evaluate(contract={**CONTRACT, "status": "PENDING"}, approval=None)
    assert result.state == po.ENROLL_PENDING_HUMAN_APPROVAL
    assert not result.verified
    gate = po.enterprise_execution_gate(
        onboarding_result=result,
        policy_valid=True,
        policy_reference_matches=True,
        production_sync_match=True,
        evidence_chain_valid=True,
    )
    assert gate["execution_authorized"] is False


def test_pending_with_approval_has_no_authority():
    result = evaluate(contract={**CONTRACT, "status": "PENDING"})
    assert result.state == po.ENROLL_PENDING_HUMAN_APPROVAL
    assert not result.verified


def test_enrolled_without_challenge_is_challenge_required():
    result = evaluate(contract={**CONTRACT, "status": "ENROLLED"}, challenge_present=False)
    assert result.state == po.ENROLL_CHALLENGE_REQUIRED
    assert not result.verified


def test_enrolled_with_attestation_is_attestation_verified_not_verified():
    result = evaluate(contract={**CONTRACT, "status": "ENROLLED"})
    assert result.state == po.ENROLL_ATTESTATION_VERIFIED
    assert not result.verified


def test_suspended_blocks():
    result = evaluate(contract={**CONTRACT, "status": "SUSPENDED"})
    assert result.state == po.ENROLL_BLOCKED
    assert result.reason_code == po.REASON_ENROLLMENT_SUSPENDED


# --- readiness separation ---------------------------------------------------

_PLATFORM_OK = {
    "policy_registry_valid": True,
    "runtime_mode_normal": True,
    "replay_protection_active": True,
    "evidence_chain_valid": True,
    "production_sync_enforced_and_matching": True,
}


def _readiness(result, **overrides):
    kwargs = dict(
        platform_checks=_PLATFORM_OK,
        onboarding_mechanism_available=True,
        failclosed_tests_pass=True,
        onboarding_result=result,
        attestation_verified=True,
        policy_valid=True,
        production_sync_match=True,
        evidence_chain_valid=True,
    )
    kwargs.update(overrides)
    return po.readiness_snapshot(**kwargs)


def test_onboarding_ready_without_enrollment():
    snap = _readiness(evaluate(contract=None))
    assert snap["platform_ready"] is True
    assert snap["pilot_onboarding_ready"] is True
    assert snap["pilot_enrolled"] is False
    assert snap["pilot_runtime_ready"] is False
    assert snap["full_production_ready"] is False


def test_platform_failure_blocks_onboarding_readiness():
    checks = {**_PLATFORM_OK, "production_sync_enforced_and_matching": False}
    snap = _readiness(evaluate(contract=None), platform_checks=checks)
    assert snap["platform_ready"] is False
    assert snap["pilot_onboarding_ready"] is False


def test_full_enrollment_reaches_runtime_ready_but_never_full_production():
    snap = _readiness(evaluate())
    assert snap["pilot_enrolled"] is True
    assert snap["pilot_runtime_ready"] is True
    assert snap["full_production_ready"] is False


def test_runtime_ready_requires_sync_and_evidence():
    assert _readiness(evaluate(), production_sync_match=False)["pilot_runtime_ready"] is False
    assert _readiness(evaluate(), evidence_chain_valid=False)["pilot_runtime_ready"] is False


# --- evidence hygiene --------------------------------------------------------

def test_evidence_contains_only_hashes_and_references():
    result = evaluate()
    ev = result.evidence
    assert ev["pilot_id_hash"] != CONTRACT["pilot_id"]
    assert len(ev["pilot_id_hash"]) == 64
    assert ev["tenant_id_hash"] != CONTRACT["tenant_id"]
    serialized = str(ev).lower()
    for forbidden in ("private", "secret", "password", "token", "-----begin"):
        assert forbidden not in serialized


# --- review-hardening: canonical schema, finite lifetimes -------------------

def test_noncanonical_status_casing_blocks():
    result = evaluate(contract={**CONTRACT, "status": "verified"})
    assert result.state == po.ENROLL_BLOCKED
    assert result.reason_code == po.REASON_CONTRACT_STATUS_INVALID


def test_nonfinite_expiry_blocks():
    result = evaluate(contract={**CONTRACT, "expires_at": "inf"})
    assert result.state == po.ENROLL_BLOCKED
    assert result.reason_code == po.REASON_CONTRACT_MALFORMED


def test_evidence_never_contains_raw_approval_reference():
    result = evaluate()
    assert "human_approval_reference" not in result.evidence
    assert result.evidence["human_approval_reference_hash"] != CONTRACT["human_approval_reference"]
    assert "approved_at" not in result.evidence
