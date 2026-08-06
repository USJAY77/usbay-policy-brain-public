"""Enterprise pilot onboarding control (fail-closed).

Minimum governed onboarding mechanism for the first real enterprise
pilot. This module is pure library code: it validates a pilot identity
contract, an explicit HUMAN approval record, and the already-existing
device-trust validation results (identity / challenge / renewal from
``governance.device_identity_lifecycle``, ``governance.remote_challenge_response``,
``governance.continuous_trust_renewal``) and derives:

* an enrollment state machine
  NOT_ENROLLED -> PENDING_HUMAN_APPROVAL -> ENROLLED ->
  CHALLENGE_REQUIRED -> ATTESTATION_VERIFIED -> VERIFIED
  (any failure -> BLOCKED, never silently recovered)
* separated readiness states
  PLATFORM_READY / PILOT_ONBOARDING_READY / PILOT_ENROLLED /
  PILOT_RUNTIME_READY / FULL_PRODUCTION_READY
* an all-or-nothing enterprise execution gate
  (``execution_authorized`` is True only when every control is valid).

Design constraints honoured here:

* No execution authority derives from PENDING alone.
* AI must not self-approve: approvals whose ``approver_kind`` is not
  ``human`` are rejected; a missing approval fails closed.
* No raw secrets/keys/nonces are placed in evidence — identifiers and
  hashes only (mirrors the existing device-trust evidence rules).
* FULL_PRODUCTION_READY is never derived true by this module.
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from typing import Any, Mapping

# ---------------------------------------------------------------------------
# Contract status model
# ---------------------------------------------------------------------------
STATUS_PENDING = "PENDING"
STATUS_ENROLLED = "ENROLLED"
STATUS_VERIFIED = "VERIFIED"
STATUS_SUSPENDED = "SUSPENDED"
STATUS_REVOKED = "REVOKED"
STATUS_EXPIRED = "EXPIRED"
CONTRACT_STATUSES = {
    STATUS_PENDING,
    STATUS_ENROLLED,
    STATUS_VERIFIED,
    STATUS_SUSPENDED,
    STATUS_REVOKED,
    STATUS_EXPIRED,
}

CONTRACT_REQUIRED_FIELDS = (
    "pilot_id",
    "tenant_id",
    "environment_id",
    "device_id",
    "verifier_id",
    "human_approval_reference",
    "policy_reference",
    "issued_at",
    "expires_at",
    "status",
)

# ---------------------------------------------------------------------------
# Enrollment state machine
# ---------------------------------------------------------------------------
ENROLL_NOT_ENROLLED = "NOT_ENROLLED"
ENROLL_PENDING_HUMAN_APPROVAL = "PENDING_HUMAN_APPROVAL"
ENROLL_ENROLLED = "ENROLLED"
ENROLL_CHALLENGE_REQUIRED = "CHALLENGE_REQUIRED"
ENROLL_ATTESTATION_VERIFIED = "ATTESTATION_VERIFIED"
ENROLL_VERIFIED = "VERIFIED"
ENROLL_BLOCKED = "BLOCKED"

# Reason codes (audit-safe identifiers, never raw material)
REASON_OK = "OK"
REASON_NO_CONTRACT = "PILOT_CONTRACT_MISSING"
REASON_CONTRACT_MALFORMED = "PILOT_CONTRACT_MALFORMED"
REASON_CONTRACT_STATUS_INVALID = "PILOT_CONTRACT_STATUS_INVALID"
REASON_ENROLLMENT_EXPIRED = "PILOT_ENROLLMENT_EXPIRED"
REASON_ENROLLMENT_REVOKED = "PILOT_ENROLLMENT_REVOKED"
REASON_ENROLLMENT_SUSPENDED = "PILOT_ENROLLMENT_SUSPENDED"
REASON_MISSING_HUMAN_APPROVAL = "MISSING_HUMAN_APPROVAL"
REASON_APPROVAL_NOT_HUMAN = "APPROVAL_NOT_HUMAN"
REASON_APPROVAL_NOT_APPROVED = "APPROVAL_DECISION_NOT_APPROVED"
REASON_APPROVAL_PILOT_MISMATCH = "APPROVAL_PILOT_MISMATCH"
REASON_APPROVAL_TENANT_MISMATCH = "APPROVAL_TENANT_MISMATCH"
REASON_APPROVAL_ENVIRONMENT_MISMATCH = "APPROVAL_ENVIRONMENT_MISMATCH"
REASON_APPROVAL_DEVICE_MISMATCH = "APPROVAL_DEVICE_MISMATCH"
REASON_APPROVAL_VERIFIER_MISMATCH = "APPROVAL_VERIFIER_MISMATCH"
REASON_UNKNOWN_DEVICE = "UNKNOWN_DEVICE"
REASON_UNKNOWN_VERIFIER = "UNKNOWN_VERIFIER"
REASON_DEVICE_IDENTITY_INVALID = "DEVICE_IDENTITY_INVALID"
REASON_CHALLENGE_MISSING = "CHALLENGE_REQUIRED"
REASON_CHALLENGE_INVALID = "CHALLENGE_INVALID"
REASON_POLICY_MISMATCH = "POLICY_MISMATCH"
REASON_SYNC_DRIFT = "PRODUCTION_SYNC_NOT_SYNCED"
REASON_EVIDENCE_INVALID = "EVIDENCE_INTEGRITY_INVALID"
REASON_PLATFORM_NOT_READY = "PLATFORM_NOT_READY"
REASON_PILOT_BINDING_MISMATCH = "PILOT_REQUEST_BINDING_MISMATCH"
REASON_APPROVAL_REFERENCE_MISMATCH = "APPROVAL_REFERENCE_MISMATCH"
REASON_PILOT_RUNTIME_NOT_READY = "PILOT_RUNTIME_NOT_READY"

_APPROVAL_REQUIRED_FIELDS = (
    "human_approval_reference",
    "decision",
    "approved_at",
    "approver_kind",
    "approved_pilot_id",
    "approved_tenant_id",
    "approved_environment_id",
    "approved_device_id",
    "approved_verifier_id",
)


def _sha256_id(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PilotOnboardingResult:
    state: str
    status: str
    verified: bool
    reason_code: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "enrollment_state": self.state,
            "contract_status": self.status,
            "verified": self.verified,
            "reason_code": self.reason_code,
            "evidence": dict(self.evidence),
        }


def _blocked(status: str, reason: str, evidence: Mapping[str, Any]) -> PilotOnboardingResult:
    return PilotOnboardingResult(
        state=ENROLL_BLOCKED,
        status=status,
        verified=False,
        reason_code=reason,
        evidence=dict(evidence),
    )


def validate_pilot_contract(
    contract: Mapping[str, Any] | None, *, now: float
) -> tuple[bool, str]:
    """Shape/status/lifetime validation of the pilot identity contract."""
    if not isinstance(contract, Mapping) or not contract:
        return False, REASON_NO_CONTRACT
    for name in CONTRACT_REQUIRED_FIELDS:
        value = contract.get(name)
        if value is None or (isinstance(value, str) and not value.strip()):
            return False, REASON_CONTRACT_MALFORMED
    # Exact canonical enum required — no case/whitespace normalization
    # (fail-closed schema validation).
    status = contract.get("status")
    if not isinstance(status, str) or status not in CONTRACT_STATUSES:
        return False, REASON_CONTRACT_STATUS_INVALID
    try:
        issued_at = float(contract["issued_at"])
        expires_at = float(contract["expires_at"])
    except (TypeError, ValueError):
        return False, REASON_CONTRACT_MALFORMED
    if not (math.isfinite(issued_at) and math.isfinite(expires_at)):
        return False, REASON_CONTRACT_MALFORMED
    if not issued_at <= now < expires_at:
        return False, REASON_ENROLLMENT_EXPIRED
    return True, REASON_OK


def validate_human_approval(
    approval: Mapping[str, Any] | None, contract: Mapping[str, Any]
) -> tuple[bool, str]:
    """Explicit human authorization check. AI must not self-approve."""
    if not isinstance(approval, Mapping) or not approval:
        return False, REASON_MISSING_HUMAN_APPROVAL
    for name in _APPROVAL_REQUIRED_FIELDS:
        value = approval.get(name)
        if value is None or (isinstance(value, str) and not value.strip()):
            return False, REASON_MISSING_HUMAN_APPROVAL
    if str(approval.get("approver_kind", "")).strip().lower() != "human":
        return False, REASON_APPROVAL_NOT_HUMAN
    if str(approval.get("decision", "")).strip().upper() != "APPROVED":
        return False, REASON_APPROVAL_NOT_APPROVED
    if str(approval.get("human_approval_reference")) != str(
        contract.get("human_approval_reference")
    ):
        return False, REASON_MISSING_HUMAN_APPROVAL
    if str(approval.get("approved_pilot_id")) != str(contract.get("pilot_id")):
        return False, REASON_APPROVAL_PILOT_MISMATCH
    if str(approval.get("approved_tenant_id")) != str(contract.get("tenant_id")):
        return False, REASON_APPROVAL_TENANT_MISMATCH
    if str(approval.get("approved_environment_id")) != str(
        contract.get("environment_id")
    ):
        return False, REASON_APPROVAL_ENVIRONMENT_MISMATCH
    if str(approval.get("approved_device_id")) != str(contract.get("device_id")):
        return False, REASON_APPROVAL_DEVICE_MISMATCH
    if str(approval.get("approved_verifier_id")) != str(contract.get("verifier_id")):
        return False, REASON_APPROVAL_VERIFIER_MISMATCH
    return True, REASON_OK


def evaluate_pilot_onboarding(
    *,
    contract: Mapping[str, Any] | None,
    approval: Mapping[str, Any] | None,
    identity_verified: bool,
    identity_device_fingerprint: str,
    challenge_present: bool,
    challenge_verified: bool,
    challenge_reason: str,
    known_device_fingerprints: frozenset[str] | set[str],
    known_verifier_ids: frozenset[str] | set[str],
    revoked_pilot_ids: frozenset[str] | set[str],
    now: float,
) -> PilotOnboardingResult:
    """Run the enrollment state machine. Failure states never recover."""
    if not isinstance(contract, Mapping) or not contract:
        return PilotOnboardingResult(
            state=ENROLL_NOT_ENROLLED,
            status="",
            verified=False,
            reason_code=REASON_NO_CONTRACT,
        )

    status = contract.get("status") if isinstance(contract.get("status"), str) else ""
    evidence: dict[str, Any] = {
        "pilot_id_hash": _sha256_id(str(contract.get("pilot_id", ""))),
        "tenant_id_hash": _sha256_id(str(contract.get("tenant_id", ""))),
        "environment_id_hash": _sha256_id(str(contract.get("environment_id", ""))),
        "device_id_reference": _sha256_id(str(contract.get("device_id", ""))),
        "verifier_id_reference": _sha256_id(str(contract.get("verifier_id", ""))),
        # Approval reference is a correlation identifier — expose only
        # its hash on unauthenticated surfaces.
        "human_approval_reference_hash": _sha256_id(
            str(contract.get("human_approval_reference", ""))
        ),
        "policy_reference": str(contract.get("policy_reference", "")),
    }

    ok, reason = validate_pilot_contract(contract, now=now)
    if not ok:
        return _blocked(status, reason, evidence)
    if str(contract.get("pilot_id")) in revoked_pilot_ids or status == STATUS_REVOKED:
        return _blocked(status, REASON_ENROLLMENT_REVOKED, evidence)
    if status == STATUS_SUSPENDED:
        return _blocked(status, REASON_ENROLLMENT_SUSPENDED, evidence)
    if status == STATUS_EXPIRED:
        return _blocked(status, REASON_ENROLLMENT_EXPIRED, evidence)

    # Human authority: PENDING without approval is a legitimate waiting
    # state (with zero execution authority); anything past PENDING with
    # a missing/invalid approval fails closed.
    approval_ok, approval_reason = validate_human_approval(approval, contract)
    if not approval_ok:
        if status == STATUS_PENDING and approval_reason == REASON_MISSING_HUMAN_APPROVAL:
            return PilotOnboardingResult(
                state=ENROLL_PENDING_HUMAN_APPROVAL,
                status=status,
                verified=False,
                reason_code=REASON_MISSING_HUMAN_APPROVAL,
                evidence=evidence,
            )
        return _blocked(status, approval_reason, evidence)
    evidence["approval_decision"] = "APPROVED"

    # Device / verifier binding against the trusted registries.
    if str(contract.get("device_id")) not in known_device_fingerprints:
        return _blocked(status, REASON_UNKNOWN_DEVICE, evidence)
    if str(contract.get("verifier_id")) not in known_verifier_ids:
        return _blocked(status, REASON_UNKNOWN_VERIFIER, evidence)

    if status == STATUS_PENDING:
        # Approved but the contract has not been promoted to ENROLLED by
        # the governed process; no authority derives from PENDING alone.
        return PilotOnboardingResult(
            state=ENROLL_PENDING_HUMAN_APPROVAL,
            status=status,
            verified=False,
            reason_code=REASON_OK,
            evidence=evidence,
        )

    # Device identity attestation (existing validator result).
    if not identity_verified:
        return _blocked(status, REASON_DEVICE_IDENTITY_INVALID, evidence)
    if identity_device_fingerprint != str(contract.get("device_id")):
        return _blocked(status, REASON_UNKNOWN_DEVICE, evidence)

    # Challenge / replay control (existing validator result).
    if not challenge_present:
        return PilotOnboardingResult(
            state=ENROLL_CHALLENGE_REQUIRED,
            status=status,
            verified=False,
            reason_code=REASON_CHALLENGE_MISSING,
            evidence=evidence,
        )
    if not challenge_verified:
        blocked_evidence = dict(evidence)
        blocked_evidence["challenge_failure_reason"] = str(challenge_reason or "")
        return _blocked(status, REASON_CHALLENGE_INVALID, blocked_evidence)

    if status == STATUS_ENROLLED:
        return PilotOnboardingResult(
            state=ENROLL_ATTESTATION_VERIFIED,
            status=status,
            verified=False,
            reason_code=REASON_OK,
            evidence=evidence,
        )
    # status == VERIFIED with every control valid
    return PilotOnboardingResult(
        state=ENROLL_VERIFIED,
        status=status,
        verified=True,
        reason_code=REASON_OK,
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Readiness derivation — states are never collapsed into each other.
# ---------------------------------------------------------------------------
def readiness_snapshot(
    *,
    platform_checks: Mapping[str, bool],
    onboarding_mechanism_available: bool,
    failclosed_tests_pass: bool | None,
    onboarding_result: PilotOnboardingResult | None,
    attestation_verified: bool,
    policy_valid: bool,
    production_sync_match: bool,
    evidence_chain_valid: bool,
) -> dict[str, Any]:
    platform_ready = bool(platform_checks) and all(platform_checks.values())
    # ``failclosed_tests_pass`` may be None when the runtime cannot
    # verify the suite itself (it is enforced by the release gate, not
    # self-attested); only an explicit False blocks readiness.
    pilot_onboarding_ready = bool(
        platform_ready
        and onboarding_mechanism_available
        and failclosed_tests_pass is not False
    )
    pilot_enrolled = bool(
        onboarding_result is not None
        and onboarding_result.state in (ENROLL_ATTESTATION_VERIFIED, ENROLL_VERIFIED)
        and onboarding_result.reason_code == REASON_OK
    )
    pilot_runtime_ready = bool(
        pilot_enrolled
        and onboarding_result is not None
        and onboarding_result.verified
        and attestation_verified
        and policy_valid
        and production_sync_match
        and evidence_chain_valid
    )
    return {
        "platform_ready": platform_ready,
        "platform_checks": dict(platform_checks),
        "pilot_onboarding_ready": pilot_onboarding_ready,
        "failclosed_suite": (
            "release_gated" if failclosed_tests_pass is None else bool(failclosed_tests_pass)
        ),
        "pilot_enrolled": pilot_enrolled,
        "pilot_runtime_ready": pilot_runtime_ready,
        # Never derived true by enrollment; real production readiness is
        # a separate business decision outside this control.
        "full_production_ready": False,
    }


# ---------------------------------------------------------------------------
# Execution gate — all-or-nothing, no partial success.
# ---------------------------------------------------------------------------
def enterprise_execution_gate(
    *,
    onboarding_result: PilotOnboardingResult | None,
    policy_valid: bool,
    policy_reference_matches: bool,
    production_sync_match: bool,
    evidence_chain_valid: bool,
) -> dict[str, Any]:
    def deny(reason: str) -> dict[str, Any]:
        return {"execution_authorized": False, "reason_code": reason}

    if onboarding_result is None:
        return deny(REASON_NO_CONTRACT)
    if onboarding_result.state != ENROLL_VERIFIED or not onboarding_result.verified:
        reason = onboarding_result.reason_code
        return deny(reason if reason != REASON_OK else REASON_DEVICE_IDENTITY_INVALID)
    if not policy_valid:
        return deny(REASON_POLICY_MISMATCH)
    if not policy_reference_matches:
        return deny(REASON_POLICY_MISMATCH)
    if not production_sync_match:
        return deny(REASON_SYNC_DRIFT)
    if not evidence_chain_valid:
        return deny(REASON_EVIDENCE_INVALID)
    return {"execution_authorized": True, "reason_code": REASON_OK}
