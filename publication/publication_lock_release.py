"""Fail-closed publication lock release guard."""

from __future__ import annotations

from publication.finalization_gate import FINALIZATION_POLICY_VERSION
from publication.models import (
    FinalizationGateResult,
    PublicationLockReleaseResult,
    PublicationLockResult,
    hash_payload,
    is_sha256_ref,
)
from publication.publication_lock import PUBLICATION_LOCK_POLICY_VERSION


PUBLICATION_LOCK_RELEASE_POLICY_VERSION = "USBAY-PUBGOV-029"
APPROVED_REASON = "PUBLICATION_LOCK_RELEASE_APPROVED"
BLOCKED_REASON = "PUBLICATION_LOCK_RELEASE_BLOCKED"


def evaluate_publication_lock_release(
    *,
    finalization_gate_result: FinalizationGateResult | None,
    publication_lock_result: PublicationLockResult | None,
    automatic_publication_requested: bool = False,
    external_connector_requested: bool = False,
) -> PublicationLockReleaseResult:
    """Approve local lock release only after finalization and lock proofs pass."""

    rejected_reasons: list[str] = []

    if finalization_gate_result is None:
        rejected_reasons.append("missing_finalization_gate")
    elif not finalization_gate_result.ready:
        rejected_reasons.append("finalization_not_ready")
        rejected_reasons.extend(finalization_gate_result.missing_controls)
    elif not is_sha256_ref(finalization_gate_result.evidence_hash):
        rejected_reasons.append("missing_finalization_evidence_hash")
    elif finalization_gate_result.policy_version != FINALIZATION_POLICY_VERSION:
        rejected_reasons.append("finalization_policy_version_mismatch")

    if publication_lock_result is None:
        rejected_reasons.append("missing_publication_lock")
        lock_id = ""
    else:
        lock_id = publication_lock_result.lock_id
        if not publication_lock_result.locked:
            rejected_reasons.append("publication_lock_not_ready")
            rejected_reasons.extend(publication_lock_result.missing_controls)
        if not is_sha256_ref(publication_lock_result.lock_id):
            rejected_reasons.append("missing_lock_id")
        if not is_sha256_ref(publication_lock_result.evidence_hash):
            rejected_reasons.append("missing_lock_evidence_hash")
        if publication_lock_result.policy_version != PUBLICATION_LOCK_POLICY_VERSION:
            rejected_reasons.append("lock_policy_version_mismatch")

    if automatic_publication_requested:
        rejected_reasons.append("automatic_publication_attempt")
    if external_connector_requested:
        rejected_reasons.append("external_connector_attempt")

    normalized_rejected_reasons = tuple(sorted(set(rejected_reasons)))
    evidence = {
        "policy_version": PUBLICATION_LOCK_RELEASE_POLICY_VERSION,
        "lock_id": lock_id,
        "finalization_gate_evidence_hash": finalization_gate_result.evidence_hash if finalization_gate_result else "",
        "publication_lock_evidence_hash": publication_lock_result.evidence_hash if publication_lock_result else "",
        "rejected_reasons": normalized_rejected_reasons,
        "raw_payload_stored": False,
    }
    evidence_hash = hash_payload(evidence)
    release_id = hash_payload(
        {
            "lock_id": lock_id,
            "finalization_gate_evidence_hash": finalization_gate_result.evidence_hash if finalization_gate_result else "",
            "publication_lock_evidence_hash": publication_lock_result.evidence_hash if publication_lock_result else "",
            "policy_version": PUBLICATION_LOCK_RELEASE_POLICY_VERSION,
        }
    )

    if normalized_rejected_reasons:
        return PublicationLockReleaseResult(
            approved=False,
            release_id=release_id,
            lock_id=lock_id,
            evidence_hash=evidence_hash,
            policy_version=PUBLICATION_LOCK_RELEASE_POLICY_VERSION,
            reason=BLOCKED_REASON,
            rejected_reasons=normalized_rejected_reasons,
        )

    return PublicationLockReleaseResult(
        approved=True,
        release_id=release_id,
        lock_id=lock_id,
        evidence_hash=evidence_hash,
        policy_version=PUBLICATION_LOCK_RELEASE_POLICY_VERSION,
        reason=APPROVED_REASON,
        rejected_reasons=(),
    )
