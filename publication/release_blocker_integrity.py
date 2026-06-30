"""Fail-closed release blocker integrity validation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from publication.models import (
    CommitScopeResult,
    FinalPublicationReport,
    FinalizationGateResult,
    PolicyBundleReadinessResult,
    PublicationLockReleaseResult,
    PublicationLockResult,
    PublicationReleaseBlockerResult,
    ReleaseBlockerIntegrityResult,
    hash_payload,
    is_sha256_ref,
)
from publication.publication_release_blocker import PUBLICATION_RELEASE_BLOCKER_POLICY_VERSION, validate_publication_release_blocker


RELEASE_BLOCKER_INTEGRITY_POLICY_VERSION = "USBAY-PUBGOV-031"
APPROVED_REASON = "RELEASE_BLOCKER_INTEGRITY_APPROVED"
BLOCKED_REASON = "RELEASE_BLOCKER_INTEGRITY_BLOCKED"
ALLOWED_INTEGRITY_CONTRACT_FIELDS = (
    "commit_scope_result",
    "policy_bundle_readiness_result",
    "finalization_gate_result",
    "publication_lock_result",
    "publication_lock_release_result",
    "publication_release_blocker_result",
    "final_publication_report",
    "release_hash",
    "automatic_publication_requested",
    "connector_execution_requested",
    "http_api_publication_requested",
)


def validate_release_blocker_integrity(
    *,
    commit_scope_result: CommitScopeResult | None,
    policy_bundle_readiness_result: PolicyBundleReadinessResult | None,
    finalization_gate_result: FinalizationGateResult | None,
    publication_lock_result: PublicationLockResult | None,
    publication_lock_release_result: PublicationLockReleaseResult | None,
    publication_release_blocker_result: PublicationReleaseBlockerResult | None,
    final_publication_report: FinalPublicationReport | None,
    release_hash: str | None,
    automatic_publication_requested: bool = False,
    connector_execution_requested: bool = False,
    http_api_publication_requested: bool = False,
    contract_fields: Mapping[str, Any] | None = None,
) -> ReleaseBlockerIntegrityResult:
    """Approve only if release blocker evidence matches the current ordered gate chain."""

    rejected_reasons: list[str] = []

    if contract_fields is not None:
        unknown_fields = tuple(sorted(set(contract_fields) - set(ALLOWED_INTEGRITY_CONTRACT_FIELDS)))
        if unknown_fields:
            rejected_reasons.append("unknown_release_contract_field")

    if automatic_publication_requested:
        rejected_reasons.append("automatic_publication_attempt")
    if connector_execution_requested:
        rejected_reasons.append("connector_execution_attempt")
    if http_api_publication_requested:
        rejected_reasons.append("http_api_publication_attempt")

    if publication_release_blocker_result is None:
        rejected_reasons.append("missing_release_blocker")
    else:
        if not publication_release_blocker_result.approved or publication_release_blocker_result.rejected:
            rejected_reasons.append("invalid_release_blocker")
        if not is_sha256_ref(publication_release_blocker_result.release_block_id):
            rejected_reasons.append("missing_release_blocker_id")
        if not is_sha256_ref(publication_release_blocker_result.evidence_hash):
            rejected_reasons.append("missing_release_blocker_evidence_hash")
        if publication_release_blocker_result.policy_version != PUBLICATION_RELEASE_BLOCKER_POLICY_VERSION:
            rejected_reasons.append("invalid_release_blocker_policy_version")

    if publication_lock_result is None:
        rejected_reasons.append("missing_publication_lock")
    else:
        if not is_sha256_ref(publication_lock_result.lock_id):
            rejected_reasons.append("missing_release_lock_id")
        if not is_sha256_ref(publication_lock_result.evidence_hash):
            rejected_reasons.append("missing_release_lock_evidence_hash")

    if finalization_gate_result is None or not is_sha256_ref(finalization_gate_result.evidence_hash if finalization_gate_result else None):
        rejected_reasons.append("missing_finalization_gate_evidence_hash")
    if commit_scope_result is None or not is_sha256_ref(commit_scope_result.evidence_hash if commit_scope_result else None):
        rejected_reasons.append("missing_commit_scope_evidence_hash")
    if policy_bundle_readiness_result is None or not is_sha256_ref(
        policy_bundle_readiness_result.evidence_hash if policy_bundle_readiness_result else None
    ):
        rejected_reasons.append("missing_policy_bundle_readiness_hash")
    if release_hash is None or not is_sha256_ref(release_hash):
        rejected_reasons.append("missing_release_hash")

    expected_blocker = validate_publication_release_blocker(
        commit_scope_result=commit_scope_result,
        policy_bundle_readiness_result=policy_bundle_readiness_result,
        finalization_gate_result=finalization_gate_result,
        publication_lock_result=publication_lock_result,
        publication_lock_release_result=publication_lock_release_result,
        final_publication_report=final_publication_report,
        release_hash=release_hash,
        automatic_publication_requested=automatic_publication_requested,
        connector_execution_requested=connector_execution_requested,
        http_api_publication_requested=http_api_publication_requested,
        contract_fields=contract_fields,
    )

    if not expected_blocker.approved:
        rejected_reasons.extend(expected_blocker.rejected_reasons)
    if publication_release_blocker_result is not None:
        if publication_release_blocker_result.release_block_id != expected_blocker.release_block_id:
            rejected_reasons.append("stale_release_blocker")
        if publication_release_blocker_result.evidence_hash != expected_blocker.evidence_hash:
            rejected_reasons.append("mismatched_release_blocker_hash")
        if finalization_gate_result is not None and finalization_gate_result.evidence_hash not in publication_release_blocker_result.release_block_id:
            # release_block_id is hashed, so the stale/mismatch comparison above is authoritative.
            pass
        if "invalid_finalization_gate" in expected_blocker.rejected_reasons or "missing_finalization_gate" in expected_blocker.rejected_reasons:
            rejected_reasons.append("blocker_generated_before_finalization_gate")
        if "invalid_publication_lock_release" in expected_blocker.rejected_reasons or "missing_publication_lock_release" in expected_blocker.rejected_reasons:
            rejected_reasons.append("blocker_generated_before_lock_release")

    normalized_rejected_reasons = tuple(sorted(set(rejected_reasons)))
    integrity_id = hash_payload(
        {
            "release_block_id": publication_release_blocker_result.release_block_id
            if publication_release_blocker_result is not None
            else "",
            "expected_release_block_id": expected_blocker.release_block_id,
            "policy_version": RELEASE_BLOCKER_INTEGRITY_POLICY_VERSION,
        }
    )
    evidence_hash = hash_payload(
        {
            "integrity_id": integrity_id,
            "release_blocker_evidence_hash": publication_release_blocker_result.evidence_hash
            if publication_release_blocker_result is not None
            else "",
            "expected_release_blocker_evidence_hash": expected_blocker.evidence_hash,
            "rejected_reasons": normalized_rejected_reasons,
            "raw_payload_stored": False,
            "policy_version": RELEASE_BLOCKER_INTEGRITY_POLICY_VERSION,
        }
    )

    if normalized_rejected_reasons:
        return ReleaseBlockerIntegrityResult(
            approved=False,
            rejected=True,
            rejected_reasons=normalized_rejected_reasons,
            evidence_hash=evidence_hash,
            policy_version=RELEASE_BLOCKER_INTEGRITY_POLICY_VERSION,
            integrity_id=integrity_id,
            reason=BLOCKED_REASON,
        )

    return ReleaseBlockerIntegrityResult(
        approved=True,
        rejected=False,
        rejected_reasons=(),
        evidence_hash=evidence_hash,
        policy_version=RELEASE_BLOCKER_INTEGRITY_POLICY_VERSION,
        integrity_id=integrity_id,
        reason=APPROVED_REASON,
    )
