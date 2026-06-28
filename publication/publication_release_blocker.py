"""Fail-closed publication release blocker."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from publication.finalization_gate import FINALIZATION_POLICY_VERSION
from publication.models import (
    CommitScopeResult,
    FinalPublicationReport,
    FinalizationGateResult,
    PolicyBundleReadinessResult,
    PublicationLockReleaseResult,
    PublicationLockResult,
    PublicationReleaseBlockerResult,
    hash_payload,
    is_sha256_ref,
)
from publication.publication_lock import PUBLICATION_LOCK_POLICY_VERSION
from publication.publication_lock_release import PUBLICATION_LOCK_RELEASE_POLICY_VERSION


PUBLICATION_RELEASE_BLOCKER_POLICY_VERSION = "USBAY-PUBGOV-030"
APPROVED_REASON = "PUBLICATION_RELEASE_BLOCKER_APPROVED"
BLOCKED_REASON = "PUBLICATION_RELEASE_BLOCKER_BLOCKED"
ALLOWED_RELEASE_CONTRACT_FIELDS = (
    "commit_scope_result",
    "policy_bundle_readiness_result",
    "finalization_gate_result",
    "publication_lock_result",
    "publication_lock_release_result",
    "final_publication_report",
    "release_hash",
    "automatic_publication_requested",
    "connector_execution_requested",
    "http_api_publication_requested",
)


def validate_publication_release_blocker(
    *,
    commit_scope_result: CommitScopeResult | None,
    policy_bundle_readiness_result: PolicyBundleReadinessResult | None,
    finalization_gate_result: FinalizationGateResult | None,
    publication_lock_result: PublicationLockResult | None,
    publication_lock_release_result: PublicationLockReleaseResult | None,
    final_publication_report: FinalPublicationReport | None,
    release_hash: str | None,
    automatic_publication_requested: bool = False,
    connector_execution_requested: bool = False,
    http_api_publication_requested: bool = False,
    contract_fields: Mapping[str, Any] | None = None,
) -> PublicationReleaseBlockerResult:
    """Approve release readiness only when every upstream local proof is valid."""

    rejected_reasons: list[str] = []

    if contract_fields is not None:
        unknown_fields = tuple(sorted(set(contract_fields) - set(ALLOWED_RELEASE_CONTRACT_FIELDS)))
        if unknown_fields:
            rejected_reasons.append("unknown_release_contract_field")

    if automatic_publication_requested:
        rejected_reasons.append("automatic_publication_attempt")
    if connector_execution_requested:
        rejected_reasons.append("connector_execution_attempt")
    if http_api_publication_requested:
        rejected_reasons.append("http_api_publication_attempt")

    if commit_scope_result is None:
        rejected_reasons.append("missing_commit_scope")
    elif not commit_scope_result.approved:
        rejected_reasons.append("rejected_commit_scope")
    elif not is_sha256_ref(commit_scope_result.evidence_hash):
        rejected_reasons.append("missing_commit_scope_evidence_hash")

    if policy_bundle_readiness_result is None:
        rejected_reasons.append("missing_policy_bundle_readiness")
    elif not policy_bundle_readiness_result.ready:
        rejected_reasons.append("invalid_policy_bundle_readiness")
    elif not is_sha256_ref(policy_bundle_readiness_result.evidence_hash):
        rejected_reasons.append("missing_policy_bundle_readiness_hash")

    if finalization_gate_result is None:
        rejected_reasons.append("missing_finalization_gate")
    elif not finalization_gate_result.ready:
        rejected_reasons.append("invalid_finalization_gate")
    elif not is_sha256_ref(finalization_gate_result.evidence_hash):
        rejected_reasons.append("missing_finalization_gate_evidence_hash")
    elif finalization_gate_result.policy_version != FINALIZATION_POLICY_VERSION:
        rejected_reasons.append("invalid_policy_version")

    if publication_lock_result is None:
        rejected_reasons.append("missing_publication_lock")
    elif not publication_lock_result.locked:
        rejected_reasons.append("invalid_publication_lock")
    elif not is_sha256_ref(publication_lock_result.lock_id):
        rejected_reasons.append("missing_publication_lock_id")
    elif not is_sha256_ref(publication_lock_result.evidence_hash):
        rejected_reasons.append("missing_publication_lock_evidence_hash")
    elif publication_lock_result.policy_version != PUBLICATION_LOCK_POLICY_VERSION:
        rejected_reasons.append("invalid_policy_version")

    if publication_lock_release_result is None:
        rejected_reasons.append("missing_publication_lock_release")
    elif not publication_lock_release_result.approved:
        rejected_reasons.append("invalid_publication_lock_release")
    elif not is_sha256_ref(publication_lock_release_result.evidence_hash):
        rejected_reasons.append("missing_publication_lock_release_evidence_hash")
    elif publication_lock_release_result.policy_version != PUBLICATION_LOCK_RELEASE_POLICY_VERSION:
        rejected_reasons.append("invalid_policy_version")

    if final_publication_report is None:
        rejected_reasons.append("missing_final_publication_report")
    elif not final_publication_report.report_complete:
        rejected_reasons.append("incomplete_final_publication_report")
    elif not is_sha256_ref(final_publication_report.report_hash):
        rejected_reasons.append("missing_final_publication_report_hash")

    if not is_sha256_ref(release_hash):
        rejected_reasons.append("missing_release_hash")
    elif publication_lock_release_result is not None and release_hash != publication_lock_release_result.evidence_hash:
        rejected_reasons.append("mismatched_release_hash")

    normalized_rejected_reasons = tuple(sorted(set(rejected_reasons)))
    release_block_id = _derive_release_block_id(
        commit_scope_result=commit_scope_result,
        policy_bundle_readiness_result=policy_bundle_readiness_result,
        finalization_gate_result=finalization_gate_result,
        publication_lock_result=publication_lock_result,
        publication_lock_release_result=publication_lock_release_result,
        final_publication_report=final_publication_report,
        release_hash=release_hash or "",
    )
    evidence_hash = hash_payload(
        {
            "policy_version": PUBLICATION_RELEASE_BLOCKER_POLICY_VERSION,
            "release_block_id": release_block_id,
            "release_hash": release_hash or "",
            "rejected_reasons": normalized_rejected_reasons,
            "raw_payload_stored": False,
        }
    )

    if normalized_rejected_reasons:
        return PublicationReleaseBlockerResult(
            approved=False,
            rejected=True,
            rejected_reasons=normalized_rejected_reasons,
            evidence_hash=evidence_hash,
            policy_version=PUBLICATION_RELEASE_BLOCKER_POLICY_VERSION,
            release_block_id=release_block_id,
            reason=BLOCKED_REASON,
        )

    return PublicationReleaseBlockerResult(
        approved=True,
        rejected=False,
        rejected_reasons=(),
        evidence_hash=evidence_hash,
        policy_version=PUBLICATION_RELEASE_BLOCKER_POLICY_VERSION,
        release_block_id=release_block_id,
        reason=APPROVED_REASON,
    )


def _derive_release_block_id(
    *,
    commit_scope_result: CommitScopeResult | None,
    policy_bundle_readiness_result: PolicyBundleReadinessResult | None,
    finalization_gate_result: FinalizationGateResult | None,
    publication_lock_result: PublicationLockResult | None,
    publication_lock_release_result: PublicationLockReleaseResult | None,
    final_publication_report: FinalPublicationReport | None,
    release_hash: str,
) -> str:
    return hash_payload(
        {
            "artifact_id": final_publication_report.artifact_id if final_publication_report is not None else "UNKNOWN_ARTIFACT",
            "artifact_version": final_publication_report.artifact_version
            if final_publication_report is not None
            else "UNKNOWN_VERSION",
            "commit_scope_evidence_hash": commit_scope_result.evidence_hash if commit_scope_result is not None else "",
            "policy_bundle_readiness_hash": policy_bundle_readiness_result.evidence_hash
            if policy_bundle_readiness_result is not None
            else "",
            "finalization_gate_evidence_hash": finalization_gate_result.evidence_hash
            if finalization_gate_result is not None
            else "",
            "publication_lock_id": publication_lock_result.lock_id if publication_lock_result is not None else "",
            "publication_lock_evidence_hash": publication_lock_result.evidence_hash if publication_lock_result is not None else "",
            "publication_lock_release_evidence_hash": publication_lock_release_result.evidence_hash
            if publication_lock_release_result is not None
            else "",
            "final_publication_report_hash": final_publication_report.report_hash if final_publication_report is not None else "",
            "release_hash": release_hash,
            "policy_version": PUBLICATION_RELEASE_BLOCKER_POLICY_VERSION,
        }
    )
