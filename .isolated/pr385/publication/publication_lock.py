"""Fail-closed publication readiness lock."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from publication.finalization_gate import FINALIZATION_POLICY_VERSION
from publication.models import (
    BlockReason,
    CommitScopeResult,
    EvidenceChainVerificationResult,
    FinalPublicationReport,
    FinalizationGateResult,
    PolicyBundleReadinessResult,
    PublicationLockResult,
    hash_payload,
    is_sha256_ref,
)


PUBLICATION_LOCK_POLICY_VERSION = "USBAY-PUBGOV-028"
LOCKED_READY = "LOCKED_READY"
LOCKED_BLOCKED = "LOCKED_BLOCKED"
PUBLICATION_LOCK_REQUIRED_INPUTS = (
    "finalization_gate_result",
    "policy_bundle_readiness_result",
    "commit_scope_result",
    "evidence_chain_result",
    "final_publication_report",
)
ALLOWED_LOCK_CONTRACT_FIELDS = (
    *PUBLICATION_LOCK_REQUIRED_INPUTS,
    "automatic_publication_requested",
    "external_connector_requested",
)
REQUIRED_REPORT_HASH_FIELDS = (
    "evidence_chain_verification_hash",
    "audit_hash",
    "connector_gate_hash",
    "human_approval_hash",
    "sensitive_scan_hash",
    "classification_hash",
    "registry_hash",
)


def evaluate_publication_lock(
    *,
    finalization_gate_result: FinalizationGateResult | None,
    policy_bundle_readiness_result: PolicyBundleReadinessResult | None,
    commit_scope_result: CommitScopeResult | None,
    evidence_chain_result: EvidenceChainVerificationResult | None,
    final_publication_report: FinalPublicationReport | None,
    automatic_publication_requested: bool = False,
    external_connector_requested: bool = False,
    contract_fields: Mapping[str, Any] | None = None,
) -> PublicationLockResult:
    """Return LOCKED_READY only when the full local publication chain is sealed."""

    missing_controls: list[str] = []
    evidence: dict[str, Any] = {
        "policy_version": PUBLICATION_LOCK_POLICY_VERSION,
        "required_inputs": PUBLICATION_LOCK_REQUIRED_INPUTS,
        "raw_payload_stored": False,
    }

    if contract_fields is not None:
        unknown_fields = tuple(sorted(set(contract_fields) - set(ALLOWED_LOCK_CONTRACT_FIELDS)))
        if unknown_fields:
            missing_controls.append("unknown_publication_lock_contract_field")
            evidence["unknown_fields"] = unknown_fields

    if automatic_publication_requested:
        missing_controls.append("automatic_publication_attempt")
    if external_connector_requested:
        missing_controls.append("external_connector_attempt")

    if finalization_gate_result is None:
        missing_controls.append("finalization_gate_result")
    elif not finalization_gate_result.ready:
        missing_controls.append("finalization_gate_result")
        evidence["finalization_reason"] = finalization_gate_result.reason
    elif not is_sha256_ref(finalization_gate_result.evidence_hash):
        missing_controls.append("finalization_gate_evidence_hash")
    elif finalization_gate_result.policy_version != FINALIZATION_POLICY_VERSION:
        missing_controls.append("dependency_version_mismatch")
        evidence["finalization_policy_version"] = finalization_gate_result.policy_version

    if commit_scope_result is None:
        missing_controls.append("commit_scope_result")
    elif not commit_scope_result.approved:
        missing_controls.append("commit_scope_result")
        evidence["commit_scope_reason"] = commit_scope_result.reason
    elif not is_sha256_ref(commit_scope_result.evidence_hash):
        missing_controls.append("commit_scope_evidence_hash")

    if policy_bundle_readiness_result is None:
        missing_controls.append("policy_bundle_readiness_result")
    elif not policy_bundle_readiness_result.ready:
        missing_controls.append("policy_bundle_readiness_result")
        evidence["policy_bundle_block_reason"] = policy_bundle_readiness_result.block_reason.value
    elif not is_sha256_ref(policy_bundle_readiness_result.evidence_hash):
        missing_controls.append("policy_bundle_readiness_hash")

    if evidence_chain_result is None:
        missing_controls.append("evidence_chain_result")
    elif not evidence_chain_result.verified:
        missing_controls.append("evidence_chain_result")
        evidence["evidence_chain_block_reason"] = evidence_chain_result.block_reason.value
    else:
        chain_hash = evidence_chain_result.audit.evidence_hashes.get("evidence_chain_verification_hash")
        if not is_sha256_ref(chain_hash):
            missing_controls.append("evidence_chain_verification_hash")

    if final_publication_report is None:
        missing_controls.append("final_publication_report")
    elif not final_publication_report.report_complete:
        missing_controls.append("final_publication_report")
    else:
        missing_report_hashes = _missing_report_hashes(final_publication_report)
        if missing_report_hashes:
            missing_controls.append("final_report_required_hashes")
            evidence["missing_report_hashes"] = missing_report_hashes
        evidence["final_report_policy_version"] = final_publication_report.policy_version
        evidence["final_report_stable_hashes"] = _stable_report_hashes(final_publication_report)

    if _has_policy_version_mismatch(
        policy_bundle_readiness_result=policy_bundle_readiness_result,
        evidence_chain_result=evidence_chain_result,
        final_publication_report=final_publication_report,
    ):
        missing_controls.append("policy_version_mismatch")

    lock_id = _derive_lock_id(
        finalization_gate_result=finalization_gate_result,
        commit_scope_result=commit_scope_result,
        policy_bundle_readiness_result=policy_bundle_readiness_result,
        evidence_chain_result=evidence_chain_result,
        final_publication_report=final_publication_report,
    )
    normalized_missing_controls = tuple(sorted(set(missing_controls)))
    evidence["lock_id"] = lock_id
    evidence["missing_controls"] = normalized_missing_controls
    evidence_hash = hash_payload(evidence)

    if normalized_missing_controls:
        return PublicationLockResult(
            locked=False,
            decision=LOCKED_BLOCKED,
            reason="PUBLICATION_LOCK_BLOCKED",
            missing_controls=normalized_missing_controls,
            evidence_hash=evidence_hash,
            policy_version=PUBLICATION_LOCK_POLICY_VERSION,
            lock_id=lock_id,
            required_inputs=PUBLICATION_LOCK_REQUIRED_INPUTS,
        )

    return PublicationLockResult(
        locked=True,
        decision=LOCKED_READY,
        reason="PUBLICATION_LOCK_READY",
        missing_controls=(),
        evidence_hash=evidence_hash,
        policy_version=PUBLICATION_LOCK_POLICY_VERSION,
        lock_id=lock_id,
        required_inputs=PUBLICATION_LOCK_REQUIRED_INPUTS,
    )


def _missing_report_hashes(report: FinalPublicationReport) -> tuple[str, ...]:
    return tuple(name for name in REQUIRED_REPORT_HASH_FIELDS if not is_sha256_ref(getattr(report, name)))


def _stable_report_hashes(report: FinalPublicationReport) -> dict[str, str]:
    return {name: getattr(report, name) for name in REQUIRED_REPORT_HASH_FIELDS}


def _has_policy_version_mismatch(
    *,
    policy_bundle_readiness_result: PolicyBundleReadinessResult | None,
    evidence_chain_result: EvidenceChainVerificationResult | None,
    final_publication_report: FinalPublicationReport | None,
) -> bool:
    if policy_bundle_readiness_result is None or evidence_chain_result is None or final_publication_report is None:
        return False
    if not policy_bundle_readiness_result.ready or not evidence_chain_result.verified or not final_publication_report.report_complete:
        return False
    return (
        policy_bundle_readiness_result.policy_version != final_publication_report.policy_version
        or evidence_chain_result.audit.policy_version != final_publication_report.policy_version
    )


def _derive_lock_id(
    *,
    finalization_gate_result: FinalizationGateResult | None,
    commit_scope_result: CommitScopeResult | None,
    policy_bundle_readiness_result: PolicyBundleReadinessResult | None,
    evidence_chain_result: EvidenceChainVerificationResult | None,
    final_publication_report: FinalPublicationReport | None,
) -> str:
    chain_hash = ""
    if evidence_chain_result is not None:
        chain_hash = evidence_chain_result.audit.evidence_hashes.get("evidence_chain_verification_hash", "")
    return hash_payload(
        {
            "artifact_id": final_publication_report.artifact_id if final_publication_report is not None else "UNKNOWN_ARTIFACT",
            "artifact_version": final_publication_report.artifact_version
            if final_publication_report is not None
            else "UNKNOWN_VERSION",
            "target_channel": final_publication_report.target_channel if final_publication_report is not None else "UNKNOWN_CHANNEL",
            "finalization_gate_evidence_hash": finalization_gate_result.evidence_hash
            if finalization_gate_result is not None
            else "",
            "commit_scope_evidence_hash": commit_scope_result.evidence_hash if commit_scope_result is not None else "",
            "policy_bundle_readiness_hash": policy_bundle_readiness_result.evidence_hash
            if policy_bundle_readiness_result is not None
            else "",
            "evidence_chain_verification_hash": chain_hash,
            "report_hashes": _stable_report_hashes(final_publication_report) if final_publication_report is not None else {},
            "policy_version": final_publication_report.policy_version if final_publication_report is not None else "UNKNOWN",
        }
    )
