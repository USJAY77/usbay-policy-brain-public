"""Fail-closed publication readiness finalization gate."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from publication.models import (
    BlockReason,
    CommitScopeResult,
    EvidenceChainVerificationResult,
    FinalizationGateResult,
    PolicyBundleReadinessResult,
    PublicationDecision,
    PublicationDecisionResult,
    hash_payload,
    is_sha256_ref,
)


FINALIZATION_POLICY_VERSION = "USBAY-PUBGOV-027"
COMMIT_SCOPE_POLICY_VERSION = "USBAY-PUBGOV-024"
READY = "READY"
BLOCKED = "BLOCKED"
FINALIZATION_REQUIRED_INPUTS = (
    "runtime_aggregator_result",
    "commit_scope_result",
    "policy_bundle_readiness_result",
    "evidence_chain_result",
)
ALLOWED_CONTRACT_FIELDS = (*FINALIZATION_REQUIRED_INPUTS, "final_report_complete")
REQUIRED_RUNTIME_HASHES = (
    "registry_hash",
    "classification_hash",
    "sensitive_scan_hash",
    "approval_validation_hash",
    "connector_gate_hash",
    "evidence_chain_verification_hash",
    "commit_scope_evidence_hash",
    "policy_bundle_readiness_evidence_hash",
)


def evaluate_finalization_gate(
    *,
    runtime_aggregator_result: PublicationDecisionResult | None,
    commit_scope_result: CommitScopeResult | None,
    policy_bundle_readiness_result: PolicyBundleReadinessResult | None,
    evidence_chain_result: EvidenceChainVerificationResult | None,
    final_report_complete: bool = True,
    contract_fields: Mapping[str, Any] | None = None,
) -> FinalizationGateResult:
    """Return READY only when all final publication readiness controls are proven."""

    missing_controls: list[str] = []
    evidence: dict[str, Any] = {
        "policy_version": FINALIZATION_POLICY_VERSION,
        "required_inputs": FINALIZATION_REQUIRED_INPUTS,
        "raw_payload_stored": False,
    }

    if contract_fields is not None:
        unknown_fields = tuple(sorted(set(contract_fields) - set(ALLOWED_CONTRACT_FIELDS)))
        if unknown_fields:
            missing_controls.append("unknown_finalization_contract_field")
            evidence["unknown_fields"] = unknown_fields

    if runtime_aggregator_result is None:
        missing_controls.append("runtime_aggregator_result")
    elif (
        not runtime_aggregator_result.publish_allowed
        or runtime_aggregator_result.decision != PublicationDecision.ALLOW_PUBLICATION
        or runtime_aggregator_result.block_reason != BlockReason.NONE
    ):
        missing_controls.append("runtime_aggregator_result")
        evidence["runtime_decision"] = runtime_aggregator_result.decision.value
        evidence["runtime_block_reason"] = runtime_aggregator_result.block_reason.value
    else:
        missing_hashes = _missing_or_malformed_hashes(runtime_aggregator_result.audit.evidence_hashes, REQUIRED_RUNTIME_HASHES)
        if missing_hashes:
            missing_controls.append("required_runtime_hashes")
            evidence["missing_runtime_hashes"] = missing_hashes
        evidence["runtime_policy_version"] = runtime_aggregator_result.audit.policy_version
        evidence["runtime_evidence_hashes"] = {
            name: runtime_aggregator_result.audit.evidence_hashes.get(name, "") for name in REQUIRED_RUNTIME_HASHES
        }

    if commit_scope_result is None:
        missing_controls.append("commit_scope_result")
    elif not commit_scope_result.approved:
        missing_controls.append("commit_scope_result")
        evidence["commit_scope_reason"] = commit_scope_result.reason
    elif not is_sha256_ref(commit_scope_result.evidence_hash):
        missing_controls.append("commit_scope_evidence_hash")
    elif commit_scope_result.policy_version != COMMIT_SCOPE_POLICY_VERSION:
        missing_controls.append("dependency_version_mismatch")
        evidence["commit_scope_policy_version"] = commit_scope_result.policy_version

    if policy_bundle_readiness_result is None:
        missing_controls.append("policy_bundle_readiness_result")
    elif not policy_bundle_readiness_result.ready:
        missing_controls.append("policy_bundle_readiness_result")
        evidence["policy_bundle_block_reason"] = policy_bundle_readiness_result.block_reason.value
    elif not is_sha256_ref(policy_bundle_readiness_result.evidence_hash):
        missing_controls.append("policy_bundle_readiness_evidence_hash")

    if evidence_chain_result is None:
        missing_controls.append("evidence_chain_result")
    elif not evidence_chain_result.verified:
        missing_controls.append("evidence_chain_result")
        evidence["evidence_chain_block_reason"] = evidence_chain_result.block_reason.value
    else:
        chain_hash = evidence_chain_result.audit.evidence_hashes.get("evidence_chain_verification_hash")
        if not is_sha256_ref(chain_hash):
            missing_controls.append("evidence_chain_verification_hash")
        evidence["evidence_chain_policy_version"] = evidence_chain_result.audit.policy_version

    if not final_report_complete:
        missing_controls.append("final_report")

    if _has_dependency_version_mismatch(
        runtime_aggregator_result=runtime_aggregator_result,
        policy_bundle_readiness_result=policy_bundle_readiness_result,
        evidence_chain_result=evidence_chain_result,
    ):
        missing_controls.append("dependency_version_mismatch")

    normalized_missing_controls = tuple(sorted(set(missing_controls)))
    evidence["missing_controls"] = normalized_missing_controls
    evidence_hash = hash_payload(evidence)
    if normalized_missing_controls:
        return FinalizationGateResult(
            ready=False,
            decision=BLOCKED,
            reason="FINALIZATION_BLOCKED",
            missing_controls=normalized_missing_controls,
            evidence_hash=evidence_hash,
            policy_version=FINALIZATION_POLICY_VERSION,
            required_inputs=FINALIZATION_REQUIRED_INPUTS,
        )

    return FinalizationGateResult(
        ready=True,
        decision=READY,
        reason="FINALIZATION_READY",
        missing_controls=(),
        evidence_hash=evidence_hash,
        policy_version=FINALIZATION_POLICY_VERSION,
        required_inputs=FINALIZATION_REQUIRED_INPUTS,
    )


def _missing_or_malformed_hashes(evidence_hashes: Mapping[str, str], required_hashes: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(name for name in required_hashes if not is_sha256_ref(evidence_hashes.get(name)))


def _has_dependency_version_mismatch(
    *,
    runtime_aggregator_result: PublicationDecisionResult | None,
    policy_bundle_readiness_result: PolicyBundleReadinessResult | None,
    evidence_chain_result: EvidenceChainVerificationResult | None,
) -> bool:
    if runtime_aggregator_result is None or policy_bundle_readiness_result is None or evidence_chain_result is None:
        return False
    if not runtime_aggregator_result.publish_allowed or not policy_bundle_readiness_result.ready or not evidence_chain_result.verified:
        return False
    runtime_policy_version = runtime_aggregator_result.audit.policy_version
    return (
        policy_bundle_readiness_result.policy_version != runtime_policy_version
        or evidence_chain_result.audit.policy_version != runtime_policy_version
    )
