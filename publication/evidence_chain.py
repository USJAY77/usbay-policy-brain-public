"""Hash-only evidence chain verification for publication decisions."""

from __future__ import annotations

from collections.abc import Iterable

from publication.models import (
    BlockReason,
    EvidenceChainEntry,
    EvidenceChainStage,
    EvidenceChainVerificationResult,
    RegistryRecord,
    hash_payload,
    is_sha256_ref,
)


REQUIRED_EVIDENCE_ORDER = (
    EvidenceChainStage.REGISTRY,
    EvidenceChainStage.CLASSIFICATION,
    EvidenceChainStage.SENSITIVE_DATA_SCAN,
    EvidenceChainStage.HUMAN_APPROVAL,
    EvidenceChainStage.RUNTIME_VALIDATOR,
    EvidenceChainStage.CONNECTOR_GATE,
    EvidenceChainStage.AUDIT_PERSISTENCE,
    EvidenceChainStage.FINAL_AGGREGATOR,
)


def verify_evidence_chain(
    *,
    record: RegistryRecord,
    entries: Iterable[EvidenceChainEntry],
) -> EvidenceChainVerificationResult:
    entry_tuple = tuple(entries)
    evidence_base = {
        "artifact_id": record.artifact_id,
        "artifact_version": record.version,
        "policy_version": record.policy_version,
        "required_order": tuple(stage.value for stage in REQUIRED_EVIDENCE_ORDER),
        "observed_order": tuple(entry.stage.value for entry in entry_tuple),
        "raw_evidence_stored": False,
    }

    if len(entry_tuple) != len(REQUIRED_EVIDENCE_ORDER):
        return EvidenceChainVerificationResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.EVIDENCE_CHAIN_MISSING,
            policy_version=record.policy_version,
            evidence=evidence_base,
        )

    observed_stages = tuple(entry.stage for entry in entry_tuple)
    if len(set(observed_stages)) != len(observed_stages):
        return EvidenceChainVerificationResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.DUPLICATE_EVIDENCE_STAGE,
            policy_version=record.policy_version,
            evidence=evidence_base,
        )

    if observed_stages != REQUIRED_EVIDENCE_ORDER:
        return EvidenceChainVerificationResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.EVIDENCE_ORDER_INVALID,
            policy_version=record.policy_version,
            evidence=evidence_base,
        )

    for entry in entry_tuple:
        if entry.artifact_id != record.artifact_id or entry.artifact_version != record.version:
            return EvidenceChainVerificationResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.EVIDENCE_ARTIFACT_MISMATCH,
                policy_version=record.policy_version,
                evidence=evidence_base,
            )
        if entry.policy_version != record.policy_version:
            return EvidenceChainVerificationResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.POLICY_VERSION_MISMATCH,
                policy_version=record.policy_version,
                evidence=evidence_base,
            )
        if not is_sha256_ref(entry.evidence_hash):
            return EvidenceChainVerificationResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.HASH_MISMATCH,
                policy_version=record.policy_version,
                evidence=evidence_base,
            )

    redacted_chain = tuple(entry.to_dict() for entry in entry_tuple)
    evidence = {
        **evidence_base,
        "stage_count": len(entry_tuple),
        "chain_hash": hash_payload(redacted_chain),
    }
    return EvidenceChainVerificationResult.verified_chain(
        artifact_id=record.artifact_id,
        policy_version=record.policy_version,
        evidence=evidence,
    )
