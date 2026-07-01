"""Local connector eligibility gate.

This module never calls external connectors. It only evaluates whether a
publication artifact is eligible for a future human-controlled connector step.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from publication.models import (
    ApprovalValidationResult,
    AuditPersistenceResult,
    BlockReason,
    ConnectorEligibilityResult,
    ConnectorGateResult,
    PublicationDecisionResult,
    RegistryRecord,
    SensitiveScanResult,
    TargetChannel,
)


DEFAULT_ALLOWED_CHANNELS = {
    TargetChannel.LINKEDIN.value,
    TargetChannel.NOTION.value,
    TargetChannel.PAGES.value,
    TargetChannel.CUSTOMER_DOCUMENT.value,
    TargetChannel.PRICING_ARTIFACT.value,
    TargetChannel.PUBLIC_ARTIFACT.value,
    # Backward-compatible schema aliases from PUBGOV-007.
    TargetChannel.PRICING_PDF.value,
    TargetChannel.PUBLIC_PDF.value,
}
KNOWN_TARGET_CHANNELS = set(DEFAULT_ALLOWED_CHANNELS)
PUBLICATION_ELIGIBLE_LIFECYCLE_STATES = {"APPROVED", "PUBLISH_ELIGIBLE"}


def allowed_channels_from_policy(connector_policy: dict[str, object] | None = None) -> set[str]:
    if connector_policy is None:
        return set(DEFAULT_ALLOWED_CHANNELS)
    channels = connector_policy.get("allowed_target_channels")
    if channels is None:
        return set(DEFAULT_ALLOWED_CHANNELS)
    if not isinstance(channels, list) or not all(isinstance(channel, str) for channel in channels):
        return set()
    return set(channels)


@dataclass(frozen=True)
class ConnectorGateValidator:
    connector_policy: dict[str, object] | None = None
    allowed_channels: frozenset[str] | None = None

    def validate(
        self,
        *,
        record: RegistryRecord,
        registry_result: PublicationDecisionResult,
        classification_result: PublicationDecisionResult,
        sensitive_scan_result: SensitiveScanResult | None,
        approval_result: ApprovalValidationResult | None,
        audit_result: AuditPersistenceResult | None,
        automatic_publication_requested: bool = False,
    ) -> ConnectorEligibilityResult:
        return evaluate_connector_gate(
            record=record,
            registry_result=registry_result,
            classification_result=classification_result,
            sensitive_scan_result=sensitive_scan_result,
            approval_result=approval_result,
            audit_result=audit_result,
            connector_policy=self.connector_policy,
            allowed_channels=self.allowed_channels,
            automatic_publication_requested=automatic_publication_requested,
        )


def evaluate_connector_gate(
    *,
    record: RegistryRecord,
    registry_result: PublicationDecisionResult | None,
    classification_result: PublicationDecisionResult | None,
    sensitive_scan_result: SensitiveScanResult | None,
    approval_result: ApprovalValidationResult | None,
    audit_result: AuditPersistenceResult | None,
    connector_policy: dict[str, object] | None = None,
    allowed_channels: Iterable[str] | None = None,
    automatic_publication_requested: bool = False,
) -> ConnectorEligibilityResult:
    policy_version = record.policy_version
    allowed = set(allowed_channels) if allowed_channels is not None else allowed_channels_from_policy(connector_policy)
    evidence_base = {
        "artifact_id": record.artifact_id,
        "target_channel": record.target_channel,
        "publish_allowed": False,
        "automatic_publication_requested": automatic_publication_requested,
        "raw_content_stored": False,
    }

    policy_mismatch_reason = _connector_policy_mismatch(record, connector_policy, allowed)
    if policy_mismatch_reason is not None:
        return ConnectorGateResult.blocked(
            artifact_id=record.artifact_id,
            target_channel=record.target_channel,
            reason=policy_mismatch_reason,
            policy_version=policy_version,
            evidence=evidence_base,
        )
    if automatic_publication_requested:
        return ConnectorGateResult.blocked(
            artifact_id=record.artifact_id,
            target_channel=record.target_channel,
            reason=BlockReason.AUTO_PUBLICATION_FORBIDDEN,
            policy_version=policy_version,
            evidence=evidence_base,
        )
    if record.target_channel not in KNOWN_TARGET_CHANNELS:
        return ConnectorGateResult.blocked(
            artifact_id=record.artifact_id,
            target_channel=record.target_channel,
            reason=BlockReason.CONNECTOR_TARGET_UNKNOWN,
            policy_version=policy_version,
            evidence=evidence_base,
        )
    if record.target_channel not in allowed:
        return ConnectorGateResult.blocked(
            artifact_id=record.artifact_id,
            target_channel=record.target_channel,
            reason=BlockReason.CONNECTOR_TARGET_UNKNOWN,
            policy_version=policy_version,
            evidence=evidence_base,
        )
    if record.lifecycle_state not in PUBLICATION_ELIGIBLE_LIFECYCLE_STATES:
        return ConnectorGateResult.blocked(
            artifact_id=record.artifact_id,
            target_channel=record.target_channel,
            reason=BlockReason.INVALID_FIELD_VALUE,
            policy_version=policy_version,
            evidence=evidence_base,
        )
    upstream_block = _first_upstream_block(
        record=record,
        registry_result=registry_result,
        classification_result=classification_result,
        sensitive_scan_result=sensitive_scan_result,
        approval_result=approval_result,
        audit_result=audit_result,
    )
    if upstream_block is not None:
        return ConnectorGateResult.blocked(
            artifact_id=record.artifact_id,
            target_channel=record.target_channel,
            reason=upstream_block,
            policy_version=policy_version,
            evidence=evidence_base,
        )

    missing_hash_reason = _missing_required_hash(
        sensitive_scan_result=sensitive_scan_result,
        approval_result=approval_result,
        audit_result=audit_result,
    )
    if missing_hash_reason is not None:
        return ConnectorGateResult.blocked(
            artifact_id=record.artifact_id,
            target_channel=record.target_channel,
            reason=missing_hash_reason,
            policy_version=policy_version,
            evidence=evidence_base,
        )

    evidence = {
        "artifact_id": record.artifact_id,
        "artifact_version": record.version,
        "target_channel": record.target_channel,
        "classification": record.classification,
        "classification_hash": record.classification_hash,
        "sensitive_scan_hash": sensitive_scan_result.audit.evidence_hashes["sensitive_scan_hash"],
        "approval_hash": approval_result.audit.evidence_hashes["approval_validation_hash"],
        "audit_hash": audit_result.audit.evidence_hashes["evidence_chain_hash"],
        "publish_allowed": True,
        "automatic_publication_requested": False,
        "raw_content_stored": False,
    }
    return ConnectorGateResult.allowed(
        artifact_id=record.artifact_id,
        target_channel=record.target_channel,
        policy_version=policy_version,
        evidence=evidence,
    )


def _first_upstream_block(
    *,
    record: RegistryRecord,
    registry_result: PublicationDecisionResult | None,
    classification_result: PublicationDecisionResult | None,
    sensitive_scan_result: SensitiveScanResult | None,
    approval_result: ApprovalValidationResult | None,
    audit_result: AuditPersistenceResult | None,
) -> BlockReason | None:
    if registry_result is None:
        return BlockReason.VALIDATOR_RESULT_MISSING
    if registry_result.artifact_id != record.artifact_id:
        return BlockReason.VALIDATOR_RESULT_MISSING
    if not registry_result.publish_allowed:
        return registry_result.block_reason
    if classification_result is None:
        return BlockReason.CLASSIFICATION_MISSING
    if classification_result.artifact_id != record.artifact_id:
        return BlockReason.CLASSIFICATION_MISSING
    if not classification_result.publish_allowed:
        return classification_result.block_reason
    if sensitive_scan_result is None:
        return BlockReason.SENSITIVE_SCAN_MISSING
    if sensitive_scan_result.artifact_id != record.artifact_id:
        return BlockReason.INVALID_SCAN_INPUT
    if not sensitive_scan_result.passed:
        return sensitive_scan_result.block_reason
    if approval_result is None:
        return BlockReason.HUMAN_APPROVAL_MISSING
    if approval_result.artifact_id != record.artifact_id:
        return BlockReason.MISSING_APPROVAL_EVIDENCE
    if not approval_result.passed:
        return approval_result.block_reason
    if audit_result is None:
        return BlockReason.AUDIT_EVENT_MISSING
    if audit_result.artifact_id != record.artifact_id:
        return BlockReason.AUDIT_EVENT_MISSING
    if not audit_result.persisted:
        return audit_result.block_reason
    return None


def _missing_required_hash(
    *,
    sensitive_scan_result: SensitiveScanResult,
    approval_result: ApprovalValidationResult,
    audit_result: AuditPersistenceResult,
) -> BlockReason | None:
    if "sensitive_scan_hash" not in sensitive_scan_result.audit.evidence_hashes:
        return BlockReason.SENSITIVE_SCAN_HASH_MISSING
    if "approval_validation_hash" not in approval_result.audit.evidence_hashes:
        return BlockReason.APPROVAL_HASH_MISSING
    if "evidence_chain_hash" not in audit_result.audit.evidence_hashes:
        return BlockReason.AUDIT_EVENT_MISSING
    return None


def _connector_policy_mismatch(
    record: RegistryRecord,
    connector_policy: dict[str, object] | None,
    allowed_channels: set[str],
) -> BlockReason | None:
    if connector_policy is None:
        return None
    policy_version = connector_policy.get("policy_version", record.policy_version)
    if policy_version != record.policy_version:
        return BlockReason.POLICY_VERSION_MISMATCH
    if not allowed_channels:
        return BlockReason.INVALID_FIELD_VALUE
    return None
