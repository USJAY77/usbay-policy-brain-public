"""Deterministic fail-closed publication decision engine."""

from __future__ import annotations

from typing import Any

from publication.classification import classify_registry_record
from publication.models import (
    ApprovalValidationResult,
    ApprovalState,
    AuditPersistenceResult,
    BlockReason,
    ConnectorGateResult,
    LifecycleState,
    PublicationDecision,
    PublicationDecisionResult,
    RegistryRecord,
    SensitiveScanResult,
)
from publication.registry_validator import validate_registry_record


def evaluate_publication_decision(
    record: RegistryRecord | None,
    *,
    registry_schema: dict[str, Any] | None = None,
    classification_policy: dict[str, Any] | None = None,
    active_policy_version: str = "1.0",
    approval_state: ApprovalState | str = ApprovalState.APPROVED,
    approval_result: ApprovalValidationResult | None = None,
    sensitive_scan_result: SensitiveScanResult | None = None,
    audit_result: AuditPersistenceResult | None = None,
    connector_gate_result: ConnectorGateResult | None = None,
) -> PublicationDecisionResult:
    registry_result = validate_registry_record(
        record,
        schema=registry_schema,
        active_policy_version=active_policy_version,
    )
    if not registry_result.publish_allowed:
        return registry_result
    assert record is not None

    classification_result = classify_registry_record(record, policy=classification_policy)
    if not classification_result.publish_allowed:
        return classification_result

    scan_result = _validate_sensitive_scan(record, sensitive_scan_result)
    if not scan_result.publish_allowed:
        return scan_result

    approval_decision = _validate_approval(record, approval_result, approval_state)
    if not approval_decision.publish_allowed:
        return approval_decision

    if record.lifecycle_state not in {LifecycleState.APPROVED.value, LifecycleState.PUBLISH_ELIGIBLE.value}:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.INVALID_FIELD_VALUE,
            policy_version=record.policy_version,
            details=(f"lifecycle state is not publication eligible: {record.lifecycle_state}",),
            evidence_hashes={"registry_hash": record.stable_hash()},
        )

    audit_decision = _validate_audit_persistence(record, audit_result)
    if not audit_decision.publish_allowed:
        return audit_decision

    connector_decision = _validate_connector_gate(record, connector_gate_result)
    if not connector_decision.publish_allowed:
        return connector_decision

    return PublicationDecisionResult.allowed(
        artifact_id=record.artifact_id,
        policy_version=record.policy_version,
        evidence_hashes={
            "registry_hash": record.stable_hash(),
            "content_hash": record.content_hash,
            "classification_hash": record.classification_hash,
            "sensitive_scan_hash": sensitive_scan_result.audit.evidence_hashes["sensitive_scan_hash"],
            "approval_validation_hash": approval_result.audit.evidence_hashes["approval_validation_hash"],
            "evidence_chain_hash": audit_result.audit.evidence_hashes["evidence_chain_hash"],
            "connector_gate_hash": connector_gate_result.audit.evidence_hashes["connector_gate_hash"],
        },
        details=("all local publication gates passed",),
    )


def _validate_sensitive_scan(
    record: RegistryRecord,
    scan_result: SensitiveScanResult | None,
) -> PublicationDecisionResult:
    if scan_result is None:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.SENSITIVE_SCAN_MISSING,
            decision=PublicationDecision.SENSITIVE_DATA_BLOCKED,
            policy_version=record.policy_version,
            evidence_hashes={"registry_hash": record.stable_hash()},
        )
    if scan_result.artifact_id != record.artifact_id:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.INVALID_SCAN_INPUT,
            decision=PublicationDecision.SENSITIVE_DATA_BLOCKED,
            policy_version=record.policy_version,
            details=("sensitive scan artifact_id does not match registry record",),
            evidence_hashes=scan_result.audit.evidence_hashes,
        )
    if not scan_result.passed:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=scan_result.block_reason,
            decision=PublicationDecision.SENSITIVE_DATA_BLOCKED,
            policy_version=record.policy_version,
            evidence_hashes=scan_result.audit.evidence_hashes,
            details=tuple(category.value for category in scan_result.detected_categories),
        )
    return PublicationDecisionResult.allowed(
        artifact_id=record.artifact_id,
        policy_version=record.policy_version,
        evidence_hashes=scan_result.audit.evidence_hashes,
    )


def _validate_approval(
    record: RegistryRecord,
    approval_result: ApprovalValidationResult | None,
    approval_state: ApprovalState | str,
) -> PublicationDecisionResult:
    if approval_result is None:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.HUMAN_APPROVAL_MISSING,
            decision=PublicationDecision.NEEDS_HUMAN_REVIEW,
            policy_version=record.policy_version,
            details=("approval validation evidence is required",),
            evidence_hashes={"registry_hash": record.stable_hash()},
        )
    if approval_result.artifact_id != record.artifact_id:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.MISSING_APPROVAL_EVIDENCE,
            decision=PublicationDecision.NEEDS_HUMAN_REVIEW,
            policy_version=record.policy_version,
            details=("approval artifact_id does not match registry record",),
            evidence_hashes=approval_result.audit.evidence_hashes,
        )
    if not approval_result.passed:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=approval_result.block_reason,
            decision=PublicationDecision.NEEDS_HUMAN_REVIEW,
            policy_version=record.policy_version,
            evidence_hashes=approval_result.audit.evidence_hashes,
            details=approval_result.reviewer_references,
        )

    # Compatibility guard: callers cannot override explicit approval evidence
    # with stale or non-approved state.
    try:
        state = ApprovalState(approval_state)
    except ValueError:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.HUMAN_APPROVAL_MISSING,
            decision=PublicationDecision.NEEDS_HUMAN_REVIEW,
            policy_version=record.policy_version,
            evidence_hashes={"registry_hash": record.stable_hash()},
        )

    if state == ApprovalState.EXPIRED:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.APPROVAL_EXPIRED,
            decision=PublicationDecision.NEEDS_HUMAN_REVIEW,
            policy_version=record.policy_version,
            evidence_hashes={"approval_hash": record.approval_hash},
        )
    if state != ApprovalState.APPROVED:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.HUMAN_APPROVAL_MISSING,
            decision=PublicationDecision.NEEDS_HUMAN_REVIEW,
            policy_version=record.policy_version,
            evidence_hashes={"approval_hash": record.approval_hash},
        )
    if not record.approval_hash:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.HUMAN_APPROVAL_MISSING,
            decision=PublicationDecision.NEEDS_HUMAN_REVIEW,
            policy_version=record.policy_version,
        )
    if record.owner == record.reviewer:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.OWNER_SELF_APPROVAL,
            decision=PublicationDecision.NEEDS_HUMAN_REVIEW,
            policy_version=record.policy_version,
            evidence_hashes={"approval_hash": record.approval_hash},
        )
    return PublicationDecisionResult.allowed(
        artifact_id=record.artifact_id,
        policy_version=record.policy_version,
        evidence_hashes={"approval_hash": record.approval_hash},
    )


def _validate_audit_persistence(
    record: RegistryRecord,
    audit_result: AuditPersistenceResult | None,
) -> PublicationDecisionResult:
    if audit_result is None:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.AUDIT_EVENT_MISSING,
            decision=PublicationDecision.AUDIT_EVIDENCE_MISSING,
            policy_version=record.policy_version,
            evidence_hashes={"registry_hash": record.stable_hash()},
        )
    if audit_result.artifact_id != record.artifact_id:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.AUDIT_EVENT_MISSING,
            decision=PublicationDecision.AUDIT_EVIDENCE_MISSING,
            policy_version=record.policy_version,
            evidence_hashes=audit_result.audit.evidence_hashes,
        )
    if not audit_result.persisted or audit_result.event is None:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=audit_result.block_reason,
            decision=PublicationDecision.AUDIT_EVIDENCE_MISSING,
            policy_version=record.policy_version,
            evidence_hashes=audit_result.audit.evidence_hashes,
        )
    if audit_result.event.classification_hash != record.classification_hash:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.HASH_MISMATCH,
            policy_version=record.policy_version,
            evidence_hashes=audit_result.audit.evidence_hashes,
        )
    return PublicationDecisionResult.allowed(
        artifact_id=record.artifact_id,
        policy_version=record.policy_version,
        evidence_hashes=audit_result.audit.evidence_hashes,
    )


def _validate_connector_gate(
    record: RegistryRecord,
    connector_gate_result: ConnectorGateResult | None,
) -> PublicationDecisionResult:
    if connector_gate_result is None:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.CONNECTOR_GATE_MISSING,
            decision=PublicationDecision.CONNECTOR_BLOCKED,
            policy_version=record.policy_version,
            evidence_hashes={"registry_hash": record.stable_hash()},
        )
    if connector_gate_result.artifact_id != record.artifact_id:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.CONNECTOR_GATE_BLOCKED,
            decision=PublicationDecision.CONNECTOR_BLOCKED,
            policy_version=record.policy_version,
            evidence_hashes=connector_gate_result.audit.evidence_hashes,
        )
    if not connector_gate_result.publish_allowed:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=connector_gate_result.block_reason,
            decision=PublicationDecision.CONNECTOR_BLOCKED,
            policy_version=record.policy_version,
            evidence_hashes=connector_gate_result.audit.evidence_hashes,
        )
    return PublicationDecisionResult.allowed(
        artifact_id=record.artifact_id,
        policy_version=record.policy_version,
        evidence_hashes=connector_gate_result.audit.evidence_hashes,
    )
