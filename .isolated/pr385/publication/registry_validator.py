"""Fail-closed publication registry validation."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from publication.models import (
    BlockReason,
    ClassificationState,
    LifecycleState,
    PublicationDecision,
    PublicationDecisionResult,
    RegistryRecord,
    TargetChannel,
    is_semver,
    is_sha256_ref,
)


def validate_registry_record(
    record: RegistryRecord | None,
    *,
    schema: dict[str, Any] | None = None,
    active_policy_version: str = "1.0",
) -> PublicationDecisionResult:
    if record is None:
        return PublicationDecisionResult.blocked(
            artifact_id="UNKNOWN_ARTIFACT",
            reason=BlockReason.REGISTRY_RECORD_MISSING,
        )

    schema_result = _validate_schema(record, schema)
    if schema_result is not None:
        return schema_result

    if record.policy_version != active_policy_version:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.POLICY_VERSION_MISMATCH,
            policy_version=record.policy_version,
            evidence_hashes={"registry_hash": record.stable_hash()},
        )

    if not record.rollback_reference:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.ROLLBACK_REFERENCE_MISSING,
            policy_version=record.policy_version,
            evidence_hashes={"registry_hash": record.stable_hash()},
        )

    if not record.audit_reference:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.AUDIT_REFERENCE_MISSING,
            policy_version=record.policy_version,
            evidence_hashes={"registry_hash": record.stable_hash()},
        )

    return PublicationDecisionResult.allowed(
        artifact_id=record.artifact_id,
        policy_version=record.policy_version,
        evidence_hashes={"registry_hash": record.stable_hash()},
        details=("registry record valid",),
    )


def _validate_schema(
    record: RegistryRecord,
    schema: dict[str, Any] | None,
) -> PublicationDecisionResult | None:
    data = record.to_dict()
    required = tuple(schema.get("required", RegistryRecord.field_names())) if schema else RegistryRecord.field_names()
    for field_name in required:
        if field_name not in data or data[field_name] in ("", None):
            if field_name == "parent_artifact_id":
                continue
            return PublicationDecisionResult.blocked(
                artifact_id=record.artifact_id or "UNKNOWN_ARTIFACT",
                reason=BlockReason.MISSING_REQUIRED_FIELD,
                policy_version=record.policy_version or "UNKNOWN",
                details=(f"missing required field: {field_name}",),
            )

    if record.lifecycle_state not in {state.value for state in LifecycleState}:
        return _invalid(record, f"invalid lifecycle_state: {record.lifecycle_state}")
    if record.classification not in {state.value for state in ClassificationState}:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.CLASSIFICATION_INVALID,
            policy_version=record.policy_version,
            details=(f"invalid classification: {record.classification}",),
            evidence_hashes={"registry_hash": record.stable_hash()},
        )
    if record.target_channel not in {channel.value for channel in TargetChannel}:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.CONNECTOR_TARGET_UNKNOWN,
            decision=PublicationDecision.CONNECTOR_BLOCKED,
            policy_version=record.policy_version,
            details=(f"invalid target_channel: {record.target_channel}",),
            evidence_hashes={"registry_hash": record.stable_hash()},
        )
    if not is_semver(record.version):
        return _invalid(record, f"invalid version: {record.version}")
    for field_name in ("content_hash", "classification_hash", "approval_hash"):
        if not is_sha256_ref(getattr(record, field_name)):
            return PublicationDecisionResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.HASH_MISMATCH,
                policy_version=record.policy_version,
                details=(f"invalid hash reference: {field_name}",),
                evidence_hashes={"registry_hash": record.stable_hash()},
            )
    for field_name in ("created_at", "updated_at"):
        try:
            datetime.fromisoformat(getattr(record, field_name).replace("Z", "+00:00"))
        except (AttributeError, ValueError):
            return _invalid(record, f"invalid timestamp: {field_name}")
    return None


def _invalid(record: RegistryRecord, detail: str) -> PublicationDecisionResult:
    return PublicationDecisionResult.blocked(
        artifact_id=record.artifact_id,
        reason=BlockReason.INVALID_FIELD_VALUE,
        policy_version=record.policy_version or "UNKNOWN",
        details=(detail,),
        evidence_hashes={"registry_hash": record.stable_hash()},
    )
