"""Publication artifact classification validation."""

from __future__ import annotations

from typing import Any

from publication.models import (
    BlockReason,
    ClassificationState,
    PublicationDecision,
    PublicationDecisionResult,
    RegistryRecord,
)


DEFAULT_PUBLISH_ELIGIBLE = {
    ClassificationState.CUSTOMER_APPROVED.value,
    ClassificationState.PUBLIC_APPROVED.value,
    ClassificationState.PRICING_APPROVED.value,
    ClassificationState.LINKEDIN_APPROVED.value,
}


def classify_registry_record(
    record: RegistryRecord,
    *,
    policy: dict[str, Any] | None = None,
) -> PublicationDecisionResult:
    allowed_classes = set(policy.get("allowed_classes", [state.value for state in ClassificationState])) if policy else {
        state.value for state in ClassificationState
    }
    publish_eligible = set(policy.get("publish_eligible_classes", DEFAULT_PUBLISH_ELIGIBLE)) if policy else DEFAULT_PUBLISH_ELIGIBLE

    if not record.classification:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.CLASSIFICATION_MISSING,
            decision=PublicationDecision.NEEDS_RECLASSIFICATION,
            policy_version=record.policy_version,
            evidence_hashes={"registry_hash": record.stable_hash()},
        )
    if record.classification not in allowed_classes:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.CLASSIFICATION_INVALID,
            decision=PublicationDecision.NEEDS_RECLASSIFICATION,
            policy_version=record.policy_version,
            evidence_hashes={"registry_hash": record.stable_hash()},
        )
    if record.classification == ClassificationState.BLOCKED_SENSITIVE.value:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.CLASSIFICATION_NOT_PUBLISH_ELIGIBLE,
            decision=PublicationDecision.SENSITIVE_DATA_BLOCKED,
            policy_version=record.policy_version,
            evidence_hashes={"classification_hash": record.classification_hash},
        )
    if record.classification not in publish_eligible:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.CLASSIFICATION_NOT_PUBLISH_ELIGIBLE,
            decision=PublicationDecision.NEEDS_RECLASSIFICATION,
            policy_version=record.policy_version,
            evidence_hashes={"classification_hash": record.classification_hash},
        )

    return PublicationDecisionResult.allowed(
        artifact_id=record.artifact_id,
        policy_version=record.policy_version,
        evidence_hashes={"classification_hash": record.classification_hash},
        details=(f"classification {record.classification} publish eligible",),
    )
