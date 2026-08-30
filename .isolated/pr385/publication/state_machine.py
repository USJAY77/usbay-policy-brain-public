"""Publication lifecycle state transitions."""

from __future__ import annotations

from publication.models import BlockReason, LifecycleState, PublicationDecisionResult, RegistryRecord


ALLOWED_TRANSITIONS: dict[LifecycleState, set[LifecycleState]] = {
    LifecycleState.DRAFT: {LifecycleState.REGISTERED, LifecycleState.BLOCKED},
    LifecycleState.REGISTERED: {LifecycleState.CLASSIFIED, LifecycleState.BLOCKED},
    LifecycleState.CLASSIFIED: {LifecycleState.UNDER_REVIEW, LifecycleState.BLOCKED},
    LifecycleState.UNDER_REVIEW: {LifecycleState.APPROVED, LifecycleState.BLOCKED},
    LifecycleState.APPROVED: {LifecycleState.PUBLISH_ELIGIBLE, LifecycleState.BLOCKED, LifecycleState.REVOKED},
    LifecycleState.PUBLISH_ELIGIBLE: {LifecycleState.PUBLISHED, LifecycleState.BLOCKED, LifecycleState.REVOKED},
    LifecycleState.PUBLISHED: {LifecycleState.SUPERSEDED, LifecycleState.REVOKED, LifecycleState.ARCHIVED},
    LifecycleState.SUPERSEDED: {LifecycleState.ARCHIVED},
    LifecycleState.REVOKED: {LifecycleState.ARCHIVED},
    LifecycleState.BLOCKED: {LifecycleState.DRAFT, LifecycleState.ARCHIVED},
    LifecycleState.ARCHIVED: set(),
}


def can_transition(current: LifecycleState | str, target: LifecycleState | str) -> bool:
    try:
        current_state = LifecycleState(current)
        target_state = LifecycleState(target)
    except ValueError:
        return False
    return target_state in ALLOWED_TRANSITIONS[current_state]


def transition_lifecycle(
    record: RegistryRecord,
    target: LifecycleState | str,
) -> RegistryRecord | PublicationDecisionResult:
    if not can_transition(record.lifecycle_state, target):
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.INVALID_LIFECYCLE_TRANSITION,
            policy_version=record.policy_version,
            details=(f"{record.lifecycle_state} -> {target} is not allowed",),
            evidence_hashes={"registry_hash": record.stable_hash()},
        )
    data = record.to_dict()
    data["lifecycle_state"] = LifecycleState(target).value
    return RegistryRecord.from_dict(data)
