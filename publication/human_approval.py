"""Local human approval validation for publication governance."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from publication.models import (
    ApprovalEvidence,
    ApprovalState,
    ApprovalValidationResult,
    BlockReason,
    RegistryRecord,
    hash_payload,
)


DEFAULT_APPROVAL_TTL_DAYS = 365


def resolve_human_approval(
    *,
    record: RegistryRecord,
    approvals: Iterable[ApprovalEvidence | dict[str, Any]] | None,
    policy: dict[str, Any] | None = None,
    required_roles: Iterable[str] | None = None,
    now: datetime | None = None,
    approval_ttl_days: int = DEFAULT_APPROVAL_TTL_DAYS,
) -> ApprovalValidationResult:
    if approvals is None:
        return ApprovalValidationResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.HUMAN_APPROVAL_MISSING,
            policy_version=record.policy_version,
        )

    approval_records = [_coerce_approval(item) for item in approvals]
    if not approval_records:
        return ApprovalValidationResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.HUMAN_APPROVAL_MISSING,
            policy_version=record.policy_version,
        )

    reviewer_roles = (policy or {}).get("reviewer_roles", {})
    required_role_set = set(required_roles or _default_required_roles(record.classification))
    valid_reviewer_refs: list[str] = []
    valid_role_set: set[str] = set()
    evidence_items: list[dict[str, Any]] = []

    for approval in approval_records:
        field_result = _validate_approval_fields(record, approval)
        if field_result is not None:
            return field_result

        state_result = _validate_approval_state(record, approval)
        if state_result is not None:
            return state_result

        expiry_result = _validate_expiry(record, approval, now=now, approval_ttl_days=approval_ttl_days)
        if expiry_result is not None:
            return expiry_result

        if approval.owner == approval.reviewer:
            return ApprovalValidationResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.OWNER_SELF_APPROVAL,
                reviewer_references=(approval.reviewer,),
                evidence=_redacted_evidence(record, (approval,), reviewer_roles),
                policy_version=record.policy_version,
            )

        if not _role_can_approve(approval.reviewer_role, record.classification, reviewer_roles):
            return ApprovalValidationResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.REVIEWER_AUTHORITY_MISSING,
                reviewer_references=(approval.reviewer,),
                evidence=_redacted_evidence(record, (approval,), reviewer_roles),
                policy_version=record.policy_version,
            )

        valid_reviewer_refs.append(approval.reviewer)
        valid_role_set.add(approval.reviewer_role)
        evidence_items.append(approval.redacted_dict())

    missing_roles = tuple(sorted(required_role_set - valid_role_set))
    if missing_roles:
        evidence = _redacted_evidence(record, approval_records, reviewer_roles)
        evidence["missing_required_roles"] = missing_roles
        return ApprovalValidationResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.REQUIRED_MULTI_REVIEW_MISSING,
            reviewer_references=tuple(valid_reviewer_refs),
            evidence=evidence,
            policy_version=record.policy_version,
        )

    evidence = {
        "artifact_id": record.artifact_id,
        "artifact_version": record.version,
        "classification": record.classification,
        "approval_count": len(evidence_items),
        "reviewer_references": tuple(sorted(valid_reviewer_refs)),
        "reviewer_roles": tuple(sorted(valid_role_set)),
        "approval_hashes": tuple(sorted(item["approval_hash"] for item in evidence_items)),
        "policy_version": record.policy_version,
        "raw_approval_content_stored": False,
    }
    evidence["approval_bundle_hash"] = hash_payload(evidence)
    return ApprovalValidationResult.approved(
        artifact_id=record.artifact_id,
        reviewer_references=tuple(sorted(valid_reviewer_refs)),
        evidence=evidence,
        policy_version=record.policy_version,
    )


def _coerce_approval(item: ApprovalEvidence | dict[str, Any]) -> ApprovalEvidence:
    if isinstance(item, ApprovalEvidence):
        return item
    return ApprovalEvidence.from_dict(item)


def _validate_approval_fields(
    record: RegistryRecord,
    approval: ApprovalEvidence,
) -> ApprovalValidationResult | None:
    missing = tuple(
        field_name
        for field_name in ApprovalEvidence.field_names()
        if getattr(approval, field_name) in ("", None)
    )
    if missing:
        evidence = {
            "artifact_id": record.artifact_id,
            "missing_fields": missing,
            "approval_hash_present": bool(approval.approval_hash),
            "raw_approval_content_stored": False,
        }
        return ApprovalValidationResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.MISSING_APPROVAL_EVIDENCE,
            evidence=evidence,
            policy_version=record.policy_version,
        )
    if approval.artifact_id != record.artifact_id or approval.artifact_version != record.version:
        return ApprovalValidationResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.MISSING_APPROVAL_EVIDENCE,
            evidence=_redacted_evidence(record, (approval,), {}),
            policy_version=record.policy_version,
        )
    if approval.policy_version != record.policy_version or approval.classification != record.classification:
        return ApprovalValidationResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.POLICY_VERSION_MISMATCH,
            evidence=_redacted_evidence(record, (approval,), {}),
            policy_version=record.policy_version,
        )
    if approval.rollback_reference != record.rollback_reference or not approval.audit_reference:
        return ApprovalValidationResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.MISSING_APPROVAL_EVIDENCE,
            evidence=_redacted_evidence(record, (approval,), {}),
            policy_version=record.policy_version,
        )
    return None


def _validate_approval_state(
    record: RegistryRecord,
    approval: ApprovalEvidence,
) -> ApprovalValidationResult | None:
    try:
        state = ApprovalState(approval.approval_state)
    except ValueError:
        return ApprovalValidationResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.HUMAN_APPROVAL_MISSING,
            state=ApprovalState.BLOCKED,
            evidence=_redacted_evidence(record, (approval,), {}),
            policy_version=record.policy_version,
        )
    if state == ApprovalState.EXPIRED:
        return ApprovalValidationResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.APPROVAL_EXPIRED,
            state=state,
            evidence=_redacted_evidence(record, (approval,), {}),
            policy_version=record.policy_version,
        )
    if state != ApprovalState.APPROVED:
        return ApprovalValidationResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.HUMAN_APPROVAL_MISSING,
            state=state,
            evidence=_redacted_evidence(record, (approval,), {}),
            policy_version=record.policy_version,
        )
    return None


def _validate_expiry(
    record: RegistryRecord,
    approval: ApprovalEvidence,
    *,
    now: datetime | None,
    approval_ttl_days: int,
) -> ApprovalValidationResult | None:
    current_time = now or datetime.now(timezone.utc)
    try:
        approved_at = datetime.fromisoformat(approval.approval_timestamp.replace("Z", "+00:00"))
    except ValueError:
        return ApprovalValidationResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.MISSING_APPROVAL_EVIDENCE,
            evidence=_redacted_evidence(record, (approval,), {}),
            policy_version=record.policy_version,
        )
    age_seconds = (current_time - approved_at).total_seconds()
    if age_seconds < 0 or age_seconds > approval_ttl_days * 24 * 60 * 60:
        return ApprovalValidationResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.APPROVAL_EXPIRED,
            state=ApprovalState.EXPIRED,
            evidence=_redacted_evidence(record, (approval,), {}),
            policy_version=record.policy_version,
        )
    return None


def _role_can_approve(
    reviewer_role: str,
    classification: str,
    reviewer_roles: dict[str, list[str]],
) -> bool:
    allowed = set(reviewer_roles.get(reviewer_role, ()))
    if classification in allowed:
        return True
    draft_class = classification.replace("_APPROVED", "_DRAFT")
    return draft_class in allowed


def _default_required_roles(classification: str) -> tuple[str, ...]:
    if classification.startswith("PRICING_"):
        return ("Pricing Reviewer",)
    if classification.startswith("CUSTOMER_"):
        return ("Customer Reviewer",)
    if classification.startswith("LINKEDIN_") or classification.startswith("PUBLIC_"):
        return ("Publication Reviewer",)
    return ("Governance Reviewer",)


def _redacted_evidence(
    record: RegistryRecord,
    approvals: Iterable[ApprovalEvidence],
    reviewer_roles: dict[str, list[str]],
) -> dict[str, Any]:
    approval_items = tuple(approval.redacted_dict() for approval in approvals)
    return {
        "artifact_id": record.artifact_id,
        "artifact_version": record.version,
        "classification": record.classification,
        "approval_count": len(approval_items),
        "approval_hashes": tuple(sorted(item.get("approval_hash", "") for item in approval_items if item.get("approval_hash"))),
        "reviewer_references": tuple(sorted(item.get("reviewer", "") for item in approval_items if item.get("reviewer"))),
        "reviewer_roles": tuple(sorted(item.get("reviewer_role", "") for item in approval_items if item.get("reviewer_role"))),
        "known_reviewer_roles_hash": hash_payload(sorted(reviewer_roles.keys())),
        "raw_approval_content_stored": False,
    }
