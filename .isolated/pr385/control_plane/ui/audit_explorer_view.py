from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


def audit_view_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditExplorerRecord:
    decision_id: str
    approval_id: str
    execution_id: str
    audit_hash: str
    policy_version: str


@dataclass(frozen=True)
class AuditExplorerUIView:
    lookup_type: str
    lookup_value: str
    found: bool
    decision_id: str | None
    approval_id: str | None
    execution_id: str | None
    audit_hash_display: str | None
    policy_version_display: str | None
    display_state: str
    view_hash: str


def lookup_audit_record(records: list[AuditExplorerRecord], *, decision_id: str | None = None, approval_id: str | None = None, execution_id: str | None = None) -> AuditExplorerUIView:
    supplied = [("decision_id", decision_id), ("approval_id", approval_id), ("execution_id", execution_id)]
    active = [(key, value) for key, value in supplied if value]
    if len(active) != 1:
        return _empty("invalid_lookup", "", "FAIL_CLOSED")
    lookup_type, lookup_value = active[0]
    for record in records:
        if getattr(record, lookup_type) == lookup_value:
            if not record.audit_hash or not record.policy_version:
                return _empty(lookup_type, lookup_value, "FAIL_CLOSED")
            return AuditExplorerUIView(
                lookup_type=lookup_type,
                lookup_value=lookup_value,
                found=True,
                decision_id=record.decision_id,
                approval_id=record.approval_id,
                execution_id=record.execution_id,
                audit_hash_display=record.audit_hash,
                policy_version_display=record.policy_version,
                display_state="READY_FOR_REVIEW",
                view_hash=audit_view_hash(lookup_type, lookup_value, record.audit_hash, record.policy_version),
            )
    return _empty(lookup_type, lookup_value, "FAIL_CLOSED")


def _empty(lookup_type: str, lookup_value: str, display_state: str) -> AuditExplorerUIView:
    return AuditExplorerUIView(
        lookup_type=lookup_type,
        lookup_value=lookup_value,
        found=False,
        decision_id=None,
        approval_id=None,
        execution_id=None,
        audit_hash_display=None,
        policy_version_display=None,
        display_state=display_state,
        view_hash=audit_view_hash(lookup_type, lookup_value, display_state),
    )

