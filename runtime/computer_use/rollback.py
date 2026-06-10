from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RollbackPlan:
    action_id: str
    rollback_path: str
    evidence_required: list[str]
    ready: bool
    reason: str


def build_rollback_plan(action_id: str, rollback_path: str | None, evidence_required: list[str] | None) -> RollbackPlan:
    evidence_required = evidence_required or []
    if not rollback_path:
        return RollbackPlan(action_id, "missing", evidence_required, False, "rollback_path_missing")
    if not evidence_required:
        return RollbackPlan(action_id, rollback_path, evidence_required, False, "rollback_evidence_missing")
    return RollbackPlan(action_id, rollback_path, evidence_required, True, "rollback_ready")

