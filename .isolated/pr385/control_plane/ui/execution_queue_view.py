from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


def execution_view_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ExecutionQueueItem:
    execution_id: str
    state: str
    evidence_link: str
    audit_hash: str


@dataclass(frozen=True)
class ExecutionQueueUIView:
    queued_executions: tuple[str, ...]
    blocked_executions: tuple[str, ...]
    completed_executions: tuple[str, ...]
    revoked_executions: tuple[str, ...]
    evidence_links: dict[str, str]
    display_state: str
    audit_hash: str


def build_execution_queue_view(items: list[object]) -> ExecutionQueueUIView:
    queued: list[str] = []
    blocked: list[str] = []
    completed: list[str] = []
    revoked: list[str] = []
    links: dict[str, str] = {}
    missing_evidence = False
    for item in items:
        execution_id = item.execution_id
        state = getattr(item, "state", getattr(item, "execution_status", "UNKNOWN"))
        audit_hash = getattr(item, "audit_hash", "")
        evidence_link = getattr(item, "evidence_link", f"governance/evidence/executions/{execution_id}.json")
        if not execution_id or not evidence_link or not audit_hash:
            missing_evidence = True
        links[execution_id] = evidence_link
        if state in {"QUEUED", "PENDING"}:
            queued.append(execution_id)
        elif state in {"BLOCK", "BLOCKED", "FAIL_CLOSED"}:
            blocked.append(execution_id)
        elif state in {"COMPLETED", "ALLOW"}:
            completed.append(execution_id)
        elif state in {"REVOKED", "SUSPENDED"}:
            revoked.append(execution_id)
        else:
            blocked.append(execution_id)
            missing_evidence = True
    display_state = "FAIL_CLOSED" if missing_evidence else "READY_FOR_REVIEW"
    return ExecutionQueueUIView(
        queued_executions=tuple(queued),
        blocked_executions=tuple(blocked),
        completed_executions=tuple(completed),
        revoked_executions=tuple(revoked),
        evidence_links=links,
        display_state=display_state,
        audit_hash=execution_view_hash(queued, blocked, completed, revoked, links, display_state),
    )
