"""Deterministic execution scheduler metadata.

The scheduler creates ordering, queue, timeout, priority, and retry metadata.
It does not create threads, async tasks, subprocesses, workers, or runtime
execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
from typing import Any, Mapping, Sequence


SCHEDULER_READY = "SCHEDULER_READY"
SCHEDULER_BLOCKED = "SCHEDULER_BLOCKED"

MISSING_GOVERNANCE_METADATA = "MISSING_GOVERNANCE_METADATA"
UNKNOWN_TASK = "UNKNOWN_TASK"
DUPLICATE_TASK = "DUPLICATE_TASK"
UNKNOWN_DEPENDENCY = "UNKNOWN_DEPENDENCY"
CYCLIC_DEPENDENCY = "CYCLIC_DEPENDENCY"
EXECUTION_REQUESTED = "EXECUTION_REQUESTED"
INVALID_RETRY_METADATA = "INVALID_RETRY_METADATA"
INVALID_TIMEOUT_METADATA = "INVALID_TIMEOUT_METADATA"
RAW_PAYLOAD_FORBIDDEN = "RAW_PAYLOAD_FORBIDDEN"

_SENSITIVE_KEYS = frozenset({
    "api_key",
    "body",
    "content",
    "credential",
    "credentials",
    "password",
    "payload",
    "private_key",
    "raw_payload",
    "secret",
    "token",
})


@dataclass(frozen=True)
class ScheduledTask:
    task_id: str
    capability: str
    dependencies: Sequence[str] = ()
    priority: int = 100
    retry_limit: int = 0
    timeout_seconds: int = 0
    queue: str = "default"
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExecutionScheduleRequest:
    tenant_id: str
    policy_hash: str
    evidence_hash: str
    correlation_id: str
    tasks: Sequence[ScheduledTask]
    requested_execution: bool = False


@dataclass(frozen=True)
class ExecutionScheduleDecision:
    schedule_hash: str
    scheduler_state: str
    ordered_task_hashes: tuple[str, ...]
    queue_metadata_hash: str
    retry_metadata_hash: str
    timeout_metadata_hash: str
    priority_metadata_hash: str
    denial_reasons: tuple[str, ...]
    execution_allowed: bool = False
    hash_only: bool = True
    redacted: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "schedule_hash": self.schedule_hash,
            "scheduler_state": self.scheduler_state,
            "ordered_task_hashes": self.ordered_task_hashes,
            "queue_metadata_hash": self.queue_metadata_hash,
            "retry_metadata_hash": self.retry_metadata_hash,
            "timeout_metadata_hash": self.timeout_metadata_hash,
            "priority_metadata_hash": self.priority_metadata_hash,
            "denial_reasons": self.denial_reasons,
            "execution_allowed": self.execution_allowed,
            "hash_only": self.hash_only,
            "redacted": self.redacted,
        }


def build_execution_schedule(request: ExecutionScheduleRequest) -> ExecutionScheduleDecision:
    """Build deterministic execution scheduling metadata."""

    reasons = list(_request_denials(request))
    ordering, ordering_reasons = _ordered_tasks(request.tasks)
    reasons.extend(ordering_reasons)
    denial_reasons = tuple(sorted(set(reasons)))
    scheduler_state = SCHEDULER_BLOCKED if denial_reasons else SCHEDULER_READY
    queue_metadata = tuple((task.task_id, task.queue) for task in sorted(request.tasks, key=lambda item: item.task_id))
    retry_metadata = tuple((task.task_id, task.retry_limit) for task in sorted(request.tasks, key=lambda item: item.task_id))
    timeout_metadata = tuple((task.task_id, task.timeout_seconds) for task in sorted(request.tasks, key=lambda item: item.task_id))
    priority_metadata = tuple((task.task_id, task.priority) for task in sorted(request.tasks, key=lambda item: item.task_id))
    ordered_task_hashes = tuple(_hash_task(task) for task in ordering)
    payload = {
        "tenant_hash": _hash_text(request.tenant_id),
        "policy_hash": request.policy_hash,
        "evidence_hash": request.evidence_hash,
        "correlation_hash": _hash_text(request.correlation_id),
        "ordered_task_hashes": ordered_task_hashes,
        "queue_metadata_hash": _canonical_hash({"queues": queue_metadata}),
        "retry_metadata_hash": _canonical_hash({"retries": retry_metadata}),
        "timeout_metadata_hash": _canonical_hash({"timeouts": timeout_metadata}),
        "priority_metadata_hash": _canonical_hash({"priorities": priority_metadata}),
        "denial_reasons": denial_reasons,
        "execution_allowed": False,
    }
    return ExecutionScheduleDecision(
        schedule_hash=_canonical_hash(payload),
        scheduler_state=scheduler_state,
        ordered_task_hashes=ordered_task_hashes,
        queue_metadata_hash=payload["queue_metadata_hash"],
        retry_metadata_hash=payload["retry_metadata_hash"],
        timeout_metadata_hash=payload["timeout_metadata_hash"],
        priority_metadata_hash=payload["priority_metadata_hash"],
        denial_reasons=denial_reasons,
    )


def _request_denials(request: ExecutionScheduleRequest) -> tuple[str, ...]:
    reasons: list[str] = []
    if not all((request.tenant_id, request.policy_hash, request.evidence_hash, request.correlation_id)):
        reasons.append(MISSING_GOVERNANCE_METADATA)
    if not request.tasks:
        reasons.append(UNKNOWN_TASK)
    if request.requested_execution:
        reasons.append(EXECUTION_REQUESTED)
    seen: set[str] = set()
    for task in request.tasks:
        if not task.task_id or not task.capability:
            reasons.append(UNKNOWN_TASK)
        if task.task_id in seen:
            reasons.append(DUPLICATE_TASK)
        seen.add(task.task_id)
        if task.retry_limit < 0:
            reasons.append(INVALID_RETRY_METADATA)
        if task.timeout_seconds < 0:
            reasons.append(INVALID_TIMEOUT_METADATA)
        if _contains_raw_payload(task.metadata):
            reasons.append(RAW_PAYLOAD_FORBIDDEN)
    return tuple(reasons)


def _ordered_tasks(tasks: Sequence[ScheduledTask]) -> tuple[tuple[ScheduledTask, ...], tuple[str, ...]]:
    task_by_id = {task.task_id: task for task in tasks}
    reasons: list[str] = []
    for task in tasks:
        if any(dependency not in task_by_id for dependency in task.dependencies):
            reasons.append(UNKNOWN_DEPENDENCY)

    ordered: list[ScheduledTask] = []
    temporary: set[str] = set()
    permanent: set[str] = set()

    def visit(task: ScheduledTask) -> None:
        if task.task_id in permanent:
            return
        if task.task_id in temporary:
            reasons.append(CYCLIC_DEPENDENCY)
            return
        temporary.add(task.task_id)
        for dependency_id in sorted(task.dependencies):
            dependency = task_by_id.get(dependency_id)
            if dependency is not None:
                visit(dependency)
        temporary.remove(task.task_id)
        permanent.add(task.task_id)
        ordered.append(task)

    for task in sorted(tasks, key=lambda item: (item.priority, item.task_id)):
        visit(task)
    return tuple(ordered), tuple(reasons)


def _hash_task(task: ScheduledTask) -> str:
    return _canonical_hash({
        "task_id_hash": _hash_text(task.task_id),
        "capability_hash": _hash_text(task.capability),
        "dependencies": tuple(_hash_text(item) for item in sorted(task.dependencies)),
        "priority": task.priority,
        "retry_limit": task.retry_limit,
        "timeout_seconds": task.timeout_seconds,
        "queue_hash": _hash_text(task.queue),
    })


def _contains_raw_payload(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(str(key).lower() in _SENSITIVE_KEYS or _contains_raw_payload(child) for key, child in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_raw_payload(item) for item in value)
    return False


def _hash_text(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + sha256(encoded.encode("utf-8")).hexdigest()
