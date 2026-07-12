import json
import re
from pathlib import Path

from governance.runtime.execution_scheduler import (
    CYCLIC_DEPENDENCY,
    DUPLICATE_TASK,
    EXECUTION_REQUESTED,
    INVALID_RETRY_METADATA,
    INVALID_TIMEOUT_METADATA,
    MISSING_GOVERNANCE_METADATA,
    RAW_PAYLOAD_FORBIDDEN,
    SCHEDULER_BLOCKED,
    SCHEDULER_READY,
    UNKNOWN_DEPENDENCY,
    UNKNOWN_TASK,
    ExecutionScheduleRequest,
    ScheduledTask,
    build_execution_schedule,
)


EVIDENCE = Path(__file__).resolve().parents[1] / "governance" / "evidence" / "execution_scheduler.json"
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _request(tasks=None, **overrides):
    payload = {
        "tenant_id": "tenant-runtime",
        "policy_hash": "sha256:policy",
        "evidence_hash": "sha256:evidence",
        "correlation_id": "correlation-1",
        "tasks": tasks if tasks is not None else (
            ScheduledTask(task_id="intake", capability="metadata"),
            ScheduledTask(task_id="proposal", capability="metadata", dependencies=("intake",), priority=20),
        ),
    }
    payload.update(overrides)
    return ExecutionScheduleRequest(**payload)


def test_scheduler_orders_dependencies_deterministically():
    result = build_execution_schedule(_request())

    assert result.scheduler_state == SCHEDULER_READY
    assert len(result.ordered_task_hashes) == 2
    assert result.execution_allowed is False
    assert result.schedule_hash.startswith("sha256:")


def test_missing_governance_metadata_blocks():
    result = build_execution_schedule(_request(tenant_id="", policy_hash="", evidence_hash="", correlation_id=""))

    assert result.scheduler_state == SCHEDULER_BLOCKED
    assert MISSING_GOVERNANCE_METADATA in result.denial_reasons


def test_empty_or_duplicate_tasks_block():
    empty = build_execution_schedule(_request(tasks=()))
    duplicate = build_execution_schedule(_request(tasks=(
        ScheduledTask(task_id="a", capability="metadata"),
        ScheduledTask(task_id="a", capability="metadata"),
    )))

    assert UNKNOWN_TASK in empty.denial_reasons
    assert DUPLICATE_TASK in duplicate.denial_reasons


def test_unknown_dependency_and_cycle_block():
    unknown = build_execution_schedule(_request(tasks=(
        ScheduledTask(task_id="a", capability="metadata", dependencies=("missing",)),
    )))
    cycle = build_execution_schedule(_request(tasks=(
        ScheduledTask(task_id="a", capability="metadata", dependencies=("b",)),
        ScheduledTask(task_id="b", capability="metadata", dependencies=("a",)),
    )))

    assert UNKNOWN_DEPENDENCY in unknown.denial_reasons
    assert CYCLIC_DEPENDENCY in cycle.denial_reasons


def test_invalid_retry_timeout_execution_and_raw_payload_block():
    result = build_execution_schedule(_request(
        tasks=(ScheduledTask(task_id="a", capability="metadata", retry_limit=-1, timeout_seconds=-1, metadata={"payload": "x"}),),
        requested_execution=True,
    ))

    assert result.scheduler_state == SCHEDULER_BLOCKED
    assert INVALID_RETRY_METADATA in result.denial_reasons
    assert INVALID_TIMEOUT_METADATA in result.denial_reasons
    assert RAW_PAYLOAD_FORBIDDEN in result.denial_reasons
    assert EXECUTION_REQUESTED in result.denial_reasons


def test_scheduler_is_deterministic_and_redacted():
    first = build_execution_schedule(_request())
    second = build_execution_schedule(_request())
    rendered = json.dumps(first.as_dict(), sort_keys=True)

    assert first.as_dict() == second.as_dict()
    assert "tenant-runtime" not in rendered
    assert "correlation-1" not in rendered


def test_scheduler_evidence_is_hash_only():
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    assert HASH_RE.match(evidence["tenant_hash"])
    assert HASH_RE.match(evidence["policy_hash"])
    assert HASH_RE.match(evidence["evidence_hash"])
    assert HASH_RE.match(evidence["scheduler_hash"])
    assert evidence["threads"] is False
    assert evidence["async_execution"] is False
    assert evidence["subprocess"] is False
    assert evidence["execution_allowed"] is False
    assert evidence["hash_only"] is True
    assert evidence["redacted"] is True
