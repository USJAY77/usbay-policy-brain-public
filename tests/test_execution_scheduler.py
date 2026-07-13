import json
import re
from pathlib import Path

from governance.runtime.execution_scheduler import (
    BLOCKED,
    CYCLIC_DEPENDENCY,
    DUPLICATE_TASK,
    EXECUTION_REQUESTED,
    INVALID_PRIORITY_METADATA,
    INVALID_QUEUE_METADATA,
    INVALID_RETRY_METADATA,
    INVALID_SCHEDULER_STATE,
    INVALID_TIMEOUT_METADATA,
    MISSING_GOVERNANCE_METADATA,
    RAW_PAYLOAD_FORBIDDEN,
    SCHEDULER_BLOCKED,
    SCHEDULER_READY,
    UNKNOWN_CAPABILITY,
    UNKNOWN_DEPENDENCY,
    UNKNOWN_METADATA_FIELD,
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
    assert result.thread_execution is False
    assert result.async_execution is False
    assert result.subprocess_execution is False
    assert result.network_execution is False
    assert result.socket_execution is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.schedule_hash.startswith("sha256:")
    assert HASH_RE.match(result.audit_evidence_hash)


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


def test_invalid_priority_queue_capability_state_and_unknown_metadata_block():
    result = build_execution_schedule(_request(
        scheduler_state="EXECUTE",
        tasks=(
            ScheduledTask(
                task_id="a",
                capability="provider_runtime",
                priority=-1,
                queue="provider",
                metadata={"owner": "raw-label"},
            ),
        ),
    ))

    assert result.scheduler_state == SCHEDULER_BLOCKED
    assert INVALID_SCHEDULER_STATE in result.denial_reasons
    assert UNKNOWN_CAPABILITY in result.denial_reasons
    assert INVALID_PRIORITY_METADATA in result.denial_reasons
    assert INVALID_QUEUE_METADATA in result.denial_reasons
    assert UNKNOWN_METADATA_FIELD in result.denial_reasons


def test_execution_vectors_block_without_execution():
    result = build_execution_schedule(_request(
        scheduler_state=BLOCKED,
        requested_execution=True,
        thread_requested=True,
        async_execution_requested=True,
        subprocess_requested=True,
        network_requested=True,
        socket_requested=True,
        provider_execution_requested=True,
        production_activation_requested=True,
    ))

    assert result.scheduler_state == SCHEDULER_BLOCKED
    assert EXECUTION_REQUESTED in result.denial_reasons
    assert result.execution_allowed is False
    assert result.thread_execution is False
    assert result.async_execution is False
    assert result.subprocess_execution is False
    assert result.network_execution is False
    assert result.socket_execution is False
    assert result.provider_execution is False
    assert result.production_activation is False


def test_scheduler_is_deterministic_and_redacted():
    first = build_execution_schedule(_request())
    second = build_execution_schedule(_request())
    rendered = json.dumps(first.as_dict(), sort_keys=True)

    assert first.as_dict() == second.as_dict()
    assert "tenant-runtime" not in rendered
    assert "correlation-1" not in rendered
    assert "intake" not in rendered


def test_scheduler_evidence_is_hash_only():
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    rendered = json.dumps(evidence, sort_keys=True)

    assert HASH_RE.match(evidence["tenant_hash"])
    assert HASH_RE.match(evidence["policy_hash"])
    assert HASH_RE.match(evidence["evidence_hash"])
    assert HASH_RE.match(evidence["scheduler_hash"])
    assert HASH_RE.match(evidence["contract_hash"])
    assert HASH_RE.match(evidence["state_registry_hash"])
    assert HASH_RE.match(evidence["capability_registry_hash"])
    assert HASH_RE.match(evidence["queue_registry_hash"])
    assert evidence["threads"] is False
    assert evidence["async_execution"] is False
    assert evidence["subprocess"] is False
    assert evidence["network"] is False
    assert evidence["sockets"] is False
    assert evidence["execution_allowed"] is False
    assert evidence["provider_execution"] is False
    assert evidence["production_activation"] is False
    assert evidence["hash_only"] is True
    assert evidence["redacted"] is True
    for forbidden in ("credential", "provider_data", "raw_payload", "secret", "sensitive", "token"):
        assert forbidden not in rendered
