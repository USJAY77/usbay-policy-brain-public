from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


def monitor_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ExecutionMonitorRecord:
    execution_id: str
    execution_status: str
    authority_status: str
    approval_status: str
    revocation_status: str
    audit_hash: str


def build_execution_monitor_record(
    *,
    execution_id: str,
    execution_status: str,
    authority_status: str,
    approval_status: str,
    revocation_status: str,
) -> ExecutionMonitorRecord:
    if not execution_id:
        execution_status = "FAIL_CLOSED"
    audit_hash = monitor_hash(execution_id, execution_status, authority_status, approval_status, revocation_status)
    return ExecutionMonitorRecord(
        execution_id=execution_id,
        execution_status=execution_status,
        authority_status=authority_status,
        approval_status=approval_status,
        revocation_status=revocation_status,
        audit_hash=audit_hash,
    )


def execution_monitor_dashboard(records: list[ExecutionMonitorRecord]) -> dict[str, object]:
    blocked = [record.execution_id for record in records if record.execution_status in {"BLOCK", "FAIL_CLOSED"}]
    return {
        "record_count": len(records),
        "blocked_executions": blocked,
        "all_records_audited": all(bool(record.audit_hash) for record in records),
        "mock_data_only": True,
        "live_execution_enabled": False,
    }

