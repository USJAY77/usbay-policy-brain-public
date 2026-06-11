from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


def operational_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class OperationalReadinessInput:
    governance: str
    runtime: str
    authority: str
    adapters: str
    review_workflows: str


@dataclass(frozen=True)
class OperationalReadinessReport:
    decision: str
    status: str
    failed_controls: tuple[str, ...]
    audit_hash: str
    report: dict[str, object]


def validate_operational_readiness(readiness: OperationalReadinessInput) -> OperationalReadinessReport:
    controls = {
        "governance": readiness.governance,
        "runtime": readiness.runtime,
        "authority": readiness.authority,
        "adapters": readiness.adapters,
        "review_workflows": readiness.review_workflows,
    }
    failed = tuple(name for name, state in controls.items() if state != "VERIFIED")
    decision = "VERIFIED" if not failed else "FAIL_CLOSED"
    status = "READY_FOR_REVIEW" if decision == "VERIFIED" else "BLOCKED"
    audit_hash = operational_hash(decision, status, controls, failed)
    report = {
        "decision": decision,
        "status": status,
        "controls": controls,
        "failed_controls": list(failed),
        "mock_data_only": True,
        "live_execution_enabled": False,
        "network_calls_enabled": False,
        "audit_hash": audit_hash,
    }
    return OperationalReadinessReport(decision, status, failed, audit_hash, report)

