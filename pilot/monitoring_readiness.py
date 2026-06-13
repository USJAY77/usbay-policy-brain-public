from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


PILOT_MONITORING_READINESS_VERSION = "pb228-pilot-monitoring-readiness-v1"
MONITORING_COUNTERS = (
    "blocked_actions",
    "approved_actions",
    "failed_evaluations",
    "audit_writes",
    "approval_expirations",
    "rollback_triggers",
)


@dataclass(frozen=True)
class PilotMonitoringReadiness:
    blocked_actions: int = 0
    approved_actions: int = 0
    failed_evaluations: int = 0
    audit_writes: int = 0
    approval_expirations: int = 0
    rollback_triggers: int = 0
    status: str = "BLOCKED"
    local_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["contract_version"] = PILOT_MONITORING_READINESS_VERSION
        payload["monitored_counters"] = list(MONITORING_COUNTERS)
        payload["live_monitoring_activation_allowed"] = False
        return payload


def pilot_monitoring_readiness_json(events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    records = events or []
    readiness = PilotMonitoringReadiness(
        blocked_actions=sum(1 for event in records if event.get("decision") in {"BLOCKED", "FAIL_CLOSED"}),
        approved_actions=sum(1 for event in records if event.get("decision") in {"APPROVED", "VERIFIED"}),
        failed_evaluations=sum(1 for event in records if event.get("event_type") == "policy_fail"),
        audit_writes=sum(1 for event in records if bool(event.get("audit_hash"))),
        approval_expirations=sum(1 for event in records if event.get("event_type") == "approval_expired"),
        rollback_triggers=sum(1 for event in records if bool(event.get("rollback_trigger"))),
    )
    return readiness.to_dict()


def evaluate_monitoring_readiness(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {"decision": "FAIL_CLOSED", "status": "BLOCKED", "gaps": ["MALFORMED_MONITORING_READINESS"]}
    gaps: list[str] = []
    for counter in MONITORING_COUNTERS:
        if counter not in payload or not isinstance(payload.get(counter), int) or payload.get(counter) < 0:
            gaps.append(f"MALFORMED_{counter.upper()}")
    if payload.get("local_only") is not True:
        gaps.append("MONITORING_NOT_LOCAL_ONLY")
    if payload.get("live_monitoring_activation_allowed") is not False:
        gaps.append("LIVE_MONITORING_ACTIVATION_NOT_ALLOWED")
    return {
        "decision": "VERIFIED" if not gaps else "FAIL_CLOSED",
        "status": "READY_FOR_REVIEW" if not gaps else "BLOCKED",
        "gaps": sorted(set(gaps)),
        "contract_version": PILOT_MONITORING_READINESS_VERSION,
    }
