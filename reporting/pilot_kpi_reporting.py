from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


PILOT_KPI_REPORTING_VERSION = "pb224-pilot-kpi-reporting-v1"
KPI_NAMES = (
    "blocked_actions",
    "approved_actions",
    "failed_evaluations",
    "audit_records_written",
    "human_approvals_required",
    "time_to_decision_seconds",
)


@dataclass(frozen=True)
class PilotKpiReport:
    blocked_actions: int = 0
    approved_actions: int = 0
    failed_evaluations: int = 0
    audit_records_written: int = 0
    human_approvals_required: int = 0
    time_to_decision_seconds: float = 0.0
    local_only: bool = True
    production_activation_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["reporting_version"] = PILOT_KPI_REPORTING_VERSION
        return payload


def generate_pilot_kpi_report(events: list[dict[str, Any]]) -> dict[str, Any]:
    report = PilotKpiReport(
        blocked_actions=sum(1 for event in events if event.get("decision") in {"BLOCKED", "FAIL_CLOSED"}),
        approved_actions=sum(1 for event in events if event.get("decision") in {"APPROVED", "VERIFIED"}),
        failed_evaluations=sum(1 for event in events if event.get("event_type") == "policy_fail"),
        audit_records_written=sum(1 for event in events if bool(event.get("audit_hash"))),
        human_approvals_required=sum(1 for event in events if bool(event.get("human_approval_required"))),
        time_to_decision_seconds=round(
            sum(float(event.get("time_to_decision_seconds", 0.0)) for event in events) / len(events),
            3,
        )
        if events
        else 0.0,
    )
    payload = report.to_dict()
    payload["kpis"] = list(KPI_NAMES)
    payload["evidence_source"] = "local_only"
    return payload
