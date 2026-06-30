from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json


METRICS_SNAPSHOT_SCHEMA = "usbay.metrics.snapshot.v1"
METRICS_KPI_SCHEMA = "usbay.metrics.kpi.v1"
METRICS_SLA_SCHEMA = "usbay.metrics.sla.v1"
METRICS_RISK_TREND_SCHEMA = "usbay.metrics.risk_trend.v1"
METRICS_EXECUTIVE_REPORT_SCHEMA = "usbay.metrics.executive_report.v1"
METRICS_POLICY_VERSION = "usbay.pb-metrics.governed-governance-intelligence.v1"

REQUIRED_METRICS_FIELDS = (
    "metrics_id",
    "generated_at",
    "policy_version",
    "source_hash",
    "audit_hash",
    "lineage_hash",
    "fail_closed",
    "reason_codes",
)

KPI_FIELDS = (
    "total_requests",
    "blocked_requests",
    "approved_requests",
    "rejected_requests",
    "needs_information_requests",
    "escalated_work_items",
    "resolved_work_items",
    "closed_work_items",
    "open_work_items",
)

SLA_FIELDS = (
    "average_review_time",
    "average_resolution_time",
    "overdue_reviews",
    "overdue_work_items",
    "sla_breaches",
)

RISK_FIELDS = (
    "high_risk_count",
    "medium_risk_count",
    "low_risk_count",
    "critical_blockers",
    "trend_direction",
)

EXECUTIVE_REPORT_FIELDS = (
    "report_id",
    "generated_at",
    "governance_health_score",
    "top_blockers",
    "sla_breaches",
    "risk_trend_summary",
    "audit_lineage_status",
    "recommendations",
    "fail_closed",
    "reason_codes",
)

ALLOWED_REQUEST_DECISIONS = frozenset(
    {
        "APPROVED",
        "REJECTED",
        "NEEDS_INFORMATION",
        "BLOCKED",
        "EXECUTION_ALLOWED_PREVIEW",
        "EXECUTION_BLOCKED",
        "HUMAN_REVIEW_REQUIRED",
    }
)
ALLOWED_WORK_STATUSES = frozenset({"NEW", "ASSIGNED", "IN_PROGRESS", "ESCALATED", "RESOLVED", "CLOSED", "BLOCKED"})
RISK_LEVELS = frozenset({"LOW", "MEDIUM", "HIGH"})


@dataclass(frozen=True)
class MetricsValidation:
    valid: bool
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "reason_codes": list(self.reason_codes)}


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _missing_fields(payload: dict[str, Any], required: tuple[str, ...]) -> list[str]:
    return [field for field in required if payload.get(field) in ("", None)]


def _nonnegative_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0


def validate_metrics_snapshot(snapshot: dict[str, Any] | None, *, now: datetime | None = None) -> MetricsValidation:
    if not isinstance(snapshot, dict):
        return MetricsValidation(False, ("METRICS_SNAPSHOT_MISSING",))

    reasons: list[str] = []
    for field in _missing_fields(snapshot, REQUIRED_METRICS_FIELDS):
        reasons.append(f"METRICS_{field.upper()}_MISSING")
    for field in KPI_FIELDS + SLA_FIELDS + RISK_FIELDS:
        if field not in snapshot:
            reasons.append(f"METRICS_{field.upper()}_MISSING")

    if snapshot.get("schema") != METRICS_SNAPSHOT_SCHEMA:
        reasons.append("METRICS_SCHEMA_INVALID")
    if not isinstance(snapshot.get("reason_codes"), list):
        reasons.append("METRICS_REASON_CODES_INVALID")
    generated_at = parse_timestamp(snapshot.get("generated_at"))
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if generated_at is None:
        reasons.append("METRICS_GENERATED_AT_INVALID")
    elif generated_at > effective_now:
        reasons.append("METRICS_GENERATED_AT_FUTURE")

    for field in KPI_FIELDS + SLA_FIELDS:
        if field in snapshot and not _nonnegative_number(snapshot.get(field)):
            reasons.append(f"METRICS_{field.upper()}_NEGATIVE_OR_INVALID")
    for field in ("high_risk_count", "medium_risk_count", "low_risk_count", "critical_blockers"):
        if field in snapshot and not _nonnegative_number(snapshot.get(field)):
            reasons.append(f"METRICS_{field.upper()}_NEGATIVE_OR_INVALID")
    if snapshot.get("trend_direction") not in {"IMPROVING", "STABLE", "WORSENING", "BLOCKED"}:
        reasons.append("METRICS_TREND_DIRECTION_UNKNOWN")

    if not str(snapshot.get("audit_hash", "")).strip():
        reasons.append("METRICS_AUDIT_HASH_MISSING")
    if not str(snapshot.get("lineage_hash", "")).strip():
        reasons.append("METRICS_LINEAGE_HASH_MISSING")
    if not str(snapshot.get("policy_version", "")).strip():
        reasons.append("METRICS_POLICY_VERSION_MISSING")

    return MetricsValidation(not reasons, tuple(sorted(set(reasons))))


def validate_executive_report(report: dict[str, Any] | None, *, now: datetime | None = None) -> MetricsValidation:
    if not isinstance(report, dict):
        return MetricsValidation(False, ("METRICS_EXECUTIVE_REPORT_MISSING",))
    reasons: list[str] = []
    for field in _missing_fields(report, EXECUTIVE_REPORT_FIELDS):
        reasons.append(f"METRICS_REPORT_{field.upper()}_MISSING")
    if report.get("schema") != METRICS_EXECUTIVE_REPORT_SCHEMA:
        reasons.append("METRICS_REPORT_SCHEMA_INVALID")
    generated_at = parse_timestamp(report.get("generated_at"))
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if generated_at is None:
        reasons.append("METRICS_REPORT_GENERATED_AT_INVALID")
    elif generated_at > effective_now:
        reasons.append("METRICS_REPORT_GENERATED_AT_FUTURE")
    for flag in ("can_approve", "can_unblock", "can_close_work", "can_deploy"):
        if report.get(flag) is not False:
            reasons.append(f"METRICS_REPORT_{flag.upper()}_MUST_BE_FALSE")
    return MetricsValidation(not reasons, tuple(sorted(set(reasons))))


def metrics_hash(payload: dict[str, Any]) -> str:
    return sha256_json({key: value for key, value in payload.items() if key != "audit_hash"})
