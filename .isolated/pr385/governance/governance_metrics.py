from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json
from governance.metrics_contracts import (
    ALLOWED_REQUEST_DECISIONS,
    ALLOWED_WORK_STATUSES,
    METRICS_EXECUTIVE_REPORT_SCHEMA,
    METRICS_POLICY_VERSION,
    METRICS_SNAPSHOT_SCHEMA,
    RISK_LEVELS,
    parse_timestamp,
    validate_executive_report,
    validate_metrics_snapshot,
)


TREND_BLOCKED = "BLOCKED"
AI_OVERRIDE_MARKERS = frozenset({"AI_AGENT", "CODEX", "AUTOMATION", "SYSTEM"})


@dataclass(frozen=True)
class MetricsResult:
    snapshot: dict[str, Any]
    executive_report: dict[str, Any]
    reason_codes: tuple[str, ...]
    fail_closed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot": self.snapshot,
            "executive_report": self.executive_report,
            "reason_codes": list(self.reason_codes),
            "fail_closed": self.fail_closed,
        }


def _now_text(now: datetime | None) -> str:
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return effective_now.isoformat().replace("+00:00", "Z")


def _append_reason(reasons: list[str], code: str) -> None:
    if code not in reasons:
        reasons.append(code)


def _hash(value: Any) -> str:
    return sha256_json(value if isinstance(value, dict) else {})


def _records(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise TypeError("metrics source lists must be arrays")
    if not all(isinstance(item, dict) for item in value):
        raise TypeError("metrics source entries must be objects")
    return value


def _duration_minutes(start: Any, end: Any) -> float | None:
    start_at = parse_timestamp(start)
    end_at = parse_timestamp(end)
    if start_at is None or end_at is None or end_at < start_at:
        return None
    return round((end_at - start_at).total_seconds() / 60.0, 2)


def _future_timestamp(record: dict[str, Any], now: datetime) -> bool:
    for key in (
        "timestamp",
        "generated_at",
        "created_at",
        "requested_at",
        "approved_at",
        "decision_timestamp",
        "assigned_at",
        "resolved_at",
        "closed_at",
    ):
        parsed = parse_timestamp(record.get(key))
        if parsed is not None and parsed > now:
            return True
    return False


def _negative_value(record: dict[str, Any]) -> bool:
    for value in record.values():
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value < 0:
            return True
    return False


def calculate_governance_health_score(
    *,
    fail_closed_count: int,
    missing_audit_count: int,
    sla_breach_count: int,
    critical_blocker_count: int,
    open_high_risk_count: int,
    stale_work_count: int,
    policy_missing: bool = False,
    lineage_missing: bool = False,
) -> int:
    if missing_audit_count > 0 or policy_missing or lineage_missing:
        return 0
    penalties = (
        fail_closed_count * 12
        + sla_breach_count * 8
        + critical_blocker_count * 15
        + open_high_risk_count * 10
        + stale_work_count * 5
    )
    return max(0, 100 - penalties)


def _risk_trend(high_risk_count: int, critical_blockers: int, open_work_items: int) -> str:
    if critical_blockers > 0 or high_risk_count > open_work_items + 1:
        return "WORSENING"
    if high_risk_count == 0 and critical_blockers == 0 and open_work_items == 0:
        return "IMPROVING"
    return "STABLE"


def _build_executive_report(snapshot: dict[str, Any], blockers: list[str], generated_at: str) -> dict[str, Any]:
    report = {
        "schema": METRICS_EXECUTIVE_REPORT_SCHEMA,
        "report_id": f"metrics-report-{sha256_json({'metrics_id': snapshot.get('metrics_id'), 'generated_at': generated_at})[:24]}",
        "generated_at": generated_at,
        "governance_health_score": snapshot["governance_health_score"],
        "top_blockers": blockers[:5],
        "sla_breaches": snapshot["sla_breaches"],
        "risk_trend_summary": snapshot["trend_direction"],
        "audit_lineage_status": "BLOCKED" if snapshot["fail_closed"] else "VERIFIED",
        "recommendations": ["Resolve fail-closed blockers before claiming readiness"] if snapshot["fail_closed"] else [],
        "fail_closed": snapshot["fail_closed"],
        "reason_codes": list(snapshot["reason_codes"]),
        "read_only": True,
        "can_approve": False,
        "can_unblock": False,
        "can_close_work": False,
        "can_deploy": False,
    }
    return report


def build_governance_metrics(source: dict[str, Any] | None, *, now: datetime | None = None) -> MetricsResult:
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    generated_at = _now_text(effective_now)
    reasons: list[str] = []
    safe_source = source if isinstance(source, dict) else {}

    if not isinstance(source, dict):
        _append_reason(reasons, "METRICS_SOURCE_MALFORMED")
    if not safe_source.get("audit_hash"):
        _append_reason(reasons, "METRICS_AUDIT_SOURCE_MISSING")
    if not safe_source.get("policy_version"):
        _append_reason(reasons, "METRICS_POLICY_VERSION_MISSING")
    if not safe_source.get("lineage_hash"):
        _append_reason(reasons, "METRICS_LINEAGE_MISSING")
    if safe_source.get("metric_overrides"):
        _append_reason(reasons, "METRICS_AI_OVERRIDE_BLOCKED")
    if str(safe_source.get("generated_by_role", "")).upper() in AI_OVERRIDE_MARKERS:
        _append_reason(reasons, "METRICS_AI_GENERATOR_BLOCKED")

    try:
        requests = _records(safe_source.get("requests"))
        reviews = _records(safe_source.get("reviews"))
        work_items = _records(safe_source.get("work_items"))
        blockers = _records(safe_source.get("blockers"))
    except TypeError:
        requests, reviews, work_items, blockers = [], [], [], []
        _append_reason(reasons, "METRICS_INPUT_MALFORMED")

    for record in requests + reviews + work_items + blockers:
        if _future_timestamp(record, effective_now):
            _append_reason(reasons, "METRICS_FUTURE_TIMESTAMP_BLOCKED")
        if _negative_value(record):
            _append_reason(reasons, "METRICS_NEGATIVE_COUNT_BLOCKED")

    decisions = [str(record.get("decision", "")) for record in requests + reviews if record.get("decision") is not None]
    for decision in decisions:
        if decision not in ALLOWED_REQUEST_DECISIONS:
            _append_reason(reasons, f"METRICS_DECISION_UNKNOWN:{decision or 'MISSING'}")
    statuses = [str(record.get("status", "")) for record in work_items if record.get("status") is not None]
    for status in statuses:
        if status not in ALLOWED_WORK_STATUSES:
            _append_reason(reasons, f"METRICS_STATUS_UNKNOWN:{status or 'MISSING'}")
    for request in requests:
        risk = str(request.get("risk_level", "LOW")).upper()
        if risk not in RISK_LEVELS:
            _append_reason(reasons, f"METRICS_RISK_UNKNOWN:{risk or 'MISSING'}")

    total_requests = len(requests)
    blocked_requests = sum(1 for item in requests + reviews if str(item.get("decision", "")) in {"BLOCKED", "EXECUTION_BLOCKED"})
    approved_requests = sum(1 for item in requests + reviews if str(item.get("decision", "")) in {"APPROVED", "EXECUTION_ALLOWED_PREVIEW"})
    rejected_requests = sum(1 for item in requests + reviews if str(item.get("decision", "")) == "REJECTED")
    needs_information_requests = sum(1 for item in requests + reviews if str(item.get("decision", "")) in {"NEEDS_INFORMATION", "HUMAN_REVIEW_REQUIRED"})
    escalated_work_items = sum(1 for item in work_items if str(item.get("status", "")) == "ESCALATED")
    resolved_work_items = sum(1 for item in work_items if str(item.get("status", "")) == "RESOLVED")
    closed_work_items = sum(1 for item in work_items if str(item.get("status", "")) == "CLOSED")
    open_work_items = sum(1 for item in work_items if str(item.get("status", "")) in {"NEW", "ASSIGNED", "IN_PROGRESS", "ESCALATED"})

    review_durations = [
        duration
        for duration in (_duration_minutes(item.get("created_at") or item.get("requested_at"), item.get("decision_timestamp")) for item in reviews)
        if duration is not None
    ]
    resolution_durations = [
        duration
        for duration in (_duration_minutes(item.get("created_at"), item.get("resolved_at")) for item in work_items)
        if duration is not None
    ]
    overdue_reviews = sum(1 for item in reviews if item.get("overdue") is True)
    overdue_work_items = sum(1 for item in work_items if item.get("overdue") is True)
    sla_breaches = overdue_reviews + overdue_work_items

    high_risk_count = sum(1 for item in requests if str(item.get("risk_level", "LOW")).upper() == "HIGH")
    medium_risk_count = sum(1 for item in requests if str(item.get("risk_level", "LOW")).upper() == "MEDIUM")
    low_risk_count = sum(1 for item in requests if str(item.get("risk_level", "LOW")).upper() == "LOW")
    critical_blockers = sum(1 for item in blockers if str(item.get("severity", "")).upper() == "CRITICAL")
    blocker_codes = [str(item.get("code", "")) for item in blockers if item.get("code")]
    trend_direction = TREND_BLOCKED if reasons else _risk_trend(high_risk_count, critical_blockers, open_work_items)

    missing_audit_count = 1 if "METRICS_AUDIT_SOURCE_MISSING" in reasons else 0
    policy_missing = "METRICS_POLICY_VERSION_MISSING" in reasons
    lineage_missing = "METRICS_LINEAGE_MISSING" in reasons
    fail_closed_count = len(reasons)
    open_high_risk_count = sum(
        1
        for item in work_items
        if str(item.get("risk_level", "")).upper() == "HIGH" and str(item.get("status", "")) in {"NEW", "ASSIGNED", "IN_PROGRESS", "ESCALATED"}
    )
    stale_work_count = sum(1 for item in work_items if item.get("stale") is True)
    health_score = calculate_governance_health_score(
        fail_closed_count=fail_closed_count,
        missing_audit_count=missing_audit_count,
        sla_breach_count=sla_breaches,
        critical_blocker_count=critical_blockers,
        open_high_risk_count=open_high_risk_count,
        stale_work_count=stale_work_count,
        policy_missing=policy_missing,
        lineage_missing=lineage_missing,
    )

    fail_closed = bool(reasons)
    snapshot = {
        "schema": METRICS_SNAPSHOT_SCHEMA,
        "metrics_id": f"metrics-{sha256_json({'source': safe_source, 'generated_at': generated_at})[:24]}",
        "generated_at": generated_at,
        "policy_version": str(safe_source.get("policy_version", METRICS_POLICY_VERSION)),
        "source_hash": str(safe_source.get("source_hash") or _hash(safe_source)),
        "audit_hash": str(safe_source.get("audit_hash", "")),
        "lineage_hash": str(safe_source.get("lineage_hash", "")),
        "fail_closed": fail_closed,
        "reason_codes": sorted(reasons),
        "total_requests": total_requests,
        "blocked_requests": blocked_requests,
        "approved_requests": approved_requests,
        "rejected_requests": rejected_requests,
        "needs_information_requests": needs_information_requests,
        "escalated_work_items": escalated_work_items,
        "resolved_work_items": resolved_work_items,
        "closed_work_items": closed_work_items,
        "open_work_items": open_work_items,
        "average_review_time": round(sum(review_durations) / len(review_durations), 2) if review_durations else 0,
        "average_resolution_time": round(sum(resolution_durations) / len(resolution_durations), 2) if resolution_durations else 0,
        "overdue_reviews": overdue_reviews,
        "overdue_work_items": overdue_work_items,
        "sla_breaches": sla_breaches,
        "high_risk_count": high_risk_count,
        "medium_risk_count": medium_risk_count,
        "low_risk_count": low_risk_count,
        "critical_blockers": critical_blockers,
        "trend_direction": trend_direction,
        "governance_health_score": health_score,
        "sla_status": "BREACHED" if sla_breaches else ("BLOCKED" if fail_closed else "ON_TRACK"),
        "risk_trends": {"trend_direction": trend_direction, "high": high_risk_count, "medium": medium_risk_count, "low": low_risk_count},
        "critical_blocker_codes": blocker_codes,
        "operator_queue_counts": dict(safe_source.get("operator_queue_counts", {})) if isinstance(safe_source.get("operator_queue_counts"), dict) else {},
        "work_queue_counts": dict(safe_source.get("work_queue_counts", {})) if isinstance(safe_source.get("work_queue_counts"), dict) else {},
        "auto_healthy": False,
        "auto_approved": False,
        "auto_resolved": False,
        "auto_closed": False,
        "auto_executed": False,
    }
    snapshot_validation = validate_metrics_snapshot(snapshot, now=effective_now)
    if not snapshot_validation.valid:
        for reason in snapshot_validation.reason_codes:
            _append_reason(reasons, reason)
        snapshot["fail_closed"] = True
        snapshot["reason_codes"] = sorted(reasons)
        snapshot["governance_health_score"] = 0
        snapshot["trend_direction"] = TREND_BLOCKED
        snapshot["sla_status"] = "BLOCKED"

    report = _build_executive_report(snapshot, blocker_codes, generated_at)
    report_validation = validate_executive_report(report, now=effective_now)
    if not report_validation.valid:
        for reason in report_validation.reason_codes:
            _append_reason(reasons, reason)
        snapshot["fail_closed"] = True
        snapshot["reason_codes"] = sorted(reasons)
        snapshot["governance_health_score"] = 0
        report = _build_executive_report(snapshot, blocker_codes, generated_at)

    return MetricsResult(
        snapshot=snapshot,
        executive_report=report,
        reason_codes=tuple(sorted(set(reasons))),
        fail_closed=bool(reasons),
    )


def empty_metrics_dashboard_state() -> dict[str, Any]:
    result = build_governance_metrics(source=None)
    snapshot = result.snapshot
    return {
        "schema_version": "usbay.metrics.demo_dashboard_state.v1",
        "governance_health_score": snapshot["governance_health_score"],
        "total_requests": snapshot["total_requests"],
        "blocked_requests": snapshot["blocked_requests"],
        "approved_requests": snapshot["approved_requests"],
        "rejected_requests": snapshot["rejected_requests"],
        "operator_queue_counts": {},
        "work_queue_counts": {},
        "sla_status": snapshot["sla_status"],
        "risk_trends": snapshot["risk_trends"],
        "critical_blockers": snapshot["critical_blocker_codes"],
        "last_metrics_generated_at": snapshot["generated_at"],
        "reason_codes": list(result.reason_codes),
        "audit_hash": snapshot["audit_hash"],
        "lineage_hash": snapshot["lineage_hash"],
        "executive_report": result.executive_report,
        "auto_healthy": False,
        "auto_approved": False,
        "auto_resolved": False,
        "auto_closed": False,
        "auto_executed": False,
    }
