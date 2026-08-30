from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.governance_metrics import build_governance_metrics, calculate_governance_health_score, empty_metrics_dashboard_state
from governance.metrics_contracts import METRICS_POLICY_VERSION


pytestmark = pytest.mark.governance

NOW = datetime(2026, 6, 17, 4, 0, tzinfo=timezone.utc)


def source(**overrides):
    payload = {
        "source_hash": "s" * 64,
        "audit_hash": "a" * 64,
        "lineage_hash": "l" * 64,
        "policy_version": METRICS_POLICY_VERSION,
        "requests": [
            {"request_id": "req-1", "decision": "APPROVED", "risk_level": "LOW", "requested_at": "2026-06-17T02:00:00Z"},
            {"request_id": "req-2", "decision": "EXECUTION_BLOCKED", "risk_level": "HIGH", "requested_at": "2026-06-17T02:10:00Z"},
            {"request_id": "req-3", "decision": "REJECTED", "risk_level": "MEDIUM", "requested_at": "2026-06-17T02:20:00Z"},
        ],
        "reviews": [
            {"review_id": "rev-1", "decision": "APPROVED", "created_at": "2026-06-17T02:00:00Z", "decision_timestamp": "2026-06-17T02:10:00Z"},
            {"review_id": "rev-2", "decision": "NEEDS_INFORMATION", "created_at": "2026-06-17T02:00:00Z", "decision_timestamp": "2026-06-17T02:20:00Z", "overdue": True},
        ],
        "work_items": [
            {"work_item_id": "work-1", "status": "ESCALATED", "risk_level": "HIGH", "created_at": "2026-06-17T02:00:00Z", "resolved_at": "2026-06-17T03:00:00Z", "overdue": True},
            {"work_item_id": "work-2", "status": "RESOLVED", "created_at": "2026-06-17T02:00:00Z", "resolved_at": "2026-06-17T02:30:00Z"},
            {"work_item_id": "work-3", "status": "CLOSED", "created_at": "2026-06-17T02:00:00Z", "resolved_at": "2026-06-17T02:15:00Z"},
        ],
        "blockers": [{"code": "PBSEC005_HUMAN_APPROVAL_MISSING", "severity": "CRITICAL"}],
        "operator_queue_counts": {"pending": 1, "approved": 1},
        "work_queue_counts": {"escalated": 1, "resolved": 1, "closed": 1},
    }
    payload.update(overrides)
    return payload


def test_valid_metrics_snapshot_kpi_sla_and_risk_calculation():
    result = build_governance_metrics(source(), now=NOW)
    snapshot = result.snapshot

    assert snapshot["total_requests"] == 3
    assert snapshot["blocked_requests"] == 1
    assert snapshot["approved_requests"] == 2
    assert snapshot["rejected_requests"] == 1
    assert snapshot["needs_information_requests"] == 1
    assert snapshot["escalated_work_items"] == 1
    assert snapshot["resolved_work_items"] == 1
    assert snapshot["closed_work_items"] == 1
    assert snapshot["open_work_items"] == 1
    assert snapshot["average_review_time"] == 15
    assert snapshot["average_resolution_time"] == 35
    assert snapshot["overdue_reviews"] == 1
    assert snapshot["overdue_work_items"] == 1
    assert snapshot["sla_breaches"] == 2
    assert snapshot["high_risk_count"] == 1
    assert snapshot["medium_risk_count"] == 1
    assert snapshot["low_risk_count"] == 1
    assert snapshot["critical_blockers"] == 1
    assert snapshot["trend_direction"] == "WORSENING"


def test_valid_executive_report_is_read_only():
    result = build_governance_metrics(source(), now=NOW)
    report = result.executive_report

    assert report["schema"] == "usbay.metrics.executive_report.v1"
    assert report["read_only"] is True
    assert report["can_approve"] is False
    assert report["can_unblock"] is False
    assert report["can_close_work"] is False
    assert report["can_deploy"] is False


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (source(audit_hash=""), "METRICS_AUDIT_SOURCE_MISSING"),
        (source(policy_version=""), "METRICS_POLICY_VERSION_MISSING"),
        (source(lineage_hash=""), "METRICS_LINEAGE_MISSING"),
        ({"audit_hash": "a"}, "METRICS_POLICY_VERSION_MISSING"),
        (source(requests=[{"decision": "AUTO_APPROVED", "risk_level": "LOW"}]), "METRICS_DECISION_UNKNOWN:AUTO_APPROVED"),
        (source(work_items=[{"status": "AUTO_CLOSED"}]), "METRICS_STATUS_UNKNOWN:AUTO_CLOSED"),
        (source(requests=[{"decision": "APPROVED", "risk_level": "LOW", "count": -1}]), "METRICS_NEGATIVE_COUNT_BLOCKED"),
        (source(requests=[{"decision": "APPROVED", "risk_level": "LOW", "requested_at": "2026-06-18T00:00:00Z"}]), "METRICS_FUTURE_TIMESTAMP_BLOCKED"),
        (source(metric_overrides={"approved_requests": 99}), "METRICS_AI_OVERRIDE_BLOCKED"),
        (source(generated_by_role="AI_AGENT"), "METRICS_AI_GENERATOR_BLOCKED"),
    ],
)
def test_fail_closed_metric_inputs(payload, reason):
    result = build_governance_metrics(payload, now=NOW)

    assert result.fail_closed is True
    assert reason in result.reason_codes
    assert result.snapshot["governance_health_score"] <= 100


def test_malformed_input_blocks():
    result = build_governance_metrics("not-a-dict", now=NOW)

    assert result.fail_closed is True
    assert "METRICS_SOURCE_MALFORMED" in result.reason_codes


def test_health_score_deterministic_and_decreases_with_blockers():
    healthy = calculate_governance_health_score(
        fail_closed_count=0,
        missing_audit_count=0,
        sla_breach_count=0,
        critical_blocker_count=0,
        open_high_risk_count=0,
        stale_work_count=0,
    )
    blocked = calculate_governance_health_score(
        fail_closed_count=1,
        missing_audit_count=0,
        sla_breach_count=1,
        critical_blocker_count=1,
        open_high_risk_count=1,
        stale_work_count=1,
    )
    blocked_again = calculate_governance_health_score(
        fail_closed_count=1,
        missing_audit_count=0,
        sla_breach_count=1,
        critical_blocker_count=1,
        open_high_risk_count=1,
        stale_work_count=1,
    )

    assert healthy == 100
    assert blocked == blocked_again
    assert blocked < healthy


def test_missing_audit_policy_or_lineage_forces_score_zero():
    assert calculate_governance_health_score(
        fail_closed_count=0,
        missing_audit_count=1,
        sla_breach_count=0,
        critical_blocker_count=0,
        open_high_risk_count=0,
        stale_work_count=0,
    ) == 0
    assert calculate_governance_health_score(
        fail_closed_count=0,
        missing_audit_count=0,
        sla_breach_count=0,
        critical_blocker_count=0,
        open_high_risk_count=0,
        stale_work_count=0,
        policy_missing=True,
    ) == 0
    assert calculate_governance_health_score(
        fail_closed_count=0,
        missing_audit_count=0,
        sla_breach_count=0,
        critical_blocker_count=0,
        open_high_risk_count=0,
        stale_work_count=0,
        lineage_missing=True,
    ) == 0


def test_empty_dashboard_metrics_state_is_fail_closed():
    state = empty_metrics_dashboard_state()

    assert state["governance_health_score"] == 0
    assert state["sla_status"] == "BLOCKED"
    assert state["auto_healthy"] is False
    assert state["auto_approved"] is False
    assert state["auto_resolved"] is False
    assert state["auto_closed"] is False
    assert state["auto_executed"] is False
