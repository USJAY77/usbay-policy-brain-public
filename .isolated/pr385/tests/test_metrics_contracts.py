from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.metrics_contracts import (
    METRICS_EXECUTIVE_REPORT_SCHEMA,
    METRICS_POLICY_VERSION,
    METRICS_SNAPSHOT_SCHEMA,
    validate_executive_report,
    validate_metrics_snapshot,
)


pytestmark = pytest.mark.governance

NOW = datetime(2026, 6, 17, 4, 0, tzinfo=timezone.utc)


def snapshot(**overrides):
    payload = {
        "schema": METRICS_SNAPSHOT_SCHEMA,
        "metrics_id": "metrics-1",
        "generated_at": "2026-06-17T03:00:00Z",
        "policy_version": METRICS_POLICY_VERSION,
        "source_hash": "s" * 64,
        "audit_hash": "a" * 64,
        "lineage_hash": "l" * 64,
        "fail_closed": False,
        "reason_codes": [],
        "total_requests": 3,
        "blocked_requests": 1,
        "approved_requests": 1,
        "rejected_requests": 1,
        "needs_information_requests": 0,
        "escalated_work_items": 1,
        "resolved_work_items": 1,
        "closed_work_items": 1,
        "open_work_items": 1,
        "average_review_time": 10,
        "average_resolution_time": 20,
        "overdue_reviews": 0,
        "overdue_work_items": 0,
        "sla_breaches": 0,
        "high_risk_count": 1,
        "medium_risk_count": 1,
        "low_risk_count": 1,
        "critical_blockers": 0,
        "trend_direction": "STABLE",
    }
    payload.update(overrides)
    return payload


def report(**overrides):
    payload = {
        "schema": METRICS_EXECUTIVE_REPORT_SCHEMA,
        "report_id": "report-1",
        "generated_at": "2026-06-17T03:00:00Z",
        "governance_health_score": 90,
        "top_blockers": [],
        "sla_breaches": 0,
        "risk_trend_summary": "STABLE",
        "audit_lineage_status": "VERIFIED",
        "recommendations": [],
        "fail_closed": False,
        "reason_codes": [],
        "can_approve": False,
        "can_unblock": False,
        "can_close_work": False,
        "can_deploy": False,
    }
    payload.update(overrides)
    return payload


def test_valid_metrics_snapshot():
    result = validate_metrics_snapshot(snapshot(), now=NOW)

    assert result.valid is True
    assert result.reason_codes == ()


def test_missing_audit_policy_and_lineage_block():
    result = validate_metrics_snapshot(snapshot(audit_hash="", policy_version="", lineage_hash=""), now=NOW)

    assert result.valid is False
    assert "METRICS_AUDIT_HASH_MISSING" in result.reason_codes
    assert "METRICS_POLICY_VERSION_MISSING" in result.reason_codes
    assert "METRICS_LINEAGE_HASH_MISSING" in result.reason_codes


def test_negative_count_blocks():
    result = validate_metrics_snapshot(snapshot(total_requests=-1), now=NOW)

    assert result.valid is False
    assert "METRICS_TOTAL_REQUESTS_NEGATIVE_OR_INVALID" in result.reason_codes


def test_future_timestamp_blocks():
    result = validate_metrics_snapshot(snapshot(generated_at="2026-06-18T00:00:00Z"), now=NOW)

    assert result.valid is False
    assert "METRICS_GENERATED_AT_FUTURE" in result.reason_codes


def test_unknown_trend_blocks():
    result = validate_metrics_snapshot(snapshot(trend_direction="AUTO_HEALTHY"), now=NOW)

    assert result.valid is False
    assert "METRICS_TREND_DIRECTION_UNKNOWN" in result.reason_codes


def test_valid_executive_report_is_read_only():
    result = validate_executive_report(report(), now=NOW)

    assert result.valid is True
    assert result.reason_codes == ()


def test_executive_report_cannot_approve_unblock_close_or_deploy():
    result = validate_executive_report(report(can_approve=True, can_unblock=True, can_close_work=True, can_deploy=True), now=NOW)

    assert result.valid is False
    assert "METRICS_REPORT_CAN_APPROVE_MUST_BE_FALSE" in result.reason_codes
    assert "METRICS_REPORT_CAN_UNBLOCK_MUST_BE_FALSE" in result.reason_codes
    assert "METRICS_REPORT_CAN_CLOSE_WORK_MUST_BE_FALSE" in result.reason_codes
    assert "METRICS_REPORT_CAN_DEPLOY_MUST_BE_FALSE" in result.reason_codes
