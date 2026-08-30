from __future__ import annotations

from reporting.pilot_kpi_reporting import KPI_NAMES, generate_pilot_kpi_report


def test_pilot_kpi_report_contains_required_kpis_and_is_local_only() -> None:
    report = generate_pilot_kpi_report([])
    assert tuple(report["kpis"]) == KPI_NAMES
    assert report["local_only"] is True
    assert report["production_activation_allowed"] is False


def test_pilot_kpi_report_counts_local_events() -> None:
    report = generate_pilot_kpi_report(
        [
            {
                "decision": "BLOCKED",
                "event_type": "policy_fail",
                "human_approval_required": True,
                "time_to_decision_seconds": 4.0,
            },
            {
                "decision": "VERIFIED",
                "audit_hash": "abc",
                "human_approval_required": False,
                "time_to_decision_seconds": 2.0,
            },
        ]
    )
    assert report["blocked_actions"] == 1
    assert report["approved_actions"] == 1
    assert report["failed_evaluations"] == 1
    assert report["audit_records_written"] == 1
    assert report["human_approvals_required"] == 1
    assert report["time_to_decision_seconds"] == 3.0
