from control_plane.execution_monitor import build_execution_monitor_record, execution_monitor_dashboard


def test_execution_monitor_reports_mock_statuses() -> None:
    record = build_execution_monitor_record(
        execution_id="execution-1",
        execution_status="PENDING",
        authority_status="VERIFIED",
        approval_status="PENDING",
        revocation_status="CLEAR",
    )
    dashboard = execution_monitor_dashboard([record])

    assert record.audit_hash
    assert dashboard["record_count"] == 1
    assert dashboard["all_records_audited"] is True
    assert dashboard["mock_data_only"] is True
    assert dashboard["live_execution_enabled"] is False


def test_execution_monitor_fail_closed_missing_execution_id() -> None:
    record = build_execution_monitor_record(
        execution_id="",
        execution_status="PENDING",
        authority_status="VERIFIED",
        approval_status="PENDING",
        revocation_status="CLEAR",
    )
    dashboard = execution_monitor_dashboard([record])

    assert record.execution_status == "FAIL_CLOSED"
    assert dashboard["blocked_executions"] == [""]

