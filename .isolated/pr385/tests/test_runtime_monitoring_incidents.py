from __future__ import annotations

from monitoring.runtime_monitoring import MonitoringEvent, MonitoringEventType, evaluate_monitoring_event, runtime_monitoring_contract_json


def test_runtime_monitoring_contract_defines_required_events() -> None:
    contract = runtime_monitoring_contract_json()
    assert contract["unsafe_state_outcome"] == "BLOCKED"
    assert contract["events"] == [
        "gateway_error",
        "policy_fail",
        "approval_expired",
        "connector_blocked",
        "audit_write_failed",
    ]


def test_every_unsafe_monitoring_event_blocks() -> None:
    for event_type in MonitoringEventType:
        result = evaluate_monitoring_event(
            MonitoringEvent(event_type=event_type, actor="pilot-monitor", policy_hash="a" * 64)
        )
        assert result["decision"] == "BLOCKED"
        assert result["status"] == "BLOCKED"


def test_unknown_monitoring_event_blocks_without_exception() -> None:
    result = evaluate_monitoring_event({"event_type": "unknown", "status": "BROKEN"})
    assert result["decision"] == "BLOCKED"
    assert "UNKNOWN_MONITORING_EVENT" in result["gaps"]
