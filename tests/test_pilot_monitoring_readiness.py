from __future__ import annotations

from pilot.monitoring_readiness import MONITORING_COUNTERS, evaluate_monitoring_readiness, pilot_monitoring_readiness_json


def test_monitoring_readiness_contains_required_counters() -> None:
    readiness = pilot_monitoring_readiness_json()
    assert tuple(readiness["monitored_counters"]) == MONITORING_COUNTERS
    assert readiness["status"] == "BLOCKED"
    assert readiness["live_monitoring_activation_allowed"] is False


def test_monitoring_readiness_counts_local_events() -> None:
    readiness = pilot_monitoring_readiness_json(
        [
            {"decision": "BLOCKED", "event_type": "policy_fail", "rollback_trigger": True},
            {"decision": "VERIFIED", "audit_hash": "hash"},
            {"event_type": "approval_expired"},
        ]
    )
    assert readiness["blocked_actions"] == 1
    assert readiness["approved_actions"] == 1
    assert readiness["failed_evaluations"] == 1
    assert readiness["audit_writes"] == 1
    assert readiness["approval_expirations"] == 1
    assert readiness["rollback_triggers"] == 1


def test_monitoring_readiness_fails_closed_on_malformed_counter() -> None:
    readiness = pilot_monitoring_readiness_json()
    readiness["blocked_actions"] = -1
    result = evaluate_monitoring_readiness(readiness)
    assert result["decision"] == "FAIL_CLOSED"
    assert "MALFORMED_BLOCKED_ACTIONS" in result["gaps"]


def test_monitoring_readiness_verifies_local_only_contract() -> None:
    result = evaluate_monitoring_readiness(pilot_monitoring_readiness_json())
    assert result["decision"] == "VERIFIED"
    assert result["status"] == "READY_FOR_REVIEW"
