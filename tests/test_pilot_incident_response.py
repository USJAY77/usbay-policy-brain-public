from pilot_operations.controlled_pilot_operations import (
    DEFAULT_POLICY_HASH,
    evaluate_incident_response,
    pilot_incident_response_playbook_json,
)


def _incident(**overrides):
    payload = {
        "incident_id": "incident-001",
        "failure_type": "audit_failure",
        "policy_hash": DEFAULT_POLICY_HASH,
        "operator_id": "pilot-operator-usbay-governance-001",
        "device_id": "pilot-device-mac-local-001",
        "audit_hash": "audit-hash-only",
        "kill_switch_state": "ENABLED_BLOCKING",
        "timestamp": "2026-06-12T00:00:00Z",
    }
    payload.update(overrides)
    return payload


def test_incident_response_playbook_requires_kill_switch_and_evidence():
    playbook = pilot_incident_response_playbook_json()

    assert playbook["default_state"] == "BLOCKED"
    assert "block_pilot_operations" in playbook["kill_switch_activation_flow"]
    assert "append_recovery_evidence" in playbook["recovery_flow"]
    assert "audit_hash" in playbook["evidence_requirements"]
    assert playbook["production_activation_allowed"] is False


def test_malformed_incident_blocks():
    result = evaluate_incident_response(None)

    assert result["decision"] == "BLOCKED"
    assert result["gaps"] == ["MALFORMED_INCIDENT"]


def test_incident_without_blocking_kill_switch_blocks():
    result = evaluate_incident_response(_incident(kill_switch_state="DISABLED"))

    assert result["decision"] == "BLOCKED"
    assert "KILL_SWITCH_NOT_BLOCKING" in result["gaps"]


def test_complete_incident_is_ready_for_review_not_activation():
    result = evaluate_incident_response(_incident())

    assert result["decision"] == "READY_FOR_REVIEW"
    assert result["gaps"] == []
    assert isinstance(result["incident_evidence_hash"], str)
