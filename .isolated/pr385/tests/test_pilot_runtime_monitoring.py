from pilot_operations.controlled_pilot_operations import (
    DEFAULT_POLICY_HASH,
    classify_monitoring_event,
    pilot_runtime_monitoring_contract_json,
)


def test_runtime_monitoring_contract_blocks_failures():
    contract = pilot_runtime_monitoring_contract_json()

    assert contract["default_state"] == "BLOCKED"
    assert contract["runtime_mode"] == "DRY_RUN"
    assert contract["failure_outcome"] == "BLOCKED"
    assert contract["kill_switch_required_on_failure"] is True
    assert set(contract["monitored_failure_types"]) == {
        "approval_failure",
        "nonce_failure",
        "replay_failure",
        "audit_failure",
        "device_failure",
    }


def test_unknown_monitoring_event_blocks():
    result = classify_monitoring_event({"failure_type": "network_failure"})

    assert result["decision"] == "BLOCKED"
    assert result["gaps"] == ["UNKNOWN_FAILURE_TYPE"]


def test_known_failure_still_blocks_and_records_hash_only_evidence():
    result = classify_monitoring_event(
        {
            "failure_type": "nonce_failure",
            "policy_hash": DEFAULT_POLICY_HASH,
            "event_hash": "event-hash-only",
        }
    )

    assert result["decision"] == "BLOCKED"
    assert result["failure_type"] == "nonce_failure"
    assert result["gaps"] == []
    assert isinstance(result["monitoring_evidence_hash"], str)
