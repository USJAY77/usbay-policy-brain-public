from pilot_operations.live_pilot_authorization import (
    evaluate_incident_ownership_matrix,
    incident_ownership_matrix_json,
)


def test_incident_matrix_requires_kill_switch_and_blocks_activation():
    contract = incident_ownership_matrix_json()

    assert contract["default_state"] == "BLOCKED"
    assert contract["kill_switch_required"] is True
    assert contract["activation_allowed"] is False
    assert len(contract["matrix"]) == 5


def test_malformed_incident_matrix_fails_closed():
    result = evaluate_incident_ownership_matrix(None)

    assert result["decision"] == "FAIL_CLOSED"
    assert result["gaps"] == ["MALFORMED_INCIDENT_MATRIX"]


def test_missing_incident_owner_fails_closed():
    matrix = incident_ownership_matrix_json()["matrix"][:-1]
    result = evaluate_incident_ownership_matrix(matrix)

    assert result["decision"] == "FAIL_CLOSED"
    assert "MISSING_INCIDENT_OWNER_DEVICE_FAILURE" in result["gaps"]


def test_complete_incident_matrix_is_review_only():
    result = evaluate_incident_ownership_matrix(incident_ownership_matrix_json()["matrix"])

    assert result["decision"] == "READY_FOR_REVIEW"
    assert result["gaps"] == []
    assert result["activation_allowed"] is False
