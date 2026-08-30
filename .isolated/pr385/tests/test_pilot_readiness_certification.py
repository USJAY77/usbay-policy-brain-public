from pilot_operations.controlled_pilot_operations import (
    REQUIRED_PRIOR_EVIDENCE,
    certify_pilot_readiness,
    pilot_readiness_checklist_json,
)


def test_readiness_checklist_verifies_pb241_through_pb270():
    checklist = pilot_readiness_checklist_json()

    assert checklist["default_state"] == "BLOCKED"
    assert checklist["required_prior_evidence"] == list(REQUIRED_PRIOR_EVIDENCE)
    assert checklist["activation_execution_allowed"] is False
    assert "no_external_api_calls" in checklist["readiness_conditions"]


def test_readiness_fails_closed_when_prior_evidence_missing(tmp_path):
    result = certify_pilot_readiness(tmp_path)

    assert result["decision"] == "FAIL_CLOSED"
    assert result["status"] == "REVIEW_REQUIRED"
    assert len(result["gaps"]) == len(REQUIRED_PRIOR_EVIDENCE)


def test_readiness_verifies_when_required_prior_evidence_exists(tmp_path):
    for evidence_dir in REQUIRED_PRIOR_EVIDENCE:
        (tmp_path / evidence_dir).mkdir()

    result = certify_pilot_readiness(tmp_path)

    assert result["decision"] == "VERIFIED"
    assert result["status"] == "READY_FOR_REVIEW"
    assert result["gaps"] == []
    assert result["activation_execution_allowed"] is False
