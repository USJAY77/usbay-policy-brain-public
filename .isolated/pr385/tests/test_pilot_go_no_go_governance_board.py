from pilot_operations.live_pilot_authorization import pilot_go_no_go_governance_board_json


def test_governance_board_remains_no_go_pending_human_board_approval(tmp_path):
    for evidence_dir in ("pb241_245", "pb246_250", "pb251_255", "pb256_260", "pb261_265", "pb266_270"):
        (tmp_path / evidence_dir).mkdir()

    board = pilot_go_no_go_governance_board_json(tmp_path)

    assert board["decision"] == "READY_FOR_REVIEW"
    assert board["status"] == "READY_FOR_REVIEW"
    assert board["go_no_go_decision"] == "NO_GO_PENDING_BOARD_APPROVAL"
    assert board["live_pilot_activation_allowed"] is False
    assert board["production_activation_allowed"] is False
    assert board["external_api_calls_allowed"] is False
    assert set(board["board"]["required_roles"]) == {
        "governance_owner",
        "security_owner",
        "pilot_operator",
        "incident_owner",
    }


def test_governance_board_fails_closed_when_prior_evidence_missing(tmp_path):
    board = pilot_go_no_go_governance_board_json(tmp_path)

    assert board["decision"] == "FAIL_CLOSED"
    assert board["status"] == "REVIEW_REQUIRED"
    assert board["go_no_go_decision"] == "NO_GO_PENDING_BOARD_APPROVAL"
    assert board["gaps"]
