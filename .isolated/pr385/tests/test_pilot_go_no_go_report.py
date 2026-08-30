from pilot_operations.end_to_end_dry_run import build_pilot_go_no_go_report


def test_go_no_go_report_allows_review_but_not_live_activation(tmp_path):
    for evidence_dir in ("pb241_245", "pb246_250", "pb251_255", "pb256_260", "pb261_265", "pb266_270"):
        (tmp_path / evidence_dir).mkdir()

    report = build_pilot_go_no_go_report(tmp_path)

    assert report["decision"] == "VERIFIED"
    assert report["status"] == "READY_FOR_REVIEW"
    assert report["go_no_go_decision"] == "GO_FOR_REVIEW_NO_GO_FOR_LIVE_ACTIVATION"
    assert report["dry_run_ready_for_review"] is True
    assert report["live_pilot_activation_allowed"] is False
    assert report["gaps"] == []


def test_go_no_go_report_fails_closed_when_prior_controls_are_missing(tmp_path):
    report = build_pilot_go_no_go_report(tmp_path)

    assert report["decision"] == "FAIL_CLOSED"
    assert report["status"] == "REVIEW_REQUIRED"
    assert report["go_no_go_decision"] == "NO_GO"
    assert report["live_pilot_activation_allowed"] is False
    assert report["gaps"]
