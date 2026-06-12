from control_plane.ui.human_review_view import build_human_review_view


def test_human_review_ui_displays_review_counts() -> None:
    view = build_human_review_view({"pending": 2, "approved": 1, "denied": 1, "expired": 0})

    assert view.pending_approvals == 2
    assert view.approved_decisions == 1
    assert view.denied_decisions == 1
    assert view.expired_approvals == 0
    assert view.display_state == "READY_FOR_REVIEW"
    assert view.audit_hash


def test_human_review_ui_fail_closed_on_expired_approval() -> None:
    view = build_human_review_view({"pending": 0, "approved": 0, "denied": 0, "expired": 1})

    assert view.display_state == "FAIL_CLOSED"
    assert view.fail_closed is True


def test_human_review_ui_fail_closed_on_missing_state() -> None:
    view = build_human_review_view({"pending": 1, "approved": 0})

    assert view.display_state == "FAIL_CLOSED"
    assert view.fail_closed is True

