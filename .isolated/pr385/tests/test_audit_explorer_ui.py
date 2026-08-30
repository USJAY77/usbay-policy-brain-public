from control_plane.ui.audit_explorer_view import AuditExplorerRecord, lookup_audit_record


def _records():
    return [
        AuditExplorerRecord(
            decision_id="decision-1",
            approval_id="approval-1",
            execution_id="execution-1",
            audit_hash="hash-1",
            policy_version="policy-v1",
        )
    ]


def test_audit_explorer_ui_looks_up_by_decision_id() -> None:
    view = lookup_audit_record(_records(), decision_id="decision-1")

    assert view.found is True
    assert view.decision_id == "decision-1"
    assert view.audit_hash_display == "hash-1"
    assert view.policy_version_display == "policy-v1"
    assert view.display_state == "READY_FOR_REVIEW"


def test_audit_explorer_ui_looks_up_by_approval_id() -> None:
    view = lookup_audit_record(_records(), approval_id="approval-1")

    assert view.found is True
    assert view.execution_id == "execution-1"


def test_audit_explorer_ui_looks_up_by_execution_id() -> None:
    view = lookup_audit_record(_records(), execution_id="execution-1")

    assert view.found is True
    assert view.approval_id == "approval-1"


def test_audit_explorer_ui_fail_closed_on_missing_record() -> None:
    view = lookup_audit_record(_records(), decision_id="missing")

    assert view.found is False
    assert view.display_state == "FAIL_CLOSED"


def test_audit_explorer_ui_fail_closed_on_ambiguous_lookup() -> None:
    view = lookup_audit_record(_records(), decision_id="decision-1", approval_id="approval-1")

    assert view.found is False
    assert view.display_state == "FAIL_CLOSED"

