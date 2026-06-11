from control_plane.execution_monitor import build_execution_monitor_record
from control_plane.ui.execution_queue_view import ExecutionQueueItem, build_execution_queue_view


def test_execution_queue_ui_displays_execution_buckets_and_evidence_links() -> None:
    view = build_execution_queue_view(
        [
            ExecutionQueueItem("exec-queued", "QUEUED", "governance/evidence/exec-queued.json", "hash-1"),
            ExecutionQueueItem("exec-blocked", "BLOCKED", "governance/evidence/exec-blocked.json", "hash-2"),
            ExecutionQueueItem("exec-completed", "COMPLETED", "governance/evidence/exec-completed.json", "hash-3"),
            ExecutionQueueItem("exec-revoked", "REVOKED", "governance/evidence/exec-revoked.json", "hash-4"),
        ]
    )

    assert view.queued_executions == ("exec-queued",)
    assert view.blocked_executions == ("exec-blocked",)
    assert view.completed_executions == ("exec-completed",)
    assert view.revoked_executions == ("exec-revoked",)
    assert view.evidence_links["exec-completed"] == "governance/evidence/exec-completed.json"
    assert view.display_state == "READY_FOR_REVIEW"


def test_execution_queue_ui_fail_closed_when_evidence_link_missing() -> None:
    view = build_execution_queue_view([ExecutionQueueItem("exec-1", "QUEUED", "", "hash-1")])

    assert view.display_state == "FAIL_CLOSED"


def test_execution_queue_ui_accepts_execution_monitor_records() -> None:
    record = build_execution_monitor_record(
        execution_id="exec-monitor",
        execution_status="FAIL_CLOSED",
        authority_status="VERIFIED",
        approval_status="DENIED",
        revocation_status="CLEAR",
    )
    view = build_execution_queue_view([record])

    assert view.blocked_executions == ("exec-monitor",)
    assert view.evidence_links["exec-monitor"] == "governance/evidence/executions/exec-monitor.json"

