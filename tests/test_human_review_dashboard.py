from datetime import datetime, timedelta, timezone

from control_plane.human_review.review_queue import HumanReviewQueue
from control_plane.human_review.review_record import ReviewRecord
from control_plane.human_review.review_state import ReviewState


def _record(review_id: str = "review-1", expires_delta: int = 300) -> ReviewRecord:
    return ReviewRecord.create(
        review_id=review_id,
        execution_id="execution-1",
        actor="USBAY-AUDIT",
        state=ReviewState.PENDING,
        reason="review_required",
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=expires_delta),
    )


def test_human_review_queue_tracks_pending_review() -> None:
    queue = HumanReviewQueue()
    ok, reason = queue.add(_record())

    assert ok is True
    assert reason == "review_queued"
    assert queue.dashboard()["pending"] == 1


def test_human_review_queue_tracks_approved_review() -> None:
    queue = HumanReviewQueue()
    queue.add(_record())

    ok, reason = queue.transition("review-1", ReviewState.APPROVED, "approved_by_human")

    assert ok is True
    assert reason == "review_approved"
    assert queue.dashboard()["approved"] == 1
    assert queue.get("review-1").audit_hash


def test_human_review_queue_tracks_denied_review() -> None:
    queue = HumanReviewQueue()
    queue.add(_record())

    ok, reason = queue.transition("review-1", ReviewState.DENIED, "denied_by_human")

    assert ok is True
    assert reason == "review_denied"
    assert queue.dashboard()["denied"] == 1


def test_human_review_queue_marks_expired_review() -> None:
    queue = HumanReviewQueue()
    queue.add(_record(expires_delta=-1))

    record = queue.get("review-1")

    assert record.state == ReviewState.EXPIRED
    assert queue.dashboard()["expired"] == 1


def test_human_review_queue_blocks_terminal_transition() -> None:
    queue = HumanReviewQueue()
    queue.add(_record())
    queue.transition("review-1", ReviewState.DENIED, "denied_by_human")

    ok, reason = queue.transition("review-1", ReviewState.APPROVED, "late_approval")

    assert ok is False
    assert reason == "review_terminal"

