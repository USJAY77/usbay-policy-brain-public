from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from control_plane.human_review.review_record import ReviewRecord, review_hash
from control_plane.human_review.review_state import ReviewState, TERMINAL_REVIEW_STATES


class HumanReviewQueue:
    def __init__(self) -> None:
        self._records: dict[str, ReviewRecord] = {}

    def add(self, record: ReviewRecord) -> tuple[bool, str]:
        if not record.review_id:
            return False, "review_id_missing"
        if record.review_id in self._records:
            return False, "review_duplicate"
        self._records[record.review_id] = record
        return True, "review_queued"

    def transition(self, review_id: str, state: ReviewState, reason: str) -> tuple[bool, str]:
        record = self._records.get(review_id)
        if record is None:
            return False, "review_missing"
        if record.state in TERMINAL_REVIEW_STATES:
            return False, "review_terminal"
        if self._is_expired(record):
            self._records[review_id] = self._replace_state(record, ReviewState.EXPIRED, "review_expired")
            return False, "review_expired"
        if state not in {ReviewState.APPROVED, ReviewState.DENIED}:
            return False, "invalid_review_transition"
        self._records[review_id] = self._replace_state(record, state, reason)
        return True, f"review_{state.value.lower()}"

    def get(self, review_id: str) -> ReviewRecord | None:
        record = self._records.get(review_id)
        if record and self._is_expired(record) and record.state == ReviewState.PENDING:
            expired = self._replace_state(record, ReviewState.EXPIRED, "review_expired")
            self._records[review_id] = expired
            return expired
        return record

    def dashboard(self) -> dict[str, int]:
        states = {state.value.lower(): 0 for state in ReviewState}
        for review_id in list(self._records):
            record = self.get(review_id)
            if record:
                states[record.state.value.lower()] += 1
        return states

    def _is_expired(self, record: ReviewRecord) -> bool:
        return datetime.now(timezone.utc) >= record.expires_at

    def _replace_state(self, record: ReviewRecord, state: ReviewState, reason: str) -> ReviewRecord:
        return replace(
            record,
            state=state,
            reason=reason,
            audit_hash=review_hash(record.review_id, record.execution_id, record.actor, state.value, reason),
        )

