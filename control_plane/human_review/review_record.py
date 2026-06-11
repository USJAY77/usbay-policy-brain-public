from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256

from control_plane.human_review.review_state import ReviewState


def _now() -> datetime:
    return datetime.now(timezone.utc)


def review_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ReviewRecord:
    review_id: str
    execution_id: str
    actor: str
    state: ReviewState
    reason: str
    created_at: datetime
    expires_at: datetime
    audit_hash: str

    @classmethod
    def create(
        cls,
        *,
        review_id: str,
        execution_id: str,
        actor: str,
        state: ReviewState,
        reason: str,
        expires_at: datetime,
    ) -> "ReviewRecord":
        created_at = _now()
        return cls(
            review_id=review_id,
            execution_id=execution_id,
            actor=actor,
            state=state,
            reason=reason,
            created_at=created_at,
            expires_at=expires_at,
            audit_hash=review_hash(review_id, execution_id, actor, state.value, reason, expires_at.isoformat()),
        )

