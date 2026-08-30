from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


def view_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class HumanReviewUIView:
    pending_approvals: int
    approved_decisions: int
    denied_decisions: int
    expired_approvals: int
    display_state: str
    fail_closed: bool
    audit_hash: str


def build_human_review_view(dashboard: dict[str, int] | None) -> HumanReviewUIView:
    if dashboard is None:
        return _view(0, 0, 0, 0, "FAIL_CLOSED", True)
    required = ("pending", "approved", "denied", "expired")
    if any(key not in dashboard for key in required):
        return _view(
            dashboard.get("pending", 0),
            dashboard.get("approved", 0),
            dashboard.get("denied", 0),
            dashboard.get("expired", 0),
            "FAIL_CLOSED",
            True,
        )
    display_state = "FAIL_CLOSED" if dashboard["expired"] else "READY_FOR_REVIEW"
    return _view(
        dashboard["pending"],
        dashboard["approved"],
        dashboard["denied"],
        dashboard["expired"],
        display_state,
        display_state == "FAIL_CLOSED",
    )


def _view(pending: int, approved: int, denied: int, expired: int, display_state: str, fail_closed: bool) -> HumanReviewUIView:
    return HumanReviewUIView(
        pending_approvals=pending,
        approved_decisions=approved,
        denied_decisions=denied,
        expired_approvals=expired,
        display_state=display_state,
        fail_closed=fail_closed,
        audit_hash=view_hash("human_review", pending, approved, denied, expired, display_state, fail_closed),
    )

