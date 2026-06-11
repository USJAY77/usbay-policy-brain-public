from __future__ import annotations

from enum import Enum


class ReviewState(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


TERMINAL_REVIEW_STATES = {ReviewState.APPROVED, ReviewState.DENIED, ReviewState.EXPIRED}

