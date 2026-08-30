from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


APPROVAL_QUEUE_VERSION = "pb214-human-approval-queue-v1"
READ_ACTIONS = {"read", "list", "get", "inspect", "evaluate"}
SENSITIVE_MARKERS = ("secret", "token", "password", "private_key", "authorization", "api_key", "payload")


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class ApprovalRecord:
    action_id: str
    actor: str
    target: str
    risk_level: str
    policy_hash: str
    expires_at: str
    status: ApprovalStatus = ApprovalStatus.PENDING

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _contains_sensitive_marker(value: str) -> bool:
    normalized = value.lower()
    return any(marker in normalized for marker in SENSITIVE_MARKERS)


def validate_approval_record(record: ApprovalRecord) -> list[str]:
    gaps: list[str] = []
    for field, value in record.to_dict().items():
        if not isinstance(value, str) or not value:
            gaps.append(f"MISSING_{field.upper()}")
    if _contains_sensitive_marker(record.action_id) or _contains_sensitive_marker(record.target):
        gaps.append("SENSITIVE_DATA_NOT_ALLOWED")
    try:
        expires_at = parse_utc(record.expires_at)
        if expires_at <= utc_now():
            gaps.append("APPROVAL_EXPIRED")
    except Exception:
        gaps.append("MALFORMED_EXPIRES_AT")
    return sorted(set(gaps))


class HumanApprovalQueue:
    def __init__(self) -> None:
        self._records: dict[str, ApprovalRecord] = {}

    def require_approval(
        self,
        *,
        action_id: str,
        action_type: str,
        actor: str,
        target: str,
        risk_level: str,
        policy_hash: str,
        expires_at: str,
    ) -> dict[str, Any]:
        if action_type.lower() in READ_ACTIONS:
            return {
                "decision": "PASS",
                "requires_human_approval": False,
                "approval": None,
                "queue_version": APPROVAL_QUEUE_VERSION,
            }

        record = ApprovalRecord(
            action_id=action_id,
            actor=actor,
            target=target,
            risk_level=risk_level,
            policy_hash=policy_hash,
            expires_at=expires_at,
        )
        gaps = validate_approval_record(record)
        if gaps:
            blocked = ApprovalRecord(
                action_id=action_id or "BLOCKED",
                actor=actor or "UNKNOWN",
                target=target or "UNKNOWN",
                risk_level=risk_level or "UNKNOWN",
                policy_hash=policy_hash or "UNKNOWN_POLICY_HASH",
                expires_at=expires_at or "1970-01-01T00:00:00Z",
                status=ApprovalStatus.BLOCKED,
            )
            return {
                "decision": "FAIL_CLOSED",
                "requires_human_approval": True,
                "gaps": gaps,
                "approval": blocked.to_dict(),
                "queue_version": APPROVAL_QUEUE_VERSION,
            }
        self._records[action_id] = record
        return {
            "decision": "PENDING_HUMAN_APPROVAL",
            "requires_human_approval": True,
            "gaps": [],
            "approval": record.to_dict(),
            "queue_version": APPROVAL_QUEUE_VERSION,
        }

    def approve(self, action_id: str, *, human_actor: str) -> dict[str, Any]:
        return self._finalize(action_id, ApprovalStatus.APPROVED, human_actor=human_actor)

    def deny(self, action_id: str, *, human_actor: str) -> dict[str, Any]:
        return self._finalize(action_id, ApprovalStatus.DENIED, human_actor=human_actor)

    def _finalize(self, action_id: str, status: ApprovalStatus, *, human_actor: str) -> dict[str, Any]:
        record = self._records.get(action_id)
        if record is None:
            return {"decision": "FAIL_CLOSED", "gaps": ["APPROVAL_NOT_FOUND"], "approval": None}
        if not human_actor:
            return {"decision": "FAIL_CLOSED", "gaps": ["MISSING_HUMAN_ACTOR"], "approval": record.to_dict()}
        if parse_utc(record.expires_at) <= utc_now():
            expired = ApprovalRecord(**{**record.to_dict(), "status": ApprovalStatus.EXPIRED})
            self._records[action_id] = expired
            return {"decision": "FAIL_CLOSED", "gaps": ["APPROVAL_EXPIRED"], "approval": expired.to_dict()}
        finalized = ApprovalRecord(**{**record.to_dict(), "status": status})
        self._records[action_id] = finalized
        return {"decision": status.value, "gaps": [], "approval": finalized.to_dict()}

    def evaluate_action(self, action_id: str) -> dict[str, Any]:
        record = self._records.get(action_id)
        if record is None:
            return {"decision": "FAIL_CLOSED", "gaps": ["APPROVAL_NOT_FOUND"], "approval": None}
        if parse_utc(record.expires_at) <= utc_now():
            expired = ApprovalRecord(**{**record.to_dict(), "status": ApprovalStatus.EXPIRED})
            self._records[action_id] = expired
            return {"decision": "FAIL_CLOSED", "gaps": ["APPROVAL_EXPIRED"], "approval": expired.to_dict()}
        if record.status != ApprovalStatus.APPROVED:
            return {"decision": "FAIL_CLOSED", "gaps": ["HUMAN_APPROVAL_REQUIRED"], "approval": record.to_dict()}
        return {"decision": "APPROVED", "gaps": [], "approval": record.to_dict()}


def approval_queue_contract_json() -> dict[str, Any]:
    return {
        "contract_version": APPROVAL_QUEUE_VERSION,
        "non_read_actions_require_explicit_human_approval": True,
        "expired_approvals_fail_closed": True,
        "sensitive_data_allowed": False,
        "required_fields": [
            "action_id",
            "actor",
            "target",
            "risk_level",
            "policy_hash",
            "expires_at",
            "status",
        ],
        "statuses": [status.value for status in ApprovalStatus],
    }
