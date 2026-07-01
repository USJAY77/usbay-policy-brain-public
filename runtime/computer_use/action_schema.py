from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Literal


ActionType = Literal["click", "type", "scroll", "wait", "open_url", "read_screen", "stop"]
RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
PolicyDecision = Literal["PENDING", "ALLOW", "BLOCK", "HUMAN_REVIEW", "FAIL_CLOSED"]

ALLOWED_ACTION_TYPES = {"click", "type", "scroll", "wait", "open_url", "read_screen", "stop"}
ALLOWED_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


@dataclass(frozen=True)
class ComputerUseAction:
    action_type: str
    target: str
    required_capability: str
    risk_level: str = "LOW"
    coordinates: dict[str, int] | None = None
    text: str | None = None
    requires_human_approval: bool = False
    policy_decision: str = "PENDING"
    action_id: str = field(default_factory=lambda: f"cua-{uuid.uuid4().hex}")
    audit_hash: str = ""

    def __post_init__(self) -> None:
        if self.action_type not in ALLOWED_ACTION_TYPES:
            raise ValueError("UNKNOWN_ACTION_TYPE")
        if self.risk_level not in ALLOWED_RISK_LEVELS:
            raise ValueError("UNKNOWN_RISK_LEVEL")
        if not self.action_id:
            raise ValueError("ACTION_ID_REQUIRED")
        if not self.target:
            raise ValueError("TARGET_REQUIRED")
        if not self.required_capability:
            raise ValueError("REQUIRED_CAPABILITY_REQUIRED")
        if self.action_type == "click" and self.coordinates is None:
            raise ValueError("CLICK_COORDINATES_REQUIRED")
        if self.action_type == "type" and self.text is None:
            raise ValueError("TYPE_TEXT_REQUIRED")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def with_policy_decision(self, decision: str) -> "ComputerUseAction":
        payload = self.to_dict()
        payload["policy_decision"] = decision
        payload["audit_hash"] = audit_hash_for_action(payload)
        return ComputerUseAction(**payload)


def audit_hash_for_action(action_payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        {key: value for key, value in action_payload.items() if key != "audit_hash"},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def action_from_json(payload: dict[str, Any]) -> ComputerUseAction:
    if not isinstance(payload, dict):
        raise ValueError("ACTION_PAYLOAD_MUST_BE_OBJECT")
    return ComputerUseAction(**payload)
