from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any


HIGH_RISK_TERMS = {
    "approve",
    "branch deletion",
    "credential",
    "delete",
    "deploy",
    "deletion",
    "merge",
    "password",
    "production",
    "secret",
    "system settings",
    "token",
    "login",
}
MEDIUM_RISK_ACTIONS = {"click", "type", "open_url"}
LOW_RISK_ACTIONS = {"read_screen", "wait", "scroll"}

_LEGACY_REASON_BY_LEVEL = {
    "LOW": "LOW_RISK",
    "MEDIUM": "MEDIUM_RISK",
    "HIGH": "HIGH_RISK",
    "UNKNOWN": "UNKNOWN",
}


@dataclass(frozen=True)
class RiskClassification:
    risk_level: str
    reason: str
    evidence: dict[str, Any]

    @property
    def legacy_reason(self) -> str:
        return _LEGACY_REASON_BY_LEVEL[self.risk_level]

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return other == self.legacy_reason
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(self.legacy_reason)

    @property
    def evidence_hash(self) -> str:
        return str(self.evidence["evidence_hash"])


def _classification(
    *,
    action_type: str | None,
    target: str | None,
    screen_summary: str | None,
    risk_level: str,
    reason: str,
) -> RiskClassification:
    evidence = {
        "schema": "usbay.computer_use.risk_classification.v1",
        "action_type": action_type or "",
        "target_present": bool(target),
        "screen_summary_present": bool(screen_summary),
        "risk_level": risk_level,
        "reason": reason,
        "fail_closed": risk_level == "UNKNOWN",
    }
    evidence["evidence_hash"] = sha256(repr(sorted(evidence.items())).encode("utf-8")).hexdigest()
    return RiskClassification(risk_level=risk_level, reason=reason, evidence=evidence)


def classify_risk(action_type: str | None, target: str | None, screen_summary: str | None = None) -> RiskClassification:
    if not action_type or not target:
        return _classification(
            action_type=action_type,
            target=target,
            screen_summary=screen_summary,
            risk_level="UNKNOWN",
            reason="RISK_INPUT_MISSING",
        )
    text = f"{action_type} {target} {screen_summary or ''}".lower()
    if any(term in text for term in HIGH_RISK_TERMS):
        return _classification(
            action_type=action_type,
            target=target,
            screen_summary=screen_summary,
            risk_level="HIGH",
            reason="HIGH_RISK_TARGET",
        )
    if action_type in MEDIUM_RISK_ACTIONS:
        return _classification(
            action_type=action_type,
            target=target,
            screen_summary=screen_summary,
            risk_level="MEDIUM",
            reason="MUTATING_OR_NAVIGATING_ACTION",
        )
    if action_type in LOW_RISK_ACTIONS:
        return _classification(
            action_type=action_type,
            target=target,
            screen_summary=screen_summary,
            risk_level="LOW",
            reason="LOW_RISK_ACTION",
        )
    return _classification(
        action_type=action_type,
        target=target,
        screen_summary=screen_summary,
        risk_level="UNKNOWN",
        reason="UNSUPPORTED_ACTION",
    )
