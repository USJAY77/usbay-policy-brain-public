from __future__ import annotations

import re
from dataclasses import dataclass

from runtime.computer_use.action_schema import ComputerUseAction


SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[A-Za-z0-9_./+=-]{8,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9_./+=-]{12,}"),
    re.compile(r"ghp_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
)

HIGH_RISK_TARGET_PATTERNS = (
    re.compile(r"(?i)\bmerge\b"),
    re.compile(r"(?i)\bapprove\b"),
    re.compile(r"(?i)\bdelete\b"),
    re.compile(r"(?i)\bdeploy\b"),
    re.compile(r"(?i)github.*pull.*request"),
)


@dataclass(frozen=True)
class GuardrailResult:
    decision: str
    reason: str
    requires_human_approval: bool = False


def contains_secret_like_value(value: str | None) -> bool:
    if not value:
        return False
    return any(pattern.search(value) for pattern in SECRET_PATTERNS)


def target_requires_human_review(target: str) -> bool:
    return any(pattern.search(target or "") for pattern in HIGH_RISK_TARGET_PATTERNS)


def evaluate_guardrails(action: ComputerUseAction) -> GuardrailResult:
    if contains_secret_like_value(action.text):
        return GuardrailResult("BLOCK", "SECRET_LIKE_TEXT_BLOCKED")
    if action.action_type in {"click", "type", "open_url"} and target_requires_human_review(action.target):
        return GuardrailResult("HUMAN_REVIEW", "HIGH_RISK_TARGET_REQUIRES_HUMAN_APPROVAL", True)
    if action.risk_level in {"HIGH", "CRITICAL"} or action.requires_human_approval:
        return GuardrailResult("HUMAN_REVIEW", "HIGH_RISK_ACTION_REQUIRES_HUMAN_APPROVAL", True)
    return GuardrailResult("ALLOW", "GUARDRAILS_PASS")
