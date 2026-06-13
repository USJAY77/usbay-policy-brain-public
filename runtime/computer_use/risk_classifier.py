from __future__ import annotations


HIGH_RISK_TERMS = {
    "approve",
    "branch deletion",
    "credential",
    "delete",
    "deploy",
    "merge",
    "password",
    "production",
    "secret",
    "token",
}
MEDIUM_RISK_ACTIONS = {"click", "type", "open_url"}
LOW_RISK_ACTIONS = {"read_screen", "wait", "scroll"}


def classify_risk(action_type: str | None, target: str | None, screen_summary: str | None = None) -> str:
    if not action_type or not target:
        return "UNKNOWN"
    text = f"{action_type} {target} {screen_summary or ''}".lower()
    if any(term in text for term in HIGH_RISK_TERMS):
        return "HIGH_RISK"
    if action_type in MEDIUM_RISK_ACTIONS:
        return "MEDIUM_RISK"
    if action_type in LOW_RISK_ACTIONS:
        return "LOW_RISK"
    return "UNKNOWN"

