from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from runtime.computer_use.policy_enforcement import PolicyEnforcer
from runtime.computer_use.risk_classifier import classify_risk


@dataclass(frozen=True)
class RuntimeDecision:
    decision_id: str
    decision: str
    reason: str
    risk_level: str
    policy_version: str | None
    audit_hash: str


def _hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


class DecisionEngine:
    def __init__(self, policy_enforcer: PolicyEnforcer) -> None:
        self.policy_enforcer = policy_enforcer

    def decide(
        self,
        *,
        action_type: str | None,
        target: str | None,
        screen_summary: str | None,
        provider_response: dict | None,
        approval_state: str | None,
        policy_version: str | None,
    ) -> RuntimeDecision:
        if not action_type or not target or provider_response is None:
            return self._decision("FAIL_CLOSED", "missing_decision_input", "UNKNOWN", policy_version)
        policy = self.policy_enforcer.check(action_type, policy_version)
        if policy.decision == "FAIL_CLOSED":
            return self._decision("FAIL_CLOSED", policy.reason, "UNKNOWN", policy.policy_version)
        if policy.decision == "BLOCK":
            return self._decision("BLOCK", policy.reason, "UNKNOWN", policy.policy_version)
        risk = classify_risk(action_type, target, screen_summary)
        if risk == "LOW_RISK":
            return self._decision("ALLOW", "low_risk_allowed", risk, policy.policy_version)
        if risk in {"MEDIUM_RISK", "HIGH_RISK"}:
            return self._decision("HUMAN_REVIEW", "human_review_required", risk, policy.policy_version)
        return self._decision("FAIL_CLOSED", "unknown_risk", risk, policy.policy_version)

    def _decision(self, decision: str, reason: str, risk: str, policy_version: str | None) -> RuntimeDecision:
        decision_id = _hash(decision, reason, risk, policy_version)[:24]
        audit_hash = _hash(decision_id, decision, reason, risk, policy_version)
        return RuntimeDecision(decision_id, decision, reason, risk, policy_version, audit_hash)

