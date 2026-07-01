from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

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

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ComputerUseExecutionDecision:
    decision_id: str
    decision: str
    reason: str
    risk_level: str
    policy_version: str | None
    audit_hash: str
    timestamp: str | None = None
    execution: dict | None = None
    audit_event: dict | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ComputerUseDecisionEngine:
    """Local-only computer-use decision contract.

    The engine evaluates already-provided metadata and provider summaries. It
    does not invoke a provider or perform desktop/browser actions.
    """

    _required_fields = (
        "action_type",
        "target",
        "screen_summary",
        "provider_response",
        "approval_state",
        "policy_version",
    )
    _supported_actions = {"click", "type", "scroll", "wait", "open_url", "read_screen", "stop"}

    def decide(self, contract: dict[str, Any]) -> ComputerUseExecutionDecision:
        for field in self._required_fields:
            if field not in contract:
                return self._decision("FAIL_CLOSED", f"ACTION_CONTRACT_REQUIRED_INPUT_MISSING:{field}", "UNKNOWN", contract.get("policy_version"))

        action_type = contract.get("action_type")
        target = contract.get("target")
        policy_version = contract.get("policy_version")
        provider_response = contract.get("provider_response")
        approval_state = contract.get("approval_state")

        if not action_type or not target:
            return self._decision("FAIL_CLOSED", "UNKNOWN", "UNKNOWN", policy_version)
        if not policy_version:
            return self._decision("FAIL_CLOSED", "MISSING_POLICY", "UNKNOWN", policy_version)
        if action_type not in self._supported_actions:
            return self._decision("BLOCK", "UNSUPPORTED_ACTION", "UNKNOWN", policy_version)
        if approval_state == "DENIED":
            return self._decision("BLOCK", "APPROVAL_STATE_BLOCKED", "UNKNOWN", policy_version)
        if not isinstance(provider_response, dict):
            return self._decision("FAIL_CLOSED", "PROVIDER_RESPONSE_MALFORMED", "UNKNOWN", policy_version)

        provider_status = provider_response.get("status")
        if provider_status == "FAIL_CLOSED":
            return self._decision("FAIL_CLOSED", "PROVIDER_FAIL_CLOSED", "UNKNOWN", policy_version)
        if provider_status == "BLOCK":
            return self._decision("BLOCK", "PROVIDER_BLOCKED_ACTION", "UNKNOWN", policy_version)
        if provider_status != "ALLOW":
            return self._decision("FAIL_CLOSED", "PROVIDER_RESPONSE_MALFORMED", "UNKNOWN", policy_version)

        risk = classify_risk(action_type, target, contract.get("screen_summary"))
        if risk == "LOW_RISK":
            return self._decision("ALLOW", risk, "LOW", policy_version)
        if risk == "MEDIUM_RISK":
            return self._decision("HUMAN_REVIEW", risk, "MEDIUM", policy_version)
        if risk == "HIGH_RISK":
            return self._decision("HUMAN_REVIEW", risk, "HIGH", policy_version)
        return self._decision("FAIL_CLOSED", "UNKNOWN", "UNKNOWN", policy_version)

    def _decision(
        self,
        decision: str,
        reason: str,
        risk_level: str,
        policy_version: str | None,
    ) -> ComputerUseExecutionDecision:
        timestamp = _now_iso()
        decision_id = "cud-" + _hash(decision, reason, risk_level, policy_version, timestamp)[:24]
        audit_hash = _hash(decision_id, decision, reason, risk_level, policy_version, timestamp)
        return ComputerUseExecutionDecision(
            decision_id=decision_id,
            decision=decision,
            reason=reason,
            risk_level=risk_level,
            policy_version=policy_version,
            audit_hash=audit_hash,
            timestamp=timestamp,
        )


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
