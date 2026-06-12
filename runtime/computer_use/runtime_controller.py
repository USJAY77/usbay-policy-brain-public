from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from hashlib import sha256
from pathlib import Path
from typing import Any

from runtime.computer_use.action_schema import ComputerUseAction, action_from_json
from runtime.computer_use.approval import ComputerUseApprovalQueue
from runtime.computer_use.audit_recorder import ComputerUseAuditRecorder
from runtime.computer_use.decision_engine import ComputerUseExecutionDecision, RuntimeDecision
from runtime.computer_use.execution_boundary import BoundaryDecision, ExecutionBoundary, ExecutionState, new_action_id


_MUTATING_ACTIONS = {"click", "type", "scroll", "open_url"}
_SECRET_MARKERS = ("password", "token", "secret", "private key", "api_key", "apikey")
_HIGH_RISK_TARGET_MARKERS = ("github merge", "approve", "approval", "delete", "deploy")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _hash_payload(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ComputerUsePolicyResult:
    decision: str
    reason: str
    policy_version: str | None


class ComputerUsePolicyEvaluator:
    """Local policy contract evaluator for computer-use fixtures.

    This evaluator performs no external calls and fails closed if the policy
    file is unavailable or malformed.
    """

    def __init__(self, policy_path: Path | str) -> None:
        self.policy_path = Path(policy_path)

    def evaluate(self, action: ComputerUseAction) -> ComputerUsePolicyResult:
        try:
            policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return ComputerUsePolicyResult("FAIL_CLOSED", f"COMPUTER_USE_POLICY_MISSING:{self.policy_path}", None)
        except (OSError, json.JSONDecodeError):
            return ComputerUsePolicyResult("FAIL_CLOSED", "COMPUTER_USE_POLICY_MALFORMED", None)

        policy_version = policy.get("policy_version")
        allowed_actions = set(policy.get("allowed_action_types") or [])
        allowed_capabilities = set(policy.get("allowed_capabilities") or [])
        if action.action_type not in allowed_actions:
            return ComputerUsePolicyResult("BLOCK", "ACTION_TYPE_NOT_ALLOWED", policy_version)
        if action.required_capability not in allowed_capabilities:
            return ComputerUsePolicyResult("BLOCK", "CAPABILITY_NOT_ALLOWED", policy_version)
        return ComputerUsePolicyResult("ALLOW", "POLICY_ALLOW", policy_version)


class ComputerUseRuntimeController:
    """Compatibility controller for governed, dry-run computer-use decisions."""

    def __init__(
        self,
        *,
        policy_evaluator: ComputerUsePolicyEvaluator,
        audit_recorder: ComputerUseAuditRecorder,
        approval_queue: ComputerUseApprovalQueue,
    ) -> None:
        self.policy_evaluator = policy_evaluator
        self.audit_recorder = audit_recorder
        self.approval_queue = approval_queue

    def decide_payload(self, payload: dict[str, Any], approval_token: str | None = None) -> ComputerUseExecutionDecision:
        try:
            action = action_from_json(payload)
        except ValueError as exc:
            return self._finalize(
                action_payload=payload if isinstance(payload, dict) else {},
                decision="BLOCK",
                reason=str(exc),
                risk_level=str(payload.get("risk_level", "UNKNOWN")) if isinstance(payload, dict) else "UNKNOWN",
                policy_version=None,
                approval_token=approval_token,
                raw_text_redacted=False,
            )
        return self.decide_and_execute(action, approval_token=approval_token)

    def decide_and_execute(
        self,
        action: ComputerUseAction,
        approval_token: str | None = None,
    ) -> ComputerUseExecutionDecision:
        policy_result = self.policy_evaluator.evaluate(action)
        if policy_result.decision in {"FAIL_CLOSED", "BLOCK"}:
            return self._finalize(
                action_payload=action.to_dict(),
                decision=policy_result.decision,
                reason=policy_result.reason,
                risk_level=action.risk_level,
                policy_version=policy_result.policy_version,
                approval_token=approval_token,
                raw_text_redacted=False,
            )

        if action.action_type == "type" and self._contains_secret_marker(action.text):
            return self._finalize(
                action_payload=action.to_dict(),
                decision="BLOCK",
                reason="SECRET_LIKE_TEXT_BLOCKED",
                risk_level=action.risk_level,
                policy_version=policy_result.policy_version,
                approval_token=approval_token,
                raw_text_redacted=True,
            )

        denied = self.approval_queue.denied_action(action)
        if denied is not None:
            return self._finalize(
                action_payload=action.to_dict(),
                decision=denied.decision,
                reason=denied.reason,
                risk_level=action.risk_level,
                policy_version=policy_result.policy_version,
                approval_token=approval_token,
                approval_reference=denied.approval_reference,
                approval_audit_hash=denied.approval_audit_hash,
                raw_text_redacted=False,
            )

        if approval_token:
            validation = self.approval_queue.validate_token(approval_token, action)
            return self._finalize(
                action_payload=action.to_dict(),
                decision=validation.decision,
                reason=validation.reason,
                risk_level=action.risk_level,
                policy_version=policy_result.policy_version,
                approval_token=approval_token,
                approval_reference=validation.approval_reference,
                approval_audit_hash=validation.approval_audit_hash,
                raw_text_redacted=False,
            )

        if self._requires_human_review(action):
            return self._finalize(
                action_payload=action.to_dict(),
                decision="HUMAN_REVIEW",
                reason="HIGH_RISK_TARGET_REQUIRES_HUMAN_APPROVAL",
                risk_level=action.risk_level,
                policy_version=policy_result.policy_version,
                approval_token=approval_token,
                raw_text_redacted=False,
            )

        if action.action_type in _MUTATING_ACTIONS:
            return self._finalize(
                action_payload=action.to_dict(),
                decision="BLOCK",
                reason="MUTATING_ACTION_REQUIRES_POLICY_APPROVAL",
                risk_level=action.risk_level,
                policy_version=policy_result.policy_version,
                approval_token=approval_token,
                raw_text_redacted=False,
            )

        return self._finalize(
            action_payload=action.to_dict(),
            decision="ALLOW",
            reason="LOW_RISK",
            risk_level=action.risk_level,
            policy_version=policy_result.policy_version,
            approval_token=approval_token,
            raw_text_redacted=False,
        )

    def _finalize(
        self,
        *,
        action_payload: dict[str, Any],
        decision: str,
        reason: str,
        risk_level: str,
        policy_version: str | None,
        approval_token: str | None,
        raw_text_redacted: bool,
        approval_reference: str | None = None,
        approval_audit_hash: str | None = None,
    ) -> ComputerUseExecutionDecision:
        decision_id = "cud-" + _hash_payload(
            {
                "action_id": action_payload.get("action_id"),
                "decision": decision,
                "reason": reason,
                "risk_level": risk_level,
                "policy_version": policy_version,
            }
        )[:24]
        execution = {
            "executed": False,
            "dry_run": decision == "ALLOW",
            "blocked": decision != "ALLOW",
        }
        audit_event = self.audit_recorder.record(
            {
                "event_type": "computer_use_decision",
                "decision_id": decision_id,
                "action_id": action_payload.get("action_id"),
                "action_type": action_payload.get("action_type"),
                "action_hash": _hash_payload(action_payload),
                "decision": decision,
                "reason": reason,
                "risk_level": risk_level,
                "policy_version": policy_version,
                "approval_reference": approval_reference,
                "approval_audit_hash": approval_audit_hash,
                "approval_token_present": bool(approval_token),
                "raw_screenshot_stored": False,
                "raw_text_redacted": raw_text_redacted,
                "executed": False,
                "dry_run": decision == "ALLOW",
            }
        )
        return ComputerUseExecutionDecision(
            decision_id=decision_id,
            decision=decision,
            reason=reason,
            risk_level=risk_level,
            policy_version=policy_version,
            audit_hash=audit_event["audit_hash"],
            timestamp=audit_event["timestamp"],
            execution=execution,
            audit_event=audit_event,
        )

    def _requires_human_review(self, action: ComputerUseAction) -> bool:
        target = action.target.lower()
        return action.requires_human_approval or action.risk_level in {"HIGH", "CRITICAL"} or any(
            marker in target for marker in _HIGH_RISK_TARGET_MARKERS
        )

    def _contains_secret_marker(self, text: str | None) -> bool:
        candidate = (text or "").lower()
        return any(marker in candidate for marker in _SECRET_MARKERS)


@dataclass(frozen=True)
class RuntimeRequest:
    action_type: str
    target: str
    required_capability: str
    policy_version: str
    action_id: str | None = None


class RuntimeController:
    """Coordinates runtime state without performing desktop/browser actions."""

    def __init__(self, boundary: ExecutionBoundary | None = None) -> None:
        self.boundary = boundary or ExecutionBoundary()
        self._states: dict[str, ExecutionState] = {}

    def create_state(self, request: RuntimeRequest) -> ExecutionState:
        action_id = request.action_id or new_action_id()
        state = ExecutionState(
            action_id=action_id,
            action_type=request.action_type,
            target=request.target,
            policy_version=request.policy_version,
            required_capability=request.required_capability,
        )
        self._states[action_id] = state
        return state

    def get_state(self, action_id: str) -> ExecutionState | None:
        return self._states.get(action_id)

    def authorize(
        self,
        action_id: str,
        *,
        policy_decision: str | None,
        approval_valid: bool = False,
        policy_version: str | None = None,
    ) -> BoundaryDecision:
        state = self._states.get(action_id)
        if state is None:
            missing = ExecutionState(
                action_id=action_id,
                action_type="unknown",
                target="unknown",
                policy_version=policy_version or "missing",
                required_capability="unknown",
            )
            return self.boundary.evaluate(
                missing,
                policy_decision=None,
                approval_valid=False,
                policy_version=policy_version,
            )
        return self.boundary.evaluate(
            state,
            policy_decision=policy_decision,
            approval_valid=approval_valid,
            policy_version=policy_version,
        )

    def snapshot(self) -> dict[str, Any]:
        return {
            action_id: {
                "action_type": state.action_type,
                "target": state.target,
                "policy_version": state.policy_version,
                "required_capability": state.required_capability,
                "state": state.state,
                "audit_event_count": len(state.audit_events),
            }
            for action_id, state in sorted(self._states.items())
        }
