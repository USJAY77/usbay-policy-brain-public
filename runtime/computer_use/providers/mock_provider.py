from __future__ import annotations

from hashlib import sha256
from typing import Any

from runtime.computer_use.audit_recorder import ComputerUseAuditRecorder
from runtime.computer_use.providers.base import ProviderResult


class MockVisionProvider:
    provider_name = "mock"
    provider_version = "1.0"

    def __init__(
        self,
        scenario: str = "low_risk_read_screen",
        *,
        audit_recorder: ComputerUseAuditRecorder | None = None,
        timeout_seconds: float = 2.0,
    ) -> None:
        self.scenario = scenario
        self.audit_recorder = audit_recorder
        self.timeout_seconds = timeout_seconds

    def health_check(self) -> dict[str, str]:
        return {"provider": self.provider_name, "status": "HEALTHY"}

    def analyze_screen(self, observation: dict[str, Any]) -> ProviderResult:
        scenario = str(observation.get("scenario") or self.scenario)
        if not self._has_required_observation(observation):
            return self._fail("OBSERVATION_REQUIRED_FIELDS_MISSING", observation)
        if scenario == "provider_exception" or scenario == "provider_failure":
            return self._fail("PROVIDER_EXCEPTION", observation)
        if scenario == "provider_timeout":
            return self._fail("PROVIDER_TIMEOUT", observation)
        if scenario == "malformed_response" or scenario == "malformed":
            return self._fail("PROVIDER_RESPONSE_MALFORMED", observation)
        if scenario == "unknown_action":
            return self._result("BLOCK", "unknown", "unknown", "CRITICAL", True, "UNKNOWN_ACTION_BLOCKED", observation)
        if scenario == "high_risk_click":
            if observation.get("observation_id") and not observation.get("screen_metadata"):
                return self._result(
                    "HUMAN_REVIEW",
                    "click",
                    "github merge button",
                    "HIGH",
                    True,
                    "human_review_required",
                    observation,
                )
            return self._result("BLOCK", "click", "github merge button", "HIGH", True, "HUMAN_APPROVAL_REQUIRED", observation)
        if scenario == "high_risk_click_missing_approval_marker":
            return self._fail("HIGH_RISK_ACTION_APPROVAL_MARKER_MISSING", observation)
        if scenario == "secret_like_text":
            return self._result("BLOCK", "type", "password field", "HIGH", True, "SECRET_LIKE_TEXT_BLOCKED", observation)
        if scenario == "missing_policy":
            return self._fail("COMPUTER_USE_POLICY_MISSING", observation)
        return self._result("ALLOW", "read_screen", "screen", "LOW", False, "low_risk_read", observation)

    def _has_required_observation(self, observation: dict[str, Any]) -> bool:
        legacy_observation = bool(observation.get("observation_id"))
        structured_observation = bool(observation.get("action_id") and observation.get("screen_metadata"))
        return legacy_observation or structured_observation

    def _fail(self, reason: str, observation: dict[str, Any]) -> ProviderResult:
        return self._result("FAIL_CLOSED", "unknown", "unknown", "CRITICAL", True, reason, observation)

    def _result(
        self,
        status: str,
        action_type: str,
        target: str,
        risk: str,
        requires_approval: bool,
        reason: str,
        observation: dict[str, Any],
    ) -> ProviderResult:
        audit = self._audit(status=status, action_type=action_type, reason=reason, observation=observation)
        return ProviderResult(
            provider=self.provider_name,
            status=status,
            screen_summary="metadata-only low risk screen observation" if status == "ALLOW" else "redacted summary",
            proposed_action={"type": action_type, "target": target, "risk": risk},
            requires_human_approval=requires_approval,
            reason=reason,
            audit=audit,
        )

    def _audit(self, *, status: str, action_type: str, reason: str, observation: dict[str, Any]) -> dict[str, Any]:
        observation_hash = sha256(
            repr(
                sorted(
                    {
                        "action_id": observation.get("action_id"),
                        "observation_id": observation.get("observation_id"),
                        "scenario": observation.get("scenario") or self.scenario,
                        "screen_metadata": observation.get("screen_metadata"),
                        "screenshot_hash": observation.get("screenshot_hash"),
                    }.items()
                )
            ).encode("utf-8")
        ).hexdigest()
        event = {
            "provider": self.provider_name,
            "provider_version": self.provider_version,
            "status": status,
            "proposed_action_type": action_type,
            "reason": reason,
            "raw_screenshot_stored": False,
            "provider_call_recorded": True,
            "policy_checked": True,
            "observation_hash": observation_hash,
            "timeout_seconds": self.timeout_seconds,
        }
        if self.audit_recorder is not None:
            recorded = self.audit_recorder.record(event)
            audit_hash = str(recorded["audit_hash"])
        else:
            audit_hash = sha256(repr(sorted(event.items())).encode("utf-8")).hexdigest()
        return {
            "raw_screenshot_stored": False,
            "provider_call_recorded": True,
            "policy_checked": True,
            "hash": audit_hash,
            "observation_hash": observation_hash,
        }
