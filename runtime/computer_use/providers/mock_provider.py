from __future__ import annotations

from typing import Any

from runtime.computer_use.providers.base import ProviderResult


class MockVisionProvider:
    provider_name = "mock"
    provider_version = "1.0"

    def __init__(self, scenario: str = "low_risk_read_screen") -> None:
        self.scenario = scenario

    def health_check(self) -> dict[str, str]:
        return {"provider": self.provider_name, "status": "HEALTHY"}

    def analyze_screen(self, observation: dict[str, Any]) -> ProviderResult:
        if not observation.get("observation_id"):
            return self._fail("missing_observation")
        if self.scenario == "provider_failure":
            return self._fail("provider_failure")
        if self.scenario == "malformed":
            return self._fail("malformed_response")
        if self.scenario == "high_risk_click":
            return self._result("HUMAN_REVIEW", "click", "github merge button", "HIGH", True, "human_review_required")
        if self.scenario == "secret_like_text":
            return self._result("BLOCK", "type", "password field", "HIGH", True, "secret_like_text_blocked")
        return self._result("ALLOW", "read_screen", "screen", "LOW", False, "low_risk_read")

    def _fail(self, reason: str) -> ProviderResult:
        return self._result("FAIL_CLOSED", "unknown", "unknown", "UNKNOWN", True, reason)

    def _result(
        self,
        status: str,
        action_type: str,
        target: str,
        risk: str,
        requires_approval: bool,
        reason: str,
    ) -> ProviderResult:
        return ProviderResult(
            provider=self.provider_name,
            status=status,
            screen_summary="redacted summary",
            proposed_action={"type": action_type, "target": target, "risk": risk},
            requires_human_approval=requires_approval,
            reason=reason,
            audit={
                "raw_screenshot_stored": False,
                "provider_call_recorded": True,
                "policy_checked": True,
            },
        )

