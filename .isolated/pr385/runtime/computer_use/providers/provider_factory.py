from __future__ import annotations

from runtime.computer_use.audit_recorder import ComputerUseAuditRecorder
from runtime.computer_use.providers.base import ProviderResult
from runtime.computer_use.providers.mock_provider import MockVisionProvider


class FailClosedProvider:
    provider_name = "unknown"
    provider_version = "0"

    def __init__(
        self,
        requested_provider: str,
        *,
        audit_recorder: ComputerUseAuditRecorder | None = None,
        timeout_seconds: float = 2.0,
    ) -> None:
        self.requested_provider = requested_provider or "missing"
        self.audit_recorder = audit_recorder
        self.timeout_seconds = timeout_seconds

    def health_check(self) -> dict[str, str]:
        return {
            "provider": self.provider_name,
            "requested_provider": self.requested_provider,
            "status": "FAIL_CLOSED",
        }

    def analyze_screen(self, observation: dict) -> ProviderResult:
        return MockVisionProvider(
            "low_risk_read_screen",
            audit_recorder=self.audit_recorder,
            timeout_seconds=self.timeout_seconds,
        )._result("FAIL_CLOSED", "unknown", "unknown", "CRITICAL", True, "PROVIDER_UNKNOWN", observation)


def get_provider(
    name: str = "mock",
    *,
    scenario: str = "low_risk_read_screen",
    audit_recorder: ComputerUseAuditRecorder | None = None,
    timeout_seconds: float = 2.0,
):
    provider_name = name or ""
    if provider_name != "mock":
        return FailClosedProvider(provider_name, audit_recorder=audit_recorder, timeout_seconds=timeout_seconds)
    return MockVisionProvider(scenario, audit_recorder=audit_recorder, timeout_seconds=timeout_seconds)
