from __future__ import annotations

from runtime.computer_use.providers.mock_provider import MockVisionProvider


def get_provider(name: str = "mock", *, scenario: str = "low_risk_read_screen"):
    if name != "mock":
        return MockVisionProvider("provider_failure")
    return MockVisionProvider(scenario)

