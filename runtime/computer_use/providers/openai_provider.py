from __future__ import annotations

from typing import Any

from runtime.computer_use.providers.base import VisionProvider


class OpenAIVisionProvider(VisionProvider):
    provider_name = "openai"
    provider_version = "future-boundary"

    def _analyze_validated(self, _observation: dict[str, Any]) -> dict[str, Any]:
        return self._fail_closed_response("LIVE_PROVIDER_NOT_IMPLEMENTED").to_dict()
