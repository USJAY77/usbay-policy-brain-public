from __future__ import annotations

from dataclasses import dataclass

from runtime.computer_use.audit_recorder import ComputerUseAuditRecorder
from runtime.computer_use.providers.base import VisionProvider
from runtime.computer_use.providers.provider_factory import get_provider
from runtime.computer_use.screen_capture import ScreenMetadata


@dataclass(frozen=True)
class VisionObservation:
    provider: str
    summary: str
    raw_model_call_performed: bool = False


class VisionAdapter:
    """Provider abstraction placeholder.

    Live Gemini/OpenAI/Claude calls are intentionally not implemented here.
    """

    def __init__(self, provider: VisionProvider | None = None) -> None:
        self.provider = provider

    @classmethod
    def for_provider(
        cls,
        provider_name: str,
        *,
        audit_recorder: ComputerUseAuditRecorder,
        timeout_seconds: float = 2.0,
    ) -> "VisionAdapter":
        provider = get_provider(
            provider_name,
            audit_recorder=audit_recorder,
            timeout_seconds=timeout_seconds,
        )
        return cls(provider=provider)

    def observe(self, metadata: ScreenMetadata) -> VisionObservation:
        if self.provider is not None:
            result = self.provider.analyze_screen(
                {
                    "action_id": metadata.capture_id,
                    "scenario": "low_risk_read_screen",
                    "screen_metadata": metadata.to_dict(),
                }
            )
            return VisionObservation(
                provider=result["provider"],
                summary=result["screen_summary"],
                raw_model_call_performed=False,
            )
        return VisionObservation(
            provider="metadata_only",
            summary=f"screen metadata {metadata.capture_id}",
            raw_model_call_performed=False,
        )
