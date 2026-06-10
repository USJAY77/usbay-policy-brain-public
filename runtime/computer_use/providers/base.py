from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Protocol


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    status: str
    screen_summary: str
    proposed_action: dict[str, Any]
    requires_human_approval: bool
    reason: str
    audit: dict[str, Any]

    def safe_audit_hash(self) -> str:
        return sha256(
            f"{self.provider}|{self.status}|{self.proposed_action.get('type')}|{self.reason}".encode("utf-8")
        ).hexdigest()


class VisionProvider(Protocol):
    provider_name: str
    provider_version: str

    def health_check(self) -> dict[str, str]:
        ...

    def analyze_screen(self, observation: dict[str, Any]) -> ProviderResult:
        ...

