from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Iterator, Protocol


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    status: str
    screen_summary: str
    proposed_action: dict[str, Any]
    requires_human_approval: bool
    reason: str
    audit: dict[str, Any]

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def __iter__(self) -> Iterator[str]:
        return iter(
            (
                "provider",
                "status",
                "screen_summary",
                "proposed_action",
                "requires_human_approval",
                "reason",
                "audit",
            )
        )

    def __len__(self) -> int:
        return 7

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
