from __future__ import annotations

from typing import Any


EXECUTION_DISABLED = "EXECUTION_DISABLED"
EXECUTION_BLOCKED = "EXECUTION_BLOCKED"
ADAPTER_NOT_IMPLEMENTED = "ADAPTER_NOT_IMPLEMENTED"


class DisabledExecutionAdapter:
    adapter_name = "base"

    def evaluate(self, request: dict[str, Any] | None = None) -> dict[str, str]:
        return {
            "adapter": self.adapter_name,
            "status": EXECUTION_DISABLED,
            "decision": EXECUTION_BLOCKED,
            "reason": ADAPTER_NOT_IMPLEMENTED,
        }
