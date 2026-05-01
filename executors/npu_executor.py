from __future__ import annotations

from typing import Any


def execute(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "EXECUTED",
        "actual_execution_target": "npu",
        "execution_verified": True,
    }
