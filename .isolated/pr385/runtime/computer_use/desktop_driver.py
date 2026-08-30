from __future__ import annotations

from dataclasses import dataclass

from runtime.computer_use.action_schema import ComputerUseAction


@dataclass(frozen=True)
class DriverResult:
    executed: bool
    dry_run: bool
    reason: str


class DesktopDriver:
    def __init__(self, *, dry_run: bool = True) -> None:
        self.dry_run = dry_run

    def execute(self, action: ComputerUseAction) -> DriverResult:
        if self.dry_run:
            return DriverResult(executed=False, dry_run=True, reason="DRY_RUN_NO_DESKTOP_MUTATION")
        raise RuntimeError("LIVE_DESKTOP_EXECUTION_NOT_ENABLED")
