from __future__ import annotations

from dataclasses import dataclass

from runtime.computer_use.action_schema import ComputerUseAction


@dataclass(frozen=True)
class BrowserDriverResult:
    executed: bool
    dry_run: bool
    reason: str


class BrowserDriver:
    def __init__(self, *, dry_run: bool = True) -> None:
        self.dry_run = dry_run

    def execute(self, action: ComputerUseAction) -> BrowserDriverResult:
        if self.dry_run:
            return BrowserDriverResult(executed=False, dry_run=True, reason="DRY_RUN_NO_BROWSER_MUTATION")
        raise RuntimeError("LIVE_BROWSER_EXECUTION_NOT_ENABLED")
