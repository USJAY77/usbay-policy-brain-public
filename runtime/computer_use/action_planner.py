from __future__ import annotations

from runtime.computer_use.action_schema import ComputerUseAction
from runtime.computer_use.vision_adapter import VisionObservation


class ActionPlanner:
    def propose_read_screen(self, observation: VisionObservation) -> ComputerUseAction:
        return ComputerUseAction(
            action_type="read_screen",
            target=observation.summary,
            required_capability="computer_use.read_screen",
            risk_level="LOW",
        )

    def propose_stop(self, reason: str) -> ComputerUseAction:
        return ComputerUseAction(
            action_type="stop",
            target=reason,
            required_capability="computer_use.stop",
            risk_level="LOW",
        )
