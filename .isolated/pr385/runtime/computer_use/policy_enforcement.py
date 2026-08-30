from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

ALLOWED_ACTIONS = {"read_screen", "wait", "scroll", "click", "type", "open_url", "stop"}


@dataclass(frozen=True)
class PolicyCheck:
    decision: str
    reason: str
    policy_version: str | None


class PolicyEnforcer:
    def __init__(self, policy: dict[str, Any] | None = None, policy_path: str | Path | None = None) -> None:
        self.policy = policy
        self.policy_path = Path(policy_path) if policy_path else None

    def load_policy(self) -> dict[str, Any] | None:
        if self.policy is not None:
            return self.policy
        if self.policy_path is None or not self.policy_path.exists():
            return None
        import json

        return json.loads(self.policy_path.read_text(encoding="utf-8"))

    def check(self, action_type: str, required_policy_version: str | None) -> PolicyCheck:
        policy = self.load_policy()
        if not policy:
            return PolicyCheck("FAIL_CLOSED", "policy_missing", None)
        version = policy.get("policy_version")
        if not version or version != required_policy_version:
            return PolicyCheck("FAIL_CLOSED", "policy_version_mismatch", version)
        allowed = set(policy.get("allowed_actions", ALLOWED_ACTIONS))
        if action_type not in allowed:
            return PolicyCheck("BLOCK", "unsupported_action", version)
        return PolicyCheck("ALLOW", "policy_valid", version)

