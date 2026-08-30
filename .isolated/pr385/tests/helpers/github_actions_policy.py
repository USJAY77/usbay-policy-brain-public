from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "approved_github_actions_policy.json"
ACTION_REF_PATTERN = re.compile(r"uses:\s*(actions/[A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+)")


def load_github_actions_policy() -> dict[str, Any]:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def approved_action_ref(action_name: str, policy: dict[str, Any] | None = None) -> str:
    resolved_policy = policy or load_github_actions_policy()
    action_policy = resolved_policy["actions"][action_name]
    return f"{action_name}@{action_policy['allowed_version']}"


def workflow_action_refs(workflow_text: str) -> list[str]:
    return [f"{match.group(1)}@{match.group(2)}" for match in ACTION_REF_PATTERN.finditer(workflow_text)]


def evaluate_action_ref(
    action_ref: str,
    *,
    context: str,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_github_actions_policy()
    if "@" not in action_ref:
        return _fail_closed(action_ref, "GITHUB_ACTION_VERSION_MISSING", context)

    action_name, version = action_ref.rsplit("@", 1)
    action_policy = resolved_policy.get("actions", {}).get(action_name)
    if action_policy is None:
        return _fail_closed(action_ref, "UNKNOWN_GITHUB_ACTION", context)

    if version != action_policy["allowed_version"]:
        return _fail_closed(action_ref, "UNAPPROVED_GITHUB_ACTION_VERSION", context)

    if context == "fast_pr" and not action_policy["allowed_in_fast_pr_path"]:
        return _fail_closed(action_ref, "GITHUB_ACTION_DISALLOWED_IN_FAST_PR", context)

    if context == "manual_resilience" and not action_policy["allowed_in_manual_resilience_workflows"]:
        return _fail_closed(action_ref, "GITHUB_ACTION_DISALLOWED_IN_MANUAL_RESILIENCE", context)

    return {
        "action": action_name,
        "context": context,
        "decision": "PASS",
        "fail_closed": False,
        "reason": "APPROVED_GITHUB_ACTION",
        "version": version,
    }


def _fail_closed(action_ref: str, reason: str, context: str) -> dict[str, Any]:
    return {
        "action_ref": action_ref,
        "context": context,
        "decision": "FAIL_CLOSED",
        "fail_closed": True,
        "reason": reason,
        "silent_pass": False,
    }
