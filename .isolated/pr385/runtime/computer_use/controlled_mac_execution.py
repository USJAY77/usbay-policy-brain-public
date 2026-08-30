from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from runtime.computer_use.vision_governance import DEFAULT_POLICY_HASH, EXECUTION_CAPABILITIES


CONTROLLED_MAC_EXECUTION_VERSION = "pb251-255-controlled-mac-execution-pilot-v1"


class ExecutionAuthorityState(str, Enum):
    BLOCKED = "BLOCKED"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"


class KillSwitchState(str, Enum):
    ENABLED_SAFE = "ENABLED_SAFE"
    DISABLED_UNSAFE = "DISABLED_UNSAFE"


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def audit_hash(data: Any) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def controlled_execution_authority_contract_json() -> dict[str, Any]:
    return {
        "contract_version": CONTROLLED_MAC_EXECUTION_VERSION,
        "default_state": ExecutionAuthorityState.BLOCKED.value,
        "execution_activation_allowed": False,
        "requirements": {
            "policy_decision": "ALLOW",
            "human_approval": "APPROVED",
            "risk_level": ["LOW", "MEDIUM"],
            "screen_class_not": "UNKNOWN",
            "sensitive_screen": False,
            "kill_switch": KillSwitchState.ENABLED_SAFE.value,
        },
        "high_risk_outcome": "HUMAN_APPROVAL_REQUIRED",
        "critical_risk_outcome": "BLOCKED",
    }


def evaluate_execution_authority(
    *,
    policy_decision: str,
    human_approval: str,
    risk_level: str,
    screen_class: str,
    sensitive_screen: bool,
    kill_switch: str,
) -> dict[str, Any]:
    gaps: list[str] = []
    if policy_decision != "ALLOW":
        gaps.append("POLICY_DECISION_NOT_ALLOW")
    if human_approval != "APPROVED":
        gaps.append("HUMAN_APPROVAL_NOT_APPROVED")
    if risk_level == "HIGH":
        gaps.append("HIGH_RISK_REQUIRES_APPROVAL")
    if risk_level == "CRITICAL":
        gaps.append("CRITICAL_RISK_BLOCKED")
    if risk_level not in {"LOW", "MEDIUM"}:
        gaps.append("RISK_LEVEL_NOT_EXECUTABLE")
    if screen_class == "UNKNOWN":
        gaps.append("UNKNOWN_SCREEN_BLOCKED")
    if sensitive_screen:
        gaps.append("SENSITIVE_SCREEN_BLOCKED")
    if kill_switch != KillSwitchState.ENABLED_SAFE.value:
        gaps.append("KILL_SWITCH_NOT_SAFE")
    return {
        "decision": "READY_FOR_REVIEW" if not gaps else "BLOCKED",
        "state": "READY_FOR_REVIEW" if not gaps else "BLOCKED",
        "gaps": sorted(set(gaps)),
        "execution_performed": False,
        "contract_version": CONTROLLED_MAC_EXECUTION_VERSION,
    }


def human_approved_desktop_actions_contract_json() -> dict[str, Any]:
    return {
        "contract_version": CONTROLLED_MAC_EXECUTION_VERSION,
        "allowed_future_actions": list(EXECUTION_CAPABILITIES),
        "approval_id_required": True,
        "free_form_execution_allowed": False,
        "live_execution_allowed": False,
        "blocked_approval_states": ["MISSING", "EXPIRED", "REUSED", "MISMATCHED"],
    }


def validate_desktop_action_approval(
    *,
    action_id: str,
    action_type: str,
    approval: dict[str, Any] | None,
    used_approval_ids: set[str] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    gaps: list[str] = []
    if action_type not in EXECUTION_CAPABILITIES:
        gaps.append("ACTION_NOT_ALLOWED")
    if not isinstance(approval, dict):
        gaps.append("MISSING_APPROVAL")
        approval = {}
    approval_id = str(approval.get("approval_id", ""))
    if not approval_id:
        gaps.append("MISSING_APPROVAL_ID")
    if approval_id and approval_id in (used_approval_ids or set()):
        gaps.append("APPROVAL_REUSED")
    if approval.get("action_id") != action_id:
        gaps.append("APPROVAL_ACTION_MISMATCH")
    if approval.get("approval_status") != "APPROVED":
        gaps.append("APPROVAL_NOT_APPROVED")
    try:
        if _parse_utc(str(approval.get("expires_at", ""))) <= _parse_utc(now or utc_now()):
            gaps.append("APPROVAL_EXPIRED")
    except Exception:
        gaps.append("APPROVAL_EXPIRED")
    return {
        "decision": "VERIFIED" if not gaps else "BLOCKED",
        "gaps": sorted(set(gaps)),
        "execution_performed": False,
        "contract_version": CONTROLLED_MAC_EXECUTION_VERSION,
    }


def execution_kill_switch_contract_json() -> dict[str, Any]:
    return {
        "contract_version": CONTROLLED_MAC_EXECUTION_VERSION,
        "default_state": KillSwitchState.DISABLED_UNSAFE.value,
        "safe_state": KillSwitchState.ENABLED_SAFE.value,
        "execution_activation_allowed": False,
        "disable_triggers": ["unsafe_state", "audit_failure", "unknown_screen", "approval_failure"],
        "rollback_records_reason_and_audit_hash": True,
    }


def evaluate_kill_switch(
    *,
    unsafe_state: bool = False,
    audit_failure: bool = False,
    unknown_screen: bool = False,
    approval_failure: bool = False,
    reason: str = "none",
) -> dict[str, Any]:
    triggers: list[str] = []
    if unsafe_state:
        triggers.append("UNSAFE_STATE")
    if audit_failure:
        triggers.append("AUDIT_FAILURE")
    if unknown_screen:
        triggers.append("UNKNOWN_SCREEN")
    if approval_failure:
        triggers.append("APPROVAL_FAILURE")
    rollback = {
        "reason": reason if triggers else "NO_EXECUTION_AUTHORITY",
        "triggers": triggers,
    }
    return {
        "decision": "BLOCKED" if triggers else "READY_FOR_REVIEW",
        "kill_switch": KillSwitchState.DISABLED_UNSAFE.value if triggers else KillSwitchState.ENABLED_SAFE.value,
        "execution_performed": False,
        "rollback": {
            **rollback,
            "audit_hash": audit_hash(rollback),
        },
        "contract_version": CONTROLLED_MAC_EXECUTION_VERSION,
    }


def live_mac_pilot_window_contract_json() -> dict[str, Any]:
    return {
        "contract_version": CONTROLLED_MAC_EXECUTION_VERSION,
        "start_time": "2030-01-01T00:00:00Z",
        "end_time": "2030-01-01T01:00:00Z",
        "approved_actor": "human-approval-required",
        "allowed_apps": ["Finder", "Code", "Terminal"],
        "allowed_actions": list(EXECUTION_CAPABILITIES),
        "blocked_apps": ["Browser", "Password Manager", "Banking", "Payments"],
        "policy_hash": DEFAULT_POLICY_HASH,
        "status": "BLOCKED",
        "live_execution_activation_allowed": False,
    }


@dataclass(frozen=True)
class MacExecutionEvidence:
    action_id: str
    approval_id: str
    screen_hash: str
    screen_class: str
    risk_level: str
    policy_hash: str
    decision: str
    executed: bool
    blocked_reason: str
    audit_hash: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["contract_version"] = CONTROLLED_MAC_EXECUTION_VERSION
        payload["raw_screenshot_stored"] = False
        payload["sensitive_data_stored"] = False
        return payload


def create_execution_evidence(
    *,
    action_id: str,
    approval_id: str,
    screen_hash: str,
    screen_class: str,
    risk_level: str,
    policy_hash: str,
    decision: str,
    executed: bool = False,
    blocked_reason: str = "EXECUTION_NOT_ACTIVATED",
) -> dict[str, Any]:
    base = {
        "action_id": action_id,
        "approval_id": approval_id,
        "screen_hash": screen_hash,
        "screen_class": screen_class,
        "risk_level": risk_level,
        "policy_hash": policy_hash,
        "decision": decision,
        "executed": False,
        "blocked_reason": blocked_reason,
    }
    evidence = MacExecutionEvidence(audit_hash=audit_hash(base), **base)
    return evidence.to_dict()
