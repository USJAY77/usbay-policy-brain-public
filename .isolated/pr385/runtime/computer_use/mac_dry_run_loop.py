from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from runtime.computer_use.vision_governance import (
    DEFAULT_POLICY_HASH,
    EXECUTION_CAPABILITIES,
    classify_screen,
    detect_sensitive_screen,
    metadata_hash,
    propose_desktop_action,
    score_vision_risk,
)


MAC_DRY_RUN_VERSION = "pb246-250-governed-mac-dry-run-loop-v1"


class ApprovalStatus(str, Enum):
    MISSING = "MISSING"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    EXPIRED = "EXPIRED"
    BLOCKED = "BLOCKED"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def screenshot_capture_contract_json() -> dict[str, Any]:
    return {
        "contract_version": MAC_DRY_RUN_VERSION,
        "capture_mode": "LOCAL_METADATA_ONLY",
        "raw_screenshot_storage": "DISABLED",
        "stored_fields": ["screenshot_hash", "timestamp", "screen_class", "risk_level", "policy_hash"],
        "sensitive_screen_outcome": "BLOCKED",
        "external_api_calls_allowed": False,
        "browser_calls_allowed": False,
        "desktop_control_allowed": False,
        "pyautogui_execution_allowed": False,
    }


def capture_screenshot_metadata(
    *,
    screen_metadata: dict[str, Any],
    policy_hash: str = DEFAULT_POLICY_HASH,
    timestamp: str | None = None,
) -> dict[str, Any]:
    classification = classify_screen(screen_metadata)
    sensitive = detect_sensitive_screen(screen_metadata)
    risk = score_vision_risk(classification["screen_class"], sensitive["markers"])
    decision = "BLOCKED" if sensitive["decision"] == "BLOCKED" or classification["decision"] == "FAIL_CLOSED" else "VERIFIED"
    return {
        "decision": decision,
        "screenshot_hash": metadata_hash({"screen_metadata": screen_metadata, "policy_hash": policy_hash}),
        "timestamp": timestamp or utc_now(),
        "screen_class": classification["screen_class"],
        "risk_level": risk["risk_level"],
        "policy_hash": policy_hash,
        "raw_screenshot_stored": False,
        "contract_version": MAC_DRY_RUN_VERSION,
    }


def run_observation_loop(screen_metadata: dict[str, Any], *, policy_hash: str = DEFAULT_POLICY_HASH) -> dict[str, Any]:
    observation = capture_screenshot_metadata(screen_metadata=screen_metadata, policy_hash=policy_hash)
    classification = classify_screen(screen_metadata)
    sensitive = detect_sensitive_screen(screen_metadata)
    risk = score_vision_risk(classification["screen_class"], sensitive["markers"])
    if classification["decision"] == "FAIL_CLOSED":
        policy_decision = "FAIL_CLOSED"
    elif sensitive["decision"] == "BLOCKED" or risk["decision"] == "BLOCKED":
        policy_decision = "BLOCKED"
    elif risk["approval_required"] or sensitive["decision"] == "HUMAN_APPROVAL_REQUIRED":
        policy_decision = "HUMAN_APPROVAL_REQUIRED"
    else:
        policy_decision = "VERIFIED"
    return {
        "steps": [
            "observe_screen",
            "classify_screen",
            "detect_sensitive_markers",
            "score_risk",
            "policy_decision",
        ],
        "policy_decision": policy_decision,
        "observation": observation,
        "classification": classification,
        "sensitive_detection": sensitive,
        "risk": risk,
        "external_vision_api_calls": False,
        "raw_screenshot_stored": False,
        "contract_version": MAC_DRY_RUN_VERSION,
    }


def propose_dry_run_action(
    *,
    action_id: str,
    action_type: str,
    screen_metadata: dict[str, Any],
    policy_hash: str = DEFAULT_POLICY_HASH,
) -> dict[str, Any]:
    loop = run_observation_loop(screen_metadata, policy_hash=policy_hash)
    sensitive_markers = loop["sensitive_detection"]["markers"]
    action = propose_desktop_action(
        action_id=action_id,
        action_type=action_type,
        screen_class=loop["classification"]["screen_class"],
        sensitive_markers=sensitive_markers,
        policy_hash=policy_hash,
    )
    if action_type not in EXECUTION_CAPABILITIES:
        action["decision"] = "BLOCKED"
    elif action["risk_level"] == "CRITICAL":
        action["decision"] = "BLOCKED"
    elif action["risk_level"] == "HIGH":
        action["decision"] = "HUMAN_APPROVAL_REQUIRED"
    action["policy_decision"] = action["decision"]
    action["real_execution_performed"] = False
    action["desktop_control_allowed"] = False
    action["contract_version"] = MAC_DRY_RUN_VERSION
    return action


@dataclass(frozen=True)
class HumanApprovalRequest:
    approval_id: str
    action_id: str
    action_type: str
    screen_class: str
    risk_level: str
    policy_hash: str
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    expires_at: str = "1970-01-01T00:00:00Z"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["approval_status"] = self.approval_status.value
        payload["contract_version"] = MAC_DRY_RUN_VERSION
        payload["real_execution_allowed"] = False
        return payload


def create_human_approval_request(proposed_action: dict[str, Any], *, expires_at: str) -> dict[str, Any]:
    request = HumanApprovalRequest(
        approval_id=metadata_hash({"action_id": proposed_action.get("action_id"), "expires_at": expires_at})[:24],
        action_id=str(proposed_action.get("action_id", "missing")),
        action_type=str(proposed_action.get("action_type", "missing")),
        screen_class=str(proposed_action.get("screen_class", "UNKNOWN")),
        risk_level=str(proposed_action.get("risk_level", "CRITICAL")),
        policy_hash=str(proposed_action.get("policy_hash", DEFAULT_POLICY_HASH)),
        expires_at=expires_at,
    )
    return request.to_dict()


def evaluate_approval_for_execution(approval: dict[str, Any] | None, *, now: str | None = None) -> dict[str, Any]:
    if not isinstance(approval, dict):
        return {"decision": "FAIL_CLOSED", "gaps": ["MISSING_APPROVAL"], "real_execution_performed": False}
    gaps: list[str] = []
    if approval.get("approval_status") != ApprovalStatus.APPROVED.value:
        gaps.append("APPROVAL_NOT_APPROVED")
    try:
        clock = datetime.fromisoformat((now or utc_now()).replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(str(approval.get("expires_at", "")).replace("Z", "+00:00"))
        if expires_at <= clock:
            gaps.append("APPROVAL_EXPIRED")
    except Exception:
        gaps.append("MALFORMED_APPROVAL_EXPIRY")
    return {
        "decision": "VERIFIED" if not gaps else "FAIL_CLOSED",
        "gaps": sorted(set(gaps)),
        "real_execution_performed": False,
        "desktop_control_allowed": False,
        "contract_version": MAC_DRY_RUN_VERSION,
    }


def simulate_controlled_mac_dry_run() -> dict[str, Any]:
    screen_metadata = {"title": "GitHub pull request review", "app": "local workspace"}
    observation = run_observation_loop(screen_metadata)
    proposed_action = propose_dry_run_action(
        action_id="pb250-dry-run-action-1",
        action_type="click",
        screen_metadata=screen_metadata,
    )
    approval = create_human_approval_request(proposed_action, expires_at="2030-01-01T00:00:00Z")
    audit_hash = metadata_hash(
        {
            "observation": observation["observation"]["screenshot_hash"],
            "action": proposed_action["audit_hash"],
            "approval": approval["approval_id"],
        }
    )
    return {
        "decision": "HUMAN_APPROVAL_REQUIRED",
        "steps": [
            "screenshot_metadata",
            "screen_classification",
            "risk_score",
            "proposed_action",
            "approval_required",
            "audit_evidence",
        ],
        "observation": observation,
        "proposed_action": proposed_action,
        "approval_request": approval,
        "audit_hash": audit_hash,
        "real_execution_performed": False,
        "pyautogui_execution_performed": False,
        "browser_calls_performed": False,
        "external_api_calls_performed": False,
        "raw_screenshot_stored": False,
        "contract_version": MAC_DRY_RUN_VERSION,
    }
