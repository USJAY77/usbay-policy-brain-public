from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


VISION_GOVERNANCE_VERSION = "pb241-245-governed-vision-computer-use-v1"
DEFAULT_POLICY_HASH = "88d1aaa62bbe011c9f51d7f159a7526a2fe283b94314e8c9b9cce73b199f04d1"


class VisionCapabilityState(str, Enum):
    LOCAL_ONLY = "LOCAL_ONLY"
    DISABLED = "DISABLED"


class ScreenClass(str, Enum):
    SAFE_WORKSPACE = "SAFE_WORKSPACE"
    CODE_EDITOR = "CODE_EDITOR"
    GITHUB_PR = "GITHUB_PR"
    NOTION_PAGE = "NOTION_PAGE"
    EURIA_PROJECT = "EURIA_PROJECT"
    LOGIN_SCREEN = "LOGIN_SCREEN"
    PAYMENT_SCREEN = "PAYMENT_SCREEN"
    BANKING_SCREEN = "BANKING_SCREEN"
    MEDICAL_SCREEN = "MEDICAL_SCREEN"
    GOVERNMENT_PORTAL = "GOVERNMENT_PORTAL"
    UNKNOWN = "UNKNOWN"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


ALLOWED_LOCAL_CAPABILITIES = (
    "take_screenshot",
    "describe_screen",
    "classify_screen",
    "propose_action",
    "request_human_approval",
)
EXECUTION_CAPABILITIES = ("click", "type_text", "press_key", "scroll", "open_app")
SENSITIVE_MARKERS = (
    "password",
    "token",
    "secret",
    "private key",
    "bank",
    "payment",
    "personal data",
    "medical",
    "government",
)


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def metadata_hash(data: Any) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def vision_capability_registry_json() -> dict[str, Any]:
    return {
        "contract_version": VISION_GOVERNANCE_VERSION,
        "local_only_capabilities": {
            capability: {
                "state": VisionCapabilityState.LOCAL_ONLY.value,
                "external_api_calls_allowed": False,
                "desktop_execution_allowed": False,
            }
            for capability in ALLOWED_LOCAL_CAPABILITIES
        },
        "execution_capabilities": {
            capability: {
                "state": VisionCapabilityState.DISABLED.value,
                "pyautogui_execution_allowed": False,
                "live_execution_allowed": False,
            }
            for capability in EXECUTION_CAPABILITIES
        },
        "browser_execution_allowed": False,
        "desktop_execution_allowed": False,
        "external_api_calls_allowed": False,
        "raw_screenshot_storage_allowed": False,
    }


def classify_screen(metadata: dict[str, Any]) -> dict[str, Any]:
    text = " ".join(str(value).lower() for value in metadata.values() if isinstance(value, str))
    screen_class = ScreenClass.UNKNOWN
    if any(marker in text for marker in ("github", "pull request", "pr #", "merge")):
        screen_class = ScreenClass.GITHUB_PR
    elif any(marker in text for marker in ("notion", "workspace page", "database")):
        screen_class = ScreenClass.NOTION_PAGE
    elif any(marker in text for marker in ("euria", "project")):
        screen_class = ScreenClass.EURIA_PROJECT
    elif any(marker in text for marker in ("vscode", "code editor", "python", "typescript")):
        screen_class = ScreenClass.CODE_EDITOR
    elif any(marker in text for marker in ("login", "sign in", "password")):
        screen_class = ScreenClass.LOGIN_SCREEN
    elif any(marker in text for marker in ("payment", "checkout", "credit card")):
        screen_class = ScreenClass.PAYMENT_SCREEN
    elif any(marker in text for marker in ("bank", "iban", "routing")):
        screen_class = ScreenClass.BANKING_SCREEN
    elif "medical" in text:
        screen_class = ScreenClass.MEDICAL_SCREEN
    elif "government" in text:
        screen_class = ScreenClass.GOVERNMENT_PORTAL
    elif any(marker in text for marker in ("workspace", "dashboard", "local")):
        screen_class = ScreenClass.SAFE_WORKSPACE
    decision = "FAIL_CLOSED" if screen_class == ScreenClass.UNKNOWN else "VERIFIED"
    return {
        "decision": decision,
        "screen_class": screen_class.value,
        "classification_hash": metadata_hash({"screen_class": screen_class.value, "metadata": metadata}),
        "raw_screenshot_stored": False,
        "contract_version": VISION_GOVERNANCE_VERSION,
    }


def detect_sensitive_screen(metadata: dict[str, Any]) -> dict[str, Any]:
    text = " ".join(str(value).lower() for value in metadata.values() if isinstance(value, str))
    markers = sorted({marker for marker in SENSITIVE_MARKERS if marker in text})
    blocked_markers = {"password", "token", "secret", "private key", "bank", "payment"}
    if not markers:
        return {
            "decision": "VERIFIED",
            "status": "SAFE_METADATA_ONLY",
            "markers": [],
            "raw_screenshot_stored": False,
            "evidence_hash": metadata_hash({"markers": [], "metadata": metadata}),
        }
    decision = "BLOCKED" if any(marker in blocked_markers for marker in markers) else "HUMAN_APPROVAL_REQUIRED"
    return {
        "decision": decision,
        "status": decision,
        "markers": markers,
        "raw_screenshot_stored": False,
        "evidence_hash": metadata_hash({"markers": markers, "metadata_hash": metadata_hash(metadata)}),
    }


def score_vision_risk(screen_class: str, sensitive_markers: list[str] | tuple[str, ...]) -> dict[str, Any]:
    markers = {marker.lower() for marker in sensitive_markers}
    if screen_class in {
        ScreenClass.BANKING_SCREEN.value,
        ScreenClass.PAYMENT_SCREEN.value,
        ScreenClass.MEDICAL_SCREEN.value,
        ScreenClass.GOVERNMENT_PORTAL.value,
    } or markers & {"password", "token", "secret", "private key", "bank", "payment"}:
        risk = RiskLevel.CRITICAL
    elif screen_class in {ScreenClass.LOGIN_SCREEN.value, ScreenClass.UNKNOWN.value} or markers:
        risk = RiskLevel.HIGH
    elif screen_class in {ScreenClass.GITHUB_PR.value, ScreenClass.NOTION_PAGE.value, ScreenClass.EURIA_PROJECT.value}:
        risk = RiskLevel.MEDIUM
    else:
        risk = RiskLevel.LOW
    return {
        "risk_level": risk.value,
        "approval_required": risk in {RiskLevel.HIGH, RiskLevel.CRITICAL},
        "decision": "BLOCKED" if risk == RiskLevel.CRITICAL else "HUMAN_APPROVAL_REQUIRED" if risk == RiskLevel.HIGH else "VERIFIED",
        "metadata_hash": metadata_hash({"screen_class": screen_class, "markers": sorted(markers), "risk": risk.value}),
        "raw_screenshot_stored": False,
        "contract_version": VISION_GOVERNANCE_VERSION,
    }


@dataclass(frozen=True)
class ProposedDesktopAction:
    action_id: str
    action_type: str
    screen_class: str
    risk_level: str
    policy_hash: str
    approval_required: bool
    decision: str
    audit_hash: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["contract_version"] = VISION_GOVERNANCE_VERSION
        payload["live_execution_allowed"] = False
        payload["pyautogui_execution_allowed"] = False
        return payload


def propose_desktop_action(
    *,
    action_id: str,
    action_type: str,
    screen_class: str,
    sensitive_markers: list[str] | None = None,
    policy_hash: str = DEFAULT_POLICY_HASH,
) -> dict[str, Any]:
    risk = score_vision_risk(screen_class, sensitive_markers or [])
    decision = "BLOCKED"
    if action_type not in EXECUTION_CAPABILITIES:
        decision = "BLOCKED"
    elif risk["risk_level"] == RiskLevel.LOW.value:
        decision = "BLOCKED"
    elif risk["risk_level"] in {RiskLevel.MEDIUM.value, RiskLevel.HIGH.value}:
        decision = "HUMAN_APPROVAL_REQUIRED"
    audit_hash = metadata_hash(
        {
            "action_id": action_id,
            "action_type": action_type,
            "screen_class": screen_class,
            "risk_level": risk["risk_level"],
            "decision": decision,
            "policy_hash": policy_hash,
        }
    )
    proposed = ProposedDesktopAction(
        action_id=action_id,
        action_type=action_type,
        screen_class=screen_class,
        risk_level=risk["risk_level"],
        policy_hash=policy_hash,
        approval_required=True,
        decision=decision,
        audit_hash=audit_hash,
    )
    return proposed.to_dict()
