from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


OBSERVATION_SCHEMA = "usbay.vision.observation.v1"
ACTION_PROPOSAL_SCHEMA = "usbay.vision.action_proposal.v1"
HUMAN_APPROVAL_SCHEMA = "usbay.vision.human_approval.v1"
AUDIT_RECORD_SCHEMA = "usbay.vision.audit_record.v1"

ALLOWED_PREVIEW_ACTION_TYPES = frozenset(
    {
        "READ_ONLY_NAVIGATION",
        "UI_INSPECTION",
        "COPY_TEXT",
        "PREPARE_COMMAND",
        "PREPARE_GITHUB_COMMENT",
        "PREPARE_PR_DESCRIPTION",
    }
)

BLOCKED_ACTION_TYPES = frozenset(
    {
        "CLICK",
        "TYPE",
        "SUBMIT_FORM",
        "RUN_COMMAND",
        "PUSH_CODE",
        "MERGE_PR",
        "DELETE_FILE",
        "MODIFY_FILE",
        "SEND_MESSAGE",
        "PAYMENT",
        "LOGIN",
        "SECRET_ACCESS",
    }
)

EXECUTION_LIKE_ACTION_TYPES = BLOCKED_ACTION_TYPES
SENSITIVE_ACTION_TYPES = frozenset({"PAYMENT", "LOGIN", "SECRET_ACCESS"})
AI_APPROVER_IDENTITIES = frozenset({"codex", "ai-agent", "ai_agent", "agent", "assistant"})
REVIEW_ONLY_SCOPES = frozenset({"REVIEW_ONLY", "PREVIEW_ONLY", "READ_ONLY"})

REQUIRED_OBSERVATION_FIELDS = (
    "schema",
    "observation_id",
    "generated_at",
    "device_id",
    "source",
    "screenshot_hash",
    "redaction_applied",
    "raw_screenshot_logged",
    "detected_ui_elements",
    "detected_text_summary",
    "confidence",
    "errors",
)

REQUIRED_PROPOSAL_FIELDS = (
    "schema",
    "proposal_id",
    "observation_id",
    "requested_action",
    "action_type",
    "target",
    "parameters",
    "reason",
    "confidence",
    "requested_by_agent",
    "device_id",
    "policy_version",
    "requires_human_approval",
    "risk_level",
    "created_at",
)

REQUIRED_APPROVAL_FIELDS = (
    "schema",
    "approval_id",
    "proposal_id",
    "approver_role",
    "approved_by_human",
    "approved_at",
    "approved_scope",
    "approval_signature_or_hash",
    "no_ai_auto_approval",
)

SECRET_FIELD_MARKERS = (
    "password",
    "secret",
    "token",
    "cookie",
    "authorization",
    "api_key",
    "private_key",
    "credential",
)


@dataclass(frozen=True)
class ContractValidation:
    valid: bool
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "reason_codes": list(self.reason_codes)}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _missing_fields(payload: dict[str, Any], required: tuple[str, ...]) -> list[str]:
    return [field for field in required if payload.get(field) in ("", None)]


def _valid_confidence(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= float(value) <= 1


def _contains_raw_screenshot(payload: dict[str, Any]) -> bool:
    raw_keys = {
        "raw_screenshot",
        "raw_screenshot_payload",
        "screenshot_payload",
        "screenshot_bytes",
        "image_bytes",
        "base64_screenshot",
    }
    return any(key in payload and payload.get(key) not in ("", None, False) for key in raw_keys)


def validate_vision_observation(observation: dict[str, Any] | None) -> ContractValidation:
    reasons: list[str] = []
    if not isinstance(observation, dict):
        return ContractValidation(False, ("VISION_OBSERVATION_MISSING",))

    for field in _missing_fields(observation, REQUIRED_OBSERVATION_FIELDS):
        reasons.append(f"VISION_OBSERVATION_{field.upper()}_MISSING")

    if observation.get("schema") != OBSERVATION_SCHEMA:
        reasons.append("VISION_OBSERVATION_SCHEMA_INVALID")
    if observation.get("redaction_applied") is not True:
        reasons.append("VISION_OBSERVATION_REDACTION_REQUIRED")
    if observation.get("raw_screenshot_logged") is not False:
        reasons.append("VISION_OBSERVATION_RAW_SCREENSHOT_LOGGED")
    if _contains_raw_screenshot(observation):
        reasons.append("VISION_OBSERVATION_RAW_SCREENSHOT_PAYLOAD_BLOCKED")
    if not isinstance(observation.get("detected_ui_elements"), list):
        reasons.append("VISION_OBSERVATION_UI_ELEMENTS_INVALID")
    if not isinstance(observation.get("errors"), list):
        reasons.append("VISION_OBSERVATION_ERRORS_INVALID")
    if not _valid_confidence(observation.get("confidence")):
        reasons.append("VISION_OBSERVATION_CONFIDENCE_INVALID")
    if _parse_timestamp(observation.get("generated_at")) is None:
        reasons.append("VISION_OBSERVATION_GENERATED_AT_INVALID")

    return ContractValidation(not reasons, tuple(sorted(set(reasons))))


def validate_action_proposal(proposal: dict[str, Any] | None) -> ContractValidation:
    reasons: list[str] = []
    if not isinstance(proposal, dict):
        return ContractValidation(False, ("VISION_PROPOSAL_MISSING",))

    for field in _missing_fields(proposal, REQUIRED_PROPOSAL_FIELDS):
        reasons.append(f"VISION_PROPOSAL_{field.upper()}_MISSING")

    action_type = str(proposal.get("action_type", ""))
    if proposal.get("schema") != ACTION_PROPOSAL_SCHEMA:
        reasons.append("VISION_PROPOSAL_SCHEMA_INVALID")
    if not _valid_confidence(proposal.get("confidence")):
        reasons.append("VISION_PROPOSAL_CONFIDENCE_INVALID")
    if not isinstance(proposal.get("parameters"), dict):
        reasons.append("VISION_PROPOSAL_PARAMETERS_INVALID")
    if not isinstance(proposal.get("requires_human_approval"), bool):
        reasons.append("VISION_PROPOSAL_HUMAN_APPROVAL_FLAG_INVALID")
    if _parse_timestamp(proposal.get("created_at")) is None:
        reasons.append("VISION_PROPOSAL_CREATED_AT_INVALID")
    if action_type in BLOCKED_ACTION_TYPES:
        reasons.append(f"VISION_PROPOSAL_ACTION_BLOCKED:{action_type}")
    elif action_type not in ALLOWED_PREVIEW_ACTION_TYPES:
        reasons.append(f"VISION_PROPOSAL_ACTION_UNKNOWN:{action_type or 'MISSING'}")

    return ContractValidation(not reasons, tuple(sorted(set(reasons))))


def validate_vision_human_approval(
    approval: dict[str, Any] | None,
    *,
    proposal: dict[str, Any] | None,
    expected_scope: str = "REVIEW_ONLY",
    now: datetime | None = None,
    max_age_hours: float = 24.0,
) -> ContractValidation:
    reasons: list[str] = []
    if not isinstance(approval, dict):
        return ContractValidation(False, ("VISION_APPROVAL_MISSING",))
    if not isinstance(proposal, dict):
        return ContractValidation(False, ("VISION_APPROVAL_PROPOSAL_MISSING",))

    for field in _missing_fields(approval, REQUIRED_APPROVAL_FIELDS):
        reasons.append(f"VISION_APPROVAL_{field.upper()}_MISSING")

    approver_role = str(approval.get("approver_role", "")).strip()
    if approval.get("schema") != HUMAN_APPROVAL_SCHEMA:
        reasons.append("VISION_APPROVAL_SCHEMA_INVALID")
    if approval.get("proposal_id") != proposal.get("proposal_id"):
        reasons.append("VISION_APPROVAL_PROPOSAL_MISMATCH")
    if not approver_role:
        reasons.append("VISION_APPROVAL_APPROVER_EMPTY")
    if approver_role.lower() in AI_APPROVER_IDENTITIES:
        reasons.append("VISION_APPROVAL_AI_APPROVER_BLOCKED")
    if approval.get("approved_by_human") is not True:
        reasons.append("VISION_APPROVAL_HUMAN_REQUIRED")
    if approval.get("no_ai_auto_approval") is not True:
        reasons.append("VISION_APPROVAL_AI_AUTO_APPROVAL_BLOCKED")
    if str(approval.get("approved_scope", "")) != expected_scope:
        reasons.append("VISION_APPROVAL_SCOPE_MISMATCH")
    if str(approval.get("approved_scope", "")) not in REVIEW_ONLY_SCOPES:
        reasons.append("VISION_APPROVAL_SCOPE_NOT_REVIEW_ONLY")
    if not str(approval.get("approval_signature_or_hash", "")).strip():
        reasons.append("VISION_APPROVAL_SIGNATURE_OR_HASH_MISSING")

    approved_at = _parse_timestamp(approval.get("approved_at"))
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if approved_at is None:
        reasons.append("VISION_APPROVAL_APPROVED_AT_INVALID")
    else:
        age_hours = (effective_now - approved_at).total_seconds() / 3600
        if age_hours < 0 or age_hours > max_age_hours:
            reasons.append("VISION_APPROVAL_STALE")

    return ContractValidation(not reasons, tuple(sorted(set(reasons))))


def sanitize_for_vision_audit(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if key_text in {"raw_screenshot", "raw_screenshot_payload", "screenshot_payload"}:
                sanitized[key_text] = "REDACTED"
            elif any(marker in lowered for marker in SECRET_FIELD_MARKERS):
                sanitized[key_text] = "REDACTED"
            else:
                sanitized[key_text] = sanitize_for_vision_audit(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_for_vision_audit(item) for item in value]
    return value


def build_vision_audit_record(
    *,
    observation: dict[str, Any] | None,
    proposal: dict[str, Any] | None,
    decision: str,
    reason_codes: list[str] | tuple[str, ...],
    policy_version: str,
    runtime_state_hash: str,
    pbsec_state_hash: str,
    previous_audit_hash: str = "",
    generated_at: str,
) -> dict[str, Any]:
    safe_observation = observation if isinstance(observation, dict) else {}
    safe_proposal = proposal if isinstance(proposal, dict) else {}
    record = {
        "schema": AUDIT_RECORD_SCHEMA,
        "event_id": "",
        "observation_id": str(safe_observation.get("observation_id", "")),
        "proposal_id": str(safe_proposal.get("proposal_id", "")),
        "decision": str(decision),
        "reason_codes": sorted({str(code) for code in reason_codes if code}),
        "policy_version": str(policy_version),
        "runtime_state_hash": str(runtime_state_hash),
        "pbsec_state_hash": str(pbsec_state_hash),
        "screenshot_hash": str(safe_observation.get("screenshot_hash", "")),
        "previous_audit_hash": str(previous_audit_hash),
        "audit_hash": "",
        "generated_at": str(generated_at),
        "raw_screenshot_logged": False,
        "secrets_logged": False,
    }
    event_seed = {key: value for key, value in record.items() if key not in {"event_id", "audit_hash"}}
    record["event_id"] = sha256_json({"event": event_seed})
    record["audit_hash"] = sha256_json(record | {"audit_hash": ""})
    return record
