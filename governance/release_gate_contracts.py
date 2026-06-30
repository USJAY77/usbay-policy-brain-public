from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json


RELEASE_REQUEST_SCHEMA = "usbay.release.request.v1"
RELEASE_APPROVAL_SCHEMA = "usbay.release.approval.v1"
RELEASE_READINESS_SCHEMA = "usbay.release.readiness.v1"
RELEASE_DECISION_SCHEMA = "usbay.release.decision.v1"
RELEASE_AUDIT_RECORD_SCHEMA = "usbay.release.audit_record.v1"
RELEASE_GATE_POLICY_VERSION = "usbay.pb-release-gate.governed-release-control.v1"

ALLOWED_RELEASE_TYPES = frozenset({"PATCH", "MINOR", "MAJOR", "HOTFIX", "ROLLBACK_PLAN_ONLY"})
ALLOWED_TARGET_ENVIRONMENTS = frozenset({"STAGING", "PRODUCTION", "DRY_RUN", "ROLLBACK_PLAN"})
REQUIRED_RELEASE_FIELDS = (
    "release_id",
    "release_name",
    "release_type",
    "target_environment",
    "policy_version",
    "policy_hash",
    "evidence_hash",
    "audit_registry_hash",
    "release_manifest_hash",
    "requested_by",
    "approved_by",
    "created_at",
    "approved_at",
    "decision",
    "reason_codes",
    "fail_closed",
)


@dataclass(frozen=True)
class ReleaseValidation:
    valid: bool
    status: str
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "status": self.status, "reason_codes": list(self.reason_codes)}


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def missing_fields(payload: dict[str, Any], required: tuple[str, ...] = REQUIRED_RELEASE_FIELDS) -> list[str]:
    return [field for field in required if payload.get(field) in ("", None)]


def validate_release_request(request: dict[str, Any] | None) -> ReleaseValidation:
    if not isinstance(request, dict):
        return ReleaseValidation(False, "BLOCKED", ("RELEASE_REQUEST_MALFORMED",))
    reasons: list[str] = []
    if request.get("schema") != RELEASE_REQUEST_SCHEMA:
        reasons.append("RELEASE_REQUEST_SCHEMA_INVALID")
    for field in missing_fields(request):
        if field in {"approved_by", "approved_at"} and request.get("decision") in {"REVIEW_REQUIRED", "BLOCKED"}:
            continue
        reasons.append(f"RELEASE_{field.upper()}_MISSING")
    release_type = str(request.get("release_type", ""))
    if release_type not in ALLOWED_RELEASE_TYPES:
        reasons.append(f"RELEASE_TYPE_UNKNOWN:{release_type or 'MISSING'}")
    target = str(request.get("target_environment", ""))
    if target not in ALLOWED_TARGET_ENVIRONMENTS:
        reasons.append(f"RELEASE_TARGET_ENVIRONMENT_INVALID:{target or 'MISSING'}")
    if parse_timestamp(request.get("created_at")) is None:
        reasons.append("RELEASE_CREATED_AT_INVALID")
    if request.get("approved_at") and parse_timestamp(request.get("approved_at")) is None:
        reasons.append("RELEASE_APPROVED_AT_INVALID")
    if not isinstance(request.get("reason_codes"), list):
        reasons.append("RELEASE_REASON_CODES_MALFORMED")
    return ReleaseValidation(not reasons, "BLOCKED" if reasons else "VERIFIED", tuple(sorted(set(reasons))))


def build_release_audit_record(*, release: dict[str, Any] | None, action: str, reason_codes: list[str] | tuple[str, ...]) -> dict[str, Any]:
    safe = release if isinstance(release, dict) else {}
    record = {
        "schema": RELEASE_AUDIT_RECORD_SCHEMA,
        "release_id": str(safe.get("release_id", "")),
        "release_type": str(safe.get("release_type", "")),
        "target_environment": str(safe.get("target_environment", "")),
        "action": str(action),
        "decision": str(safe.get("decision", "BLOCKED")),
        "reason_codes": sorted(str(code) for code in reason_codes if code),
        "policy_version": str(safe.get("policy_version", RELEASE_GATE_POLICY_VERSION)),
        "audit_hash": "",
        "deploy_enabled": False,
        "publish_enabled": False,
        "rollback_enabled": False,
        "auto_promoted": False,
        "auto_approved": False,
    }
    record["audit_hash"] = sha256_json(record | {"audit_hash": ""})
    return record
