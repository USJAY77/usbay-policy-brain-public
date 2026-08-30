from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import sha256_json


OBSERVATION_SNAPSHOT_SCHEMA = "usbay.observation.snapshot.v1"
OBSERVATION_HEALTH_SCHEMA = "usbay.observation.health.v1"
OBSERVATION_EVENT_SCHEMA = "usbay.observation.event.v1"
OBSERVATION_TIMELINE_SCHEMA = "usbay.observation.timeline.v1"
OBSERVATION_AUDIT_RECORD_SCHEMA = "usbay.observation.audit_record.v1"
OBSERVATION_POLICY_VERSION = "usbay.pb-observability.governed-runtime-observation.v1"

ALLOWED_OBSERVATION_STATUSES = frozenset({"HEALTHY", "WARNING", "BLOCKED", "UNKNOWN"})
BLOCKING_OBSERVATION_STATUSES = frozenset({"BLOCKED", "UNKNOWN"})
ALLOWED_EVENT_TYPES = frozenset(
    {
        "observation",
        "proposal",
        "request",
        "approval",
        "review",
        "decision",
        "work item",
        "connector read",
        "evidence verification",
    }
)

REQUIRED_OBSERVATION_FIELDS = (
    "snapshot_id",
    "event_id",
    "component",
    "status",
    "timestamp",
    "policy_version",
    "audit_hash",
    "lineage_hash",
    "fail_closed",
    "reason_codes",
)


@dataclass(frozen=True)
class ObservationValidation:
    valid: bool
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "reason_codes": list(self.reason_codes)}


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


def _missing_fields(payload: dict[str, Any], required: tuple[str, ...]) -> list[str]:
    return [field for field in required if payload.get(field) in ("", None)]


def _validate_common(payload: dict[str, Any] | None, *, expected_schema: str) -> list[str]:
    if not isinstance(payload, dict):
        return ["OBSERVATION_PAYLOAD_MALFORMED"]
    reasons: list[str] = []
    for field in _missing_fields(payload, REQUIRED_OBSERVATION_FIELDS):
        reasons.append(f"OBSERVATION_{field.upper()}_MISSING")
    if payload.get("schema") != expected_schema:
        reasons.append("OBSERVATION_SCHEMA_INVALID")
    status = str(payload.get("status", ""))
    if status not in ALLOWED_OBSERVATION_STATUSES:
        reasons.append(f"OBSERVATION_STATUS_UNKNOWN:{status or 'MISSING'}")
    if status in BLOCKING_OBSERVATION_STATUSES:
        reasons.append(f"OBSERVATION_STATUS_BLOCKED:{status}")
    if parse_timestamp(payload.get("timestamp")) is None:
        reasons.append("OBSERVATION_TIMESTAMP_MISSING_OR_INVALID")
    if not str(payload.get("audit_hash", "")).strip():
        reasons.append("OBSERVATION_AUDIT_HASH_MISSING")
    if not str(payload.get("lineage_hash", "")).strip():
        reasons.append("OBSERVATION_LINEAGE_HASH_MISSING")
    if not str(payload.get("policy_version", "")).strip():
        reasons.append("OBSERVATION_POLICY_VERSION_MISSING")
    if not isinstance(payload.get("reason_codes"), list):
        reasons.append("OBSERVATION_REASON_CODES_MALFORMED")
    return reasons


def validate_snapshot(snapshot: dict[str, Any] | None) -> ObservationValidation:
    reasons = _validate_common(snapshot, expected_schema=OBSERVATION_SNAPSHOT_SCHEMA)
    return ObservationValidation(not reasons, tuple(sorted(set(reasons))))


def validate_health(health: dict[str, Any] | None) -> ObservationValidation:
    reasons = _validate_common(health, expected_schema=OBSERVATION_HEALTH_SCHEMA)
    return ObservationValidation(not reasons, tuple(sorted(set(reasons))))


def validate_event(event: dict[str, Any] | None) -> ObservationValidation:
    reasons = _validate_common(event, expected_schema=OBSERVATION_EVENT_SCHEMA)
    if isinstance(event, dict):
        event_type = str(event.get("event_type", ""))
        if event_type not in ALLOWED_EVENT_TYPES:
            reasons.append(f"OBSERVATION_EVENT_TYPE_UNKNOWN:{event_type or 'MISSING'}")
    return ObservationValidation(not reasons, tuple(sorted(set(reasons))))


def validate_timeline(timeline: dict[str, Any] | None) -> ObservationValidation:
    if not isinstance(timeline, dict):
        return ObservationValidation(False, ("OBSERVATION_TIMELINE_MALFORMED",))
    reasons: list[str] = []
    if timeline.get("schema") != OBSERVATION_TIMELINE_SCHEMA:
        reasons.append("OBSERVATION_TIMELINE_SCHEMA_INVALID")
    events = timeline.get("events")
    if not isinstance(events, list):
        reasons.append("OBSERVATION_TIMELINE_EVENTS_MALFORMED")
        events = []
    for index, event in enumerate(events):
        validation = validate_event(event)
        if not validation.valid:
            reasons.extend(f"EVENT_{index}_{code}" for code in validation.reason_codes)
    if any(parse_timestamp(event.get("timestamp")) is None for event in events if isinstance(event, dict)):
        reasons.append("OBSERVATION_TIMELINE_TIMESTAMP_MISSING")
    return ObservationValidation(not reasons, tuple(sorted(set(reasons))))


def build_observation_audit_record(*, payload: dict[str, Any] | None, decision: str, reason_codes: list[str] | tuple[str, ...]) -> dict[str, Any]:
    safe = payload if isinstance(payload, dict) else {}
    record = {
        "schema": OBSERVATION_AUDIT_RECORD_SCHEMA,
        "snapshot_id": str(safe.get("snapshot_id", "")),
        "event_id": str(safe.get("event_id", "")),
        "component": str(safe.get("component", "")),
        "status": str(safe.get("status", "BLOCKED")),
        "decision": str(decision),
        "timestamp": str(safe.get("timestamp", "")),
        "policy_version": str(safe.get("policy_version", OBSERVATION_POLICY_VERSION)),
        "lineage_hash": str(safe.get("lineage_hash", "")),
        "reason_codes": sorted({str(code) for code in reason_codes if code}),
        "fail_closed": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "auto_remediation_enabled": False,
        "audit_hash": "",
    }
    record["audit_hash"] = sha256_json(record | {"audit_hash": ""})
    return record
