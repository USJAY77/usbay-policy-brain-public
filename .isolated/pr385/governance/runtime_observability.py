from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from governance.observation_contracts import OBSERVATION_POLICY_VERSION, validate_health, validate_snapshot


OBSERVABLE_COMPONENTS = (
    "Policy Brain",
    "Gateway",
    "Evidence",
    "Metrics",
    "Work",
    "Operator Queue",
    "Connector Registry",
)
HEALTHY = "HEALTHY"
WARNING = "WARNING"
BLOCKED = "BLOCKED"
UNKNOWN = "UNKNOWN"
ALLOWED_HEALTH_STATES = frozenset({HEALTHY, WARNING, BLOCKED, UNKNOWN})


def _now_text(now: datetime | None = None) -> str:
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return effective_now.isoformat().replace("+00:00", "Z")


def evaluate_component_health(component: str, health: dict[str, Any] | None) -> tuple[str, tuple[str, ...]]:
    reasons: list[str] = []
    if component not in OBSERVABLE_COMPONENTS:
        reasons.append(f"OBSERVATION_COMPONENT_UNKNOWN:{component or 'MISSING'}")
    validation = validate_health(health)
    if not validation.valid:
        reasons.extend(validation.reason_codes)
    status = str(health.get("status", UNKNOWN) if isinstance(health, dict) else UNKNOWN)
    if status not in ALLOWED_HEALTH_STATES:
        reasons.append(f"OBSERVATION_STATUS_UNKNOWN:{status or 'MISSING'}")
        status = BLOCKED
    if status == UNKNOWN:
        reasons.append(f"OBSERVATION_COMPONENT_UNKNOWN_STATE:{component}")
        status = BLOCKED
    if not isinstance(health, dict) or not str(health.get("audit_hash", "")).strip():
        reasons.append(f"OBSERVATION_COMPONENT_AUDIT_MISSING:{component}")
        status = BLOCKED
    if not isinstance(health, dict) or not str(health.get("lineage_hash", "")).strip():
        reasons.append(f"OBSERVATION_COMPONENT_LINEAGE_MISSING:{component}")
        status = BLOCKED
    if reasons and status == HEALTHY:
        status = BLOCKED
    return status, tuple(sorted(set(reasons)))


def build_runtime_health_snapshot(*, component_health: dict[str, dict[str, Any]] | None = None, now: datetime | None = None) -> dict[str, Any]:
    health_inputs = component_health if isinstance(component_health, dict) else {}
    component_states: dict[str, str] = {}
    reason_codes: list[str] = []
    for component in OBSERVABLE_COMPONENTS:
        state, reasons = evaluate_component_health(component, health_inputs.get(component))
        component_states[component] = state
        reason_codes.extend(reasons)
    if any(state == BLOCKED for state in component_states.values()):
        runtime_health = BLOCKED
    elif any(state == WARNING for state in component_states.values()):
        runtime_health = WARNING
    else:
        runtime_health = HEALTHY
    return {
        "schema": "usbay.observation.runtime_health.v1",
        "runtime_health": runtime_health,
        "component_health": component_states,
        "last_observation": _now_text(now),
        "observation_count": len(component_states),
        "policy_version": OBSERVATION_POLICY_VERSION,
        "fail_closed": runtime_health != HEALTHY,
        "reason_codes": sorted(set(reason_codes)) or ([] if runtime_health == HEALTHY else ["OBSERVATION_BLOCKED"]),
        "execution_enabled": False,
        "deployment_enabled": False,
        "auto_healed": False,
        "auto_fixed": False,
        "auto_corrected": False,
        "auto_executed": False,
        "auto_deployed": False,
    }


def evaluate_observation_snapshot(snapshot: dict[str, Any] | None) -> tuple[str, tuple[str, ...]]:
    validation = validate_snapshot(snapshot)
    if not validation.valid:
        return BLOCKED, validation.reason_codes
    status = str(snapshot.get("status", UNKNOWN))
    if status == UNKNOWN:
        return BLOCKED, ("OBSERVATION_STATUS_BLOCKED:UNKNOWN",)
    if status == BLOCKED:
        return BLOCKED, ("OBSERVATION_STATUS_BLOCKED:BLOCKED",)
    return status, ()


def empty_runtime_observation_dashboard_state() -> dict[str, Any]:
    state = build_runtime_health_snapshot()
    state["event_timeline_status"] = BLOCKED
    state["drift_status"] = BLOCKED
    state["timeline_event_count"] = 0
    state["latest_event_type"] = ""
    state["reason_codes"] = sorted(set(state["reason_codes"] + ["OBSERVATION_EVENTS_MISSING", "DRIFT_BASELINE_MISSING"]))
    return state
