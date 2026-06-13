from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


RUNTIME_MONITORING_VERSION = "pb223-runtime-monitoring-incident-response-v1"


class MonitoringEventType(str, Enum):
    GATEWAY_ERROR = "gateway_error"
    POLICY_FAIL = "policy_fail"
    APPROVAL_EXPIRED = "approval_expired"
    CONNECTOR_BLOCKED = "connector_blocked"
    AUDIT_WRITE_FAILED = "audit_write_failed"


@dataclass(frozen=True)
class MonitoringEvent:
    event_type: MonitoringEventType
    actor: str
    policy_hash: str
    status: str = "BLOCKED"
    evidence_hash: str = "UNAVAILABLE"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["event_type"] = self.event_type.value
        payload["contract_version"] = RUNTIME_MONITORING_VERSION
        return payload


def runtime_monitoring_contract_json() -> dict[str, Any]:
    return {
        "contract_version": RUNTIME_MONITORING_VERSION,
        "events": [event.value for event in MonitoringEventType],
        "unsafe_state_outcome": "BLOCKED",
        "incident_response_required": True,
        "external_calls_allowed": False,
    }


def evaluate_monitoring_event(event: MonitoringEvent | dict[str, Any]) -> dict[str, Any]:
    try:
        payload = event.to_dict() if isinstance(event, MonitoringEvent) else dict(event)
        event_type = str(payload.get("event_type", ""))
        if event_type not in {item.value for item in MonitoringEventType}:
            return {"decision": "BLOCKED", "gaps": ["UNKNOWN_MONITORING_EVENT"], "status": "BLOCKED"}
        if payload.get("status") != "RESOLVED":
            return {
                "decision": "BLOCKED",
                "gaps": ["UNSAFE_STATE"],
                "status": "BLOCKED",
                "event_type": event_type,
                "contract_version": RUNTIME_MONITORING_VERSION,
            }
        return {
            "decision": "VERIFIED",
            "gaps": [],
            "status": "RESOLVED",
            "event_type": event_type,
            "contract_version": RUNTIME_MONITORING_VERSION,
        }
    except Exception:
        return {"decision": "BLOCKED", "gaps": ["MONITORING_EVENT_MALFORMED"], "status": "BLOCKED"}
