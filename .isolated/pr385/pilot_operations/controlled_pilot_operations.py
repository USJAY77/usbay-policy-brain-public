from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


PILOT_OPERATIONS_VERSION = "pb271-275-controlled-end-to-end-pilot-operations-v1"
DEFAULT_POLICY_HASH = "88d1aaa62bbe011c9f51d7f159a7526a2fe283b94314e8c9b9cce73b199f04d1"
APPROVED_OPERATOR_IDS = frozenset({"pilot-operator-usbay-governance-001"})
APPROVED_DEVICE_IDS = frozenset({"pilot-device-mac-local-001"})
MONITORED_FAILURE_TYPES = (
    "approval_failure",
    "nonce_failure",
    "replay_failure",
    "audit_failure",
    "device_failure",
)
REQUIRED_PRIOR_EVIDENCE = (
    "pb241_245",
    "pb246_250",
    "pb251_255",
    "pb256_260",
    "pb261_265",
    "pb266_270",
)


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sha256_json(data: Any) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def pilot_operator_registry_contract_json() -> dict[str, Any]:
    operators = [
        {
            "operator_id": "pilot-operator-usbay-governance-001",
            "role": "pilot_governance_operator",
            "approval_scope": "GitHub -> USBAY Gateway -> Human Approval -> Codex -> Mac -> Terminal dry-run review",
            "state": "READ_ONLY",
            "activation_allowed": False,
        }
    ]
    return {
        "contract_version": PILOT_OPERATIONS_VERSION,
        "control": "PB-271 Pilot Operator Registry",
        "default_state": "BLOCKED",
        "unknown_operator_outcome": "BLOCKED",
        "operators": operators,
        "operator_registry_hash": sha256_json(operators),
        "production_activation_allowed": False,
        "external_calls_allowed": False,
    }


def validate_pilot_operator(operator_id: str | None) -> dict[str, Any]:
    gaps: list[str] = []
    if not operator_id:
        gaps.append("MISSING_OPERATOR")
    elif operator_id not in APPROVED_OPERATOR_IDS:
        gaps.append("UNKNOWN_OPERATOR")
    return {
        "decision": "VERIFIED" if not gaps else "BLOCKED",
        "state": "READ_ONLY" if not gaps else "BLOCKED",
        "gaps": gaps,
        "contract_version": PILOT_OPERATIONS_VERSION,
    }


def pilot_device_registry_contract_json() -> dict[str, Any]:
    devices = [
        {
            "device_id": "pilot-device-mac-local-001",
            "device_class": "mac_local_controlled_pilot",
            "allowed_modes": ["READ_ONLY", "DRY_RUN"],
            "state": "READ_ONLY",
            "desktop_execution_allowed": False,
        }
    ]
    return {
        "contract_version": PILOT_OPERATIONS_VERSION,
        "control": "PB-272 Pilot Device Registry",
        "default_state": "BLOCKED",
        "unknown_device_outcome": "BLOCKED",
        "devices": devices,
        "device_registry_hash": sha256_json(devices),
        "production_activation_allowed": False,
        "external_calls_allowed": False,
    }


def validate_pilot_device(device_id: str | None) -> dict[str, Any]:
    gaps: list[str] = []
    if not device_id:
        gaps.append("MISSING_DEVICE")
    elif device_id not in APPROVED_DEVICE_IDS:
        gaps.append("UNKNOWN_DEVICE")
    return {
        "decision": "VERIFIED" if not gaps else "BLOCKED",
        "state": "READ_ONLY" if not gaps else "BLOCKED",
        "gaps": gaps,
        "contract_version": PILOT_OPERATIONS_VERSION,
    }


def pilot_runtime_monitoring_contract_json() -> dict[str, Any]:
    return {
        "contract_version": PILOT_OPERATIONS_VERSION,
        "control": "PB-273 Pilot Runtime Monitoring",
        "default_state": "BLOCKED",
        "runtime_mode": "DRY_RUN",
        "monitored_failure_types": list(MONITORED_FAILURE_TYPES),
        "failure_outcome": "BLOCKED",
        "kill_switch_required_on_failure": True,
        "production_activation_allowed": False,
        "connector_activation_allowed": False,
        "external_calls_allowed": False,
    }


def classify_monitoring_event(event: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(event, dict):
        return {
            "decision": "BLOCKED",
            "gaps": ["MALFORMED_MONITORING_EVENT"],
            "contract_version": PILOT_OPERATIONS_VERSION,
        }
    failure_type = event.get("failure_type")
    if failure_type not in MONITORED_FAILURE_TYPES:
        return {
            "decision": "BLOCKED",
            "gaps": ["UNKNOWN_FAILURE_TYPE"],
            "contract_version": PILOT_OPERATIONS_VERSION,
        }
    evidence = {
        "failure_type": failure_type,
        "policy_hash": event.get("policy_hash"),
        "event_hash": event.get("event_hash"),
    }
    gaps: list[str] = []
    if event.get("policy_hash") != DEFAULT_POLICY_HASH:
        gaps.append("UNKNOWN_POLICY_HASH")
    if not isinstance(event.get("event_hash"), str) or not event.get("event_hash"):
        gaps.append("MISSING_EVENT_HASH")
    return {
        "decision": "BLOCKED",
        "failure_type": failure_type,
        "gaps": gaps,
        "monitoring_evidence_hash": sha256_json(evidence),
        "contract_version": PILOT_OPERATIONS_VERSION,
    }


def pilot_incident_response_playbook_json() -> dict[str, Any]:
    return {
        "contract_version": PILOT_OPERATIONS_VERSION,
        "control": "PB-274 Pilot Incident Response",
        "default_state": "BLOCKED",
        "kill_switch_activation_flow": [
            "classify_failure",
            "block_pilot_operations",
            "record_incident_hash",
            "notify_human_operator",
            "preserve_evidence"
        ],
        "recovery_flow": [
            "human_review_required",
            "verify_policy_hash",
            "verify_operator",
            "verify_device",
            "verify_nonce_and_replay_state",
            "append_recovery_evidence",
            "remain_blocked_until_new_approval"
        ],
        "evidence_requirements": [
            "incident_id",
            "failure_type",
            "policy_hash",
            "operator_id",
            "device_id",
            "audit_hash",
            "kill_switch_state",
            "timestamp"
        ],
        "production_activation_allowed": False,
        "external_calls_allowed": False,
    }


def evaluate_incident_response(incident: dict[str, Any] | None) -> dict[str, Any]:
    required = (
        "incident_id",
        "failure_type",
        "policy_hash",
        "operator_id",
        "device_id",
        "audit_hash",
        "kill_switch_state",
        "timestamp",
    )
    gaps: list[str] = []
    if not isinstance(incident, dict):
        return {
            "decision": "BLOCKED",
            "gaps": ["MALFORMED_INCIDENT"],
            "contract_version": PILOT_OPERATIONS_VERSION,
        }
    for field in required:
        if not isinstance(incident.get(field), str) or not incident.get(field):
            gaps.append(f"MISSING_{field.upper()}")
    if incident.get("failure_type") not in MONITORED_FAILURE_TYPES:
        gaps.append("UNKNOWN_FAILURE_TYPE")
    if incident.get("kill_switch_state") != "ENABLED_BLOCKING":
        gaps.append("KILL_SWITCH_NOT_BLOCKING")
    return {
        "decision": "READY_FOR_REVIEW" if not gaps else "BLOCKED",
        "gaps": sorted(set(gaps)),
        "incident_evidence_hash": sha256_json(incident),
        "contract_version": PILOT_OPERATIONS_VERSION,
    }


def pilot_readiness_checklist_json() -> dict[str, Any]:
    return {
        "contract_version": PILOT_OPERATIONS_VERSION,
        "control": "PB-275 Pilot Readiness Certification",
        "default_state": "BLOCKED",
        "required_prior_evidence": list(REQUIRED_PRIOR_EVIDENCE),
        "required_current_controls": [
            "approved_operator_registry",
            "approved_device_registry",
            "runtime_monitoring_contract",
            "incident_response_playbook",
            "readiness_certification"
        ],
        "readiness_conditions": [
            "read_only_default",
            "dry_run_default",
            "no_production_activation",
            "no_connector_activation",
            "no_browser_automation",
            "no_desktop_automation",
            "no_terminal_write_execution",
            "no_external_api_calls"
        ],
        "certification_state": "READY_FOR_REVIEW",
        "activation_execution_allowed": False,
    }


def certify_pilot_readiness(evidence_root: str | Path) -> dict[str, Any]:
    root = Path(evidence_root)
    gaps = [f"MISSING_EVIDENCE_{name.upper()}" for name in REQUIRED_PRIOR_EVIDENCE if not (root / name).is_dir()]
    checks = {
        "read_only_default": True,
        "dry_run_default": True,
        "no_production_activation": True,
        "no_connector_activation": True,
        "no_browser_automation": True,
        "no_desktop_automation": True,
        "no_terminal_write_execution": True,
        "no_external_api_calls": True,
    }
    return {
        "decision": "VERIFIED" if not gaps and all(checks.values()) else "FAIL_CLOSED",
        "status": "READY_FOR_REVIEW" if not gaps and all(checks.values()) else "REVIEW_REQUIRED",
        "gaps": gaps,
        "verified_prior_evidence": [name for name in REQUIRED_PRIOR_EVIDENCE if (root / name).is_dir()],
        "checks": checks,
        "activation_execution_allowed": False,
        "contract_version": PILOT_OPERATIONS_VERSION,
    }
