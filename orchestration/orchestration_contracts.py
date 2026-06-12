from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


ORCHESTRATION_CONTRACT_VERSION = "pb310-usbay-orchestration-contract-v1"

TARGET_FLOW = (
    "LinkedIn",
    "USBAY Intake",
    "Notion",
    "Euria",
    "USBAY Control Plane",
    "GitHub",
    "Codex",
    "Evidence Layer",
    "Executive Report",
)

SOURCE_SYSTEMS = frozenset(TARGET_FLOW)
RISK_LEVELS = frozenset(("LOW", "MEDIUM", "HIGH", "CRITICAL"))
POLICY_DECISIONS = frozenset(("ALLOW", "DENY", "BLOCK", "FAIL_CLOSED"))
EXECUTION_STATUSES = frozenset(("BLOCKED", "DRY_RUN_READY", "PENDING_HUMAN_APPROVAL", "EVIDENCE_READY"))
SENSITIVE_MARKERS = frozenset(
    (
        "authorization",
        "api_key",
        "credential",
        "customer_data",
        "password",
        "personal_data",
        "private_key",
        "raw_payload",
        "secret",
        "token",
    )
)

REQUIRED_EVENT_FIELDS = (
    "event_type",
    "source_system",
    "actor",
    "requested_action",
    "risk_level",
    "required_human_approval",
    "policy_hash",
    "policy_decision",
    "audit_hash",
    "execution_status",
)

REQUIRED_AUDIT_FIELDS = (
    "event_id",
    "event_type",
    "source_system",
    "actor_hash",
    "requested_action_hash",
    "risk_level",
    "policy_hash",
    "policy_decision",
    "execution_status",
    "audit_hash",
    "timestamp",
)

APPROVAL_CHECKPOINTS = (
    "LINKEDIN_PUBLIC_ACTION",
    "NOTION_CASE_WRITE",
    "EURIA_PROJECT_WRITE",
    "GITHUB_WORK_ITEM_WRITE",
    "CODEX_EXECUTION_PROPOSAL",
    "EXECUTIVE_REPORT_EXTERNAL_SHARE",
)


class ContractDecision(str, Enum):
    VERIFIED = "VERIFIED"
    FAIL_CLOSED = "FAIL_CLOSED"


@dataclass(frozen=True)
class OrchestrationEvent:
    event_type: str
    source_system: str
    actor: str
    requested_action: str
    risk_level: str
    required_human_approval: bool
    policy_hash: str
    policy_decision: str
    audit_hash: str
    execution_status: str
    event_id: str = "orch_evt_local_contract"
    approval_id: str | None = None
    connector_available: bool = True
    audit_evidence_present: bool = True
    sensitive_data_logged: bool = False
    external_execution_requested: bool = False
    log_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sha256_payload(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value.lower())


def _contains_sensitive_marker(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_sensitive_marker(key) or _contains_sensitive_marker(item) for key, item in value.items())
    if isinstance(value, list | tuple | set):
        return any(_contains_sensitive_marker(item) for item in value)
    if isinstance(value, str):
        normalized = value.lower()
        return any(marker in normalized for marker in SENSITIVE_MARKERS)
    return False


def orchestration_contract_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "USBAY Orchestration Event Contract",
        "type": "object",
        "additionalProperties": False,
        "required": list(REQUIRED_EVENT_FIELDS),
        "properties": {
            "event_id": {"type": "string", "minLength": 1},
            "event_type": {"type": "string", "minLength": 1},
            "source_system": {"type": "string", "enum": list(TARGET_FLOW)},
            "actor": {"type": "string", "minLength": 1},
            "requested_action": {"type": "string", "minLength": 1},
            "risk_level": {"type": "string", "enum": sorted(RISK_LEVELS)},
            "required_human_approval": {"type": "boolean"},
            "approval_id": {"type": ["string", "null"]},
            "policy_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "policy_decision": {"type": "string", "enum": sorted(POLICY_DECISIONS)},
            "audit_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "execution_status": {"type": "string", "enum": sorted(EXECUTION_STATUSES)},
            "connector_available": {"type": "boolean"},
            "audit_evidence_present": {"type": "boolean"},
            "sensitive_data_logged": {"type": "boolean"},
            "external_execution_requested": {"type": "boolean"},
            "log_metadata": {"type": "object"},
        },
    }


def audit_evidence_contract_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "USBAY Orchestration Audit Evidence Contract",
        "type": "object",
        "additionalProperties": False,
        "required": list(REQUIRED_AUDIT_FIELDS),
        "properties": {
            "event_id": {"type": "string", "minLength": 1},
            "event_type": {"type": "string", "minLength": 1},
            "source_system": {"type": "string", "enum": list(TARGET_FLOW)},
            "actor_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "requested_action_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "risk_level": {"type": "string", "enum": sorted(RISK_LEVELS)},
            "policy_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "policy_decision": {"type": "string", "enum": sorted(POLICY_DECISIONS)},
            "execution_status": {"type": "string", "enum": sorted(EXECUTION_STATUSES)},
            "audit_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "timestamp": {"type": "string", "minLength": 1},
        },
    }


def approval_checkpoints_contract() -> dict[str, Any]:
    return {
        "contract_version": ORCHESTRATION_CONTRACT_VERSION,
        "approval_checkpoints": list(APPROVAL_CHECKPOINTS),
        "non_read_actions_require_human_approval": True,
        "high_and_critical_risk_require_human_approval": True,
        "external_sharing_requires_human_approval": True,
        "missing_approval_outcome": ContractDecision.FAIL_CLOSED.value,
    }


def audit_evidence_contract() -> dict[str, Any]:
    return {
        "contract_version": ORCHESTRATION_CONTRACT_VERSION,
        "required_fields": list(REQUIRED_AUDIT_FIELDS),
        "raw_payloads_allowed": False,
        "sensitive_data_allowed": False,
        "hash_only_actor_and_action": True,
        "missing_audit_outcome": ContractDecision.FAIL_CLOSED.value,
        "schema": audit_evidence_contract_schema(),
    }


def example_orchestration_event() -> dict[str, Any]:
    event = OrchestrationEvent(
        event_id="orch_evt_pb310_example",
        event_type="linkedin_lead_intake",
        source_system="LinkedIn",
        actor="operator:local",
        requested_action="create_governed_case",
        risk_level="HIGH",
        required_human_approval=True,
        approval_id="approval_pb310_example",
        policy_hash=sha256_payload({"policy": "pb310", "version": ORCHESTRATION_CONTRACT_VERSION}),
        policy_decision="ALLOW",
        audit_hash=sha256_payload({"audit": "pb310-example"}),
        execution_status="DRY_RUN_READY",
    )
    return event.to_dict()


def validate_orchestration_event(event: dict[str, Any]) -> dict[str, Any]:
    gaps: list[str] = []
    for field_name in REQUIRED_EVENT_FIELDS:
        if field_name not in event:
            gaps.append(f"MISSING_{field_name.upper()}")

    source_system = str(event.get("source_system", ""))
    if source_system not in SOURCE_SYSTEMS:
        gaps.append("UNKNOWN_SOURCE_SYSTEM")
    if event.get("connector_available") is False:
        gaps.append("CONNECTOR_MISSING")
    if str(event.get("risk_level", "")) not in RISK_LEVELS:
        gaps.append("UNKNOWN_RISK_LEVEL")
    if str(event.get("policy_decision", "")) not in POLICY_DECISIONS:
        gaps.append("UNKNOWN_POLICY_DECISION")
    if str(event.get("execution_status", "")) not in EXECUTION_STATUSES:
        gaps.append("UNKNOWN_EXECUTION_STATUS")
    if not _is_sha256(event.get("policy_hash")):
        gaps.append("POLICY_HASH_MISSING_OR_MALFORMED")
    if not _is_sha256(event.get("audit_hash")):
        gaps.append("AUDIT_HASH_MISSING_OR_MALFORMED")
    if event.get("audit_evidence_present") is False:
        gaps.append("AUDIT_EVIDENCE_MISSING")
    if event.get("required_human_approval") is True and not event.get("approval_id"):
        gaps.append("HUMAN_APPROVAL_REQUIRED")
    if str(event.get("risk_level", "")) in {"HIGH", "CRITICAL"} and not event.get("approval_id"):
        gaps.append("HUMAN_APPROVAL_REQUIRED")
    if str(event.get("risk_level", "")) == "CRITICAL":
        gaps.append("CRITICAL_RISK_BLOCKED")
    if str(event.get("policy_decision", "")) != "ALLOW":
        gaps.append("POLICY_NOT_ALLOW")
    if event.get("external_execution_requested") is True:
        gaps.append("EXTERNAL_EXECUTION_FORBIDDEN")
    if event.get("sensitive_data_logged") is True or _contains_sensitive_marker(event.get("log_metadata", {})):
        gaps.append("SENSITIVE_DATA_IN_LOGS")

    decision = ContractDecision.VERIFIED if not gaps else ContractDecision.FAIL_CLOSED
    execution_status = str(event.get("execution_status", "UNKNOWN"))
    if decision == ContractDecision.FAIL_CLOSED:
        execution_status = "BLOCKED"
    evidence = {
        "contract_version": ORCHESTRATION_CONTRACT_VERSION,
        "decision": decision.value,
        "execution_status": execution_status,
        "gaps": sorted(set(gaps)),
        "required_human_approval": bool(event.get("required_human_approval")),
        "external_execution_performed": False,
        "sensitive_data_logged": False if "SENSITIVE_DATA_IN_LOGS" not in gaps else True,
    }
    evidence["validation_hash"] = sha256_payload(evidence)
    return evidence


def build_audit_evidence(event: dict[str, Any], *, timestamp: str) -> dict[str, Any]:
    validation = validate_orchestration_event(event)
    if validation["decision"] != ContractDecision.VERIFIED.value:
        return {
            "contract_version": ORCHESTRATION_CONTRACT_VERSION,
            "decision": ContractDecision.FAIL_CLOSED.value,
            "gaps": validation["gaps"],
            "audit_evidence_created": False,
        }
    evidence = {
        "event_id": str(event.get("event_id", "")),
        "event_type": str(event["event_type"]),
        "source_system": str(event["source_system"]),
        "actor_hash": sha256_payload(str(event["actor"])),
        "requested_action_hash": sha256_payload(str(event["requested_action"])),
        "risk_level": str(event["risk_level"]),
        "policy_hash": str(event["policy_hash"]),
        "policy_decision": str(event["policy_decision"]),
        "execution_status": str(event["execution_status"]),
        "timestamp": timestamp,
    }
    evidence["audit_hash"] = sha256_payload(evidence)
    return evidence
