from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from connectors.connector_contracts import (
    ApprovalGate,
    AuthStatus,
    ConnectorState,
    approval_gate_for,
    validate_connector_event,
)
from orchestration.orchestration_contracts import validate_orchestration_event


APPROVAL_GATE_CONTRACT_VERSION = "pb313-approval-gate-mapping-v1"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class ApprovalState(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


class HumanReviewStep(str, Enum):
    REQUEST_REVIEW = "REQUEST_REVIEW"
    VERIFY_POLICY_DECISION = "VERIFY_POLICY_DECISION"
    VERIFY_APPROVAL_EVIDENCE = "VERIFY_APPROVAL_EVIDENCE"
    RECORD_HUMAN_DECISION = "RECORD_HUMAN_DECISION"
    LINK_AUDIT_EVIDENCE = "LINK_AUDIT_EVIDENCE"


@dataclass(frozen=True)
class ApprovalIdentifier:
    approval_id: str
    approval_gate: ApprovalGate
    requested_action_hash: str
    policy_hash: str
    audit_hash: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["approval_gate"] = self.approval_gate.value
        return payload


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    approval_gate: ApprovalGate
    approval_state: ApprovalState
    actor_hash: str
    reviewer_hash: str
    requested_action_hash: str
    policy_hash: str
    evidence_hash: str
    created_at: str
    expires_at: str
    audit_hash: str
    human_review_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["approval_gate"] = self.approval_gate.value
        payload["approval_state"] = self.approval_state.value
        payload["contract_version"] = APPROVAL_GATE_CONTRACT_VERSION
        return payload


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sha256_payload(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value.lower())


def _parse_utc_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime(TIMESTAMP_FORMAT)


def approval_gate_for_orchestration_event(event: dict[str, Any]) -> ApprovalGate | None:
    source_system = str(event.get("source_system", ""))
    requested_action = str(event.get("requested_action", ""))
    if source_system == "Executive Report":
        return ApprovalGate.EXECUTIVE_REPORT_EXTERNAL_SHARE
    if source_system == "USBAY Intake":
        return ApprovalGate.NOTION_CASE_WRITE
    if source_system == "USBAY Control Plane":
        return None
    return approval_gate_for(source_system, requested_action)


def build_approval_identifier(event: dict[str, Any]) -> dict[str, Any]:
    gate = approval_gate_for_orchestration_event(event)
    if gate is None:
        return {
            "contract_version": APPROVAL_GATE_CONTRACT_VERSION,
            "decision": "FAIL_CLOSED",
            "gaps": ["APPROVAL_GATE_MISSING"],
        }
    requested_action_hash = sha256_payload(str(event.get("requested_action", "")))
    policy_hash = str(event.get("policy_hash", ""))
    audit_hash = str(event.get("audit_hash", ""))
    approval_id = "approval_" + sha256_payload(
        {
            "approval_gate": gate.value,
            "requested_action_hash": requested_action_hash,
            "policy_hash": policy_hash,
            "audit_hash": audit_hash,
        }
    )[:32]
    return ApprovalIdentifier(
        approval_id=approval_id,
        approval_gate=gate,
        requested_action_hash=requested_action_hash,
        policy_hash=policy_hash,
        audit_hash=audit_hash,
    ).to_dict()


def approval_record_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "USBAY Approval Gate Record",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "contract_version",
            "approval_id",
            "approval_gate",
            "approval_state",
            "actor_hash",
            "reviewer_hash",
            "requested_action_hash",
            "policy_hash",
            "evidence_hash",
            "created_at",
            "expires_at",
            "audit_hash",
            "human_review_required",
        ],
        "properties": {
            "contract_version": {"type": "string", "const": APPROVAL_GATE_CONTRACT_VERSION},
            "approval_id": {"type": "string", "pattern": "^approval_[0-9a-f]{32}$"},
            "approval_gate": {"type": "string", "enum": [gate.value for gate in ApprovalGate]},
            "approval_state": {"type": "string", "enum": [state.value for state in ApprovalState]},
            "actor_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "reviewer_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "requested_action_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "policy_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "evidence_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "created_at": {"type": "string", "minLength": 1},
            "expires_at": {"type": "string", "minLength": 1},
            "audit_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "human_review_required": {"type": "boolean", "const": True},
        },
    }


def human_review_workflow() -> dict[str, Any]:
    return {
        "contract_version": APPROVAL_GATE_CONTRACT_VERSION,
        "steps": [step.value for step in HumanReviewStep],
        "requires_explicit_human_decision": True,
        "auto_approval_allowed": False,
        "missing_review_outcome": "FAIL_CLOSED",
        "raw_approval_contents_allowed": False,
    }


def build_approval_record(
    event: dict[str, Any],
    *,
    approval_state: ApprovalState,
    actor: str,
    reviewer: str,
    created_at: str,
    expires_at: str,
    evidence_hash: str,
) -> dict[str, Any]:
    identifier = build_approval_identifier(event)
    if identifier.get("decision") == "FAIL_CLOSED":
        return identifier
    actor_hash = sha256_payload(actor)
    reviewer_hash = sha256_payload(reviewer)
    audit_payload = {
        "approval_id": identifier["approval_id"],
        "approval_gate": identifier["approval_gate"],
        "approval_state": approval_state.value,
        "actor_hash": actor_hash,
        "reviewer_hash": reviewer_hash,
        "requested_action_hash": identifier["requested_action_hash"],
        "policy_hash": identifier["policy_hash"],
        "evidence_hash": evidence_hash,
        "created_at": created_at,
        "expires_at": expires_at,
    }
    return ApprovalRecord(
        approval_id=identifier["approval_id"],
        approval_gate=ApprovalGate(identifier["approval_gate"]),
        approval_state=approval_state,
        actor_hash=actor_hash,
        reviewer_hash=reviewer_hash,
        requested_action_hash=identifier["requested_action_hash"],
        policy_hash=identifier["policy_hash"],
        evidence_hash=evidence_hash,
        created_at=created_at,
        expires_at=expires_at,
        audit_hash=sha256_payload(audit_payload),
    ).to_dict()


def validate_approval_gate_mapping(
    *,
    orchestration_event: dict[str, Any],
    connector_event: dict[str, Any],
    approval_record: dict[str, Any] | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    gaps: list[str] = []
    orchestration_validation = validate_orchestration_event(orchestration_event)
    connector_validation = validate_connector_event(connector_event)
    if orchestration_validation.get("decision") != "VERIFIED":
        gaps.append("ORCHESTRATION_EVENT_INVALID")
    if connector_validation.get("decision") != "VERIFIED":
        gaps.append("CONNECTOR_EVENT_INVALID")

    expected_identifier = build_approval_identifier(orchestration_event)
    if expected_identifier.get("decision") == "FAIL_CLOSED":
        gaps.extend(expected_identifier.get("gaps", []))
    expected_gate = expected_identifier.get("approval_gate")
    expected_approval_id = expected_identifier.get("approval_id")

    if not isinstance(approval_record, dict):
        gaps.append("APPROVAL_RECORD_MISSING")
        approval_record = {}
    if connector_event.get("approval_gate") != expected_gate:
        gaps.append("APPROVAL_GATE_MISMATCH")
    if connector_event.get("approval_id") != approval_record.get("approval_id"):
        gaps.append("CONNECTOR_APPROVAL_LINK_MISMATCH")
    if approval_record.get("approval_id") != expected_approval_id:
        gaps.append("APPROVAL_ID_MISMATCH")
    if approval_record.get("approval_gate") != expected_gate:
        gaps.append("APPROVAL_GATE_MISMATCH")
    if approval_record.get("approval_state") != ApprovalState.APPROVED.value:
        gaps.append("APPROVAL_NOT_APPROVED")
    if approval_record.get("human_review_required") is not True:
        gaps.append("HUMAN_REVIEW_REQUIRED")
    if not _is_sha256(approval_record.get("actor_hash")):
        gaps.append("ACTOR_HASH_MISSING")
    if not _is_sha256(approval_record.get("reviewer_hash")):
        gaps.append("REVIEWER_HASH_MISSING")
    if approval_record.get("requested_action_hash") != expected_identifier.get("requested_action_hash"):
        gaps.append("REQUESTED_ACTION_HASH_MISMATCH")
    if approval_record.get("policy_hash") != orchestration_event.get("policy_hash"):
        gaps.append("POLICY_HASH_MISMATCH")
    if not _is_sha256(approval_record.get("evidence_hash")):
        gaps.append("APPROVAL_EVIDENCE_MISSING")
    if not _is_sha256(approval_record.get("audit_hash")):
        gaps.append("APPROVAL_AUDIT_MISSING")

    expires_at = _parse_utc_timestamp(approval_record.get("expires_at"))
    if expires_at is None:
        gaps.append("APPROVAL_EXPIRATION_MALFORMED")
    elif expires_at <= (now or datetime.now(timezone.utc)):
        gaps.append("APPROVAL_EXPIRED")
    if _parse_utc_timestamp(approval_record.get("created_at")) is None:
        gaps.append("APPROVAL_CREATED_AT_MALFORMED")

    if connector_event.get("connector_state") != ConnectorState.AVAILABLE.value:
        gaps.append("CONNECTOR_NOT_AVAILABLE")
    if connector_event.get("auth_status") != AuthStatus.VALID.value:
        gaps.append("CONNECTOR_AUTH_NOT_VALID")
    if connector_event.get("policy_decision") != "ALLOW" or orchestration_event.get("policy_decision") != "ALLOW":
        gaps.append("POLICY_NOT_ALLOW")
    if orchestration_event.get("audit_evidence_present") is not True or connector_event.get("audit_evidence_present") is not True:
        gaps.append("AUDIT_EVIDENCE_MISSING")

    decision = "VERIFIED" if not gaps else "FAIL_CLOSED"
    return {
        "contract_version": APPROVAL_GATE_CONTRACT_VERSION,
        "decision": decision,
        "execution_status": "PENDING_HUMAN_APPROVAL_VERIFIED" if decision == "VERIFIED" else "BLOCKED",
        "gaps": sorted(set(gaps)),
        "approval_id": expected_approval_id if decision == "VERIFIED" else None,
        "approval_gate": expected_gate,
        "human_review_workflow": human_review_workflow(),
        "validated_at": _format_utc(now or datetime.now(timezone.utc)),
        "external_calls_performed": False,
    }


def example_approval_gate_mapping() -> dict[str, Any]:
    now = datetime(2026, 6, 13, tzinfo=timezone.utc)
    expires = datetime(2026, 6, 14, tzinfo=timezone.utc)
    event = {
        "event_id": "orch_evt_pb313_example",
        "event_type": "github_work_item_write_proposed",
        "source_system": "GitHub",
        "actor": "operator:local",
        "requested_action": "create_governed_github_issue_proposal",
        "risk_level": "HIGH",
        "required_human_approval": True,
        "approval_id": "approval_placeholder",
        "policy_hash": sha256_payload({"policy": "pb313", "version": APPROVAL_GATE_CONTRACT_VERSION}),
        "policy_decision": "ALLOW",
        "audit_hash": sha256_payload({"audit": "pb313-orchestration"}),
        "execution_status": "PENDING_HUMAN_APPROVAL",
        "connector_available": True,
        "audit_evidence_present": True,
        "sensitive_data_logged": False,
        "external_execution_requested": False,
        "log_metadata": {},
    }
    approval = build_approval_record(
        event,
        approval_state=ApprovalState.APPROVED,
        actor="operator:local",
        reviewer="human:reviewer",
        created_at=_format_utc(now),
        expires_at=_format_utc(expires),
        evidence_hash=sha256_payload({"evidence": "pb313-approval"}),
    )
    event["approval_id"] = approval["approval_id"]
    connector_event = {
        "contract_version": "pb312-connector-contract-layer-v1",
        "connector": "GitHub",
        "connector_type": "WRITE",
        "connector_state": "AVAILABLE",
        "auth_status": "VALID",
        "event_type": "github_work_item_write_proposed",
        "requested_action_hash": approval["requested_action_hash"],
        "policy_hash": event["policy_hash"],
        "policy_decision": "ALLOW",
        "audit_hash": sha256_payload({"audit": "pb313-connector"}),
        "execution_status": "BLOCKED",
        "approval_gate": approval["approval_gate"],
        "approval_id": approval["approval_id"],
        "audit_evidence_present": True,
        "sensitive_data_detected": False,
        "metadata": {},
    }
    return {
        "orchestration_event": event,
        "connector_event": connector_event,
        "approval_record": approval,
    }
