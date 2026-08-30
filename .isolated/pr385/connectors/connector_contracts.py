from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


CONNECTOR_CONTRACT_VERSION = "pb213-connector-governance-gates-v1"
PB312_CONNECTOR_CONTRACT_VERSION = "pb312-connector-contract-layer-v1"
PB355_CONNECTOR_CONTRACT_VERSION = "pb355-connector-contract-program-v1"
ACTION_APPROVED_DRY_RUN = "APPROVED_DRY_RUN"
ACTION_BLOCKED = "BLOCKED"
STATUS_READY_FOR_REVIEW = "READY_FOR_REVIEW"
STATUS_FAIL_CLOSED = "FAIL_CLOSED"

CONNECTOR_NAMES = ("LinkedIn", "Notion", "Euria", "GitHub", "Codex")
CONNECTOR_SYSTEMS = (
    "LinkedIn",
    "Notion",
    "Euria",
    "USBAY Control Plane",
    "GitHub",
    "Codex",
    "Evidence Layer",
)

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


class GovernedConnectorState(str, Enum):
    DISABLED = "DISABLED"
    DRY_RUN = "DRY_RUN"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
    BLOCKED = "BLOCKED"


class ConnectorType(str, Enum):
    READ_ONLY = "READ_ONLY"
    PROPOSAL = "PROPOSAL"
    WRITE = "WRITE"
    EXECUTION = "EXECUTION"


class ConnectorState(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    AUTH_INVALID = "AUTH_INVALID"
    AUTH_UNKNOWN = "AUTH_UNKNOWN"
    FAIL_CLOSED = "FAIL_CLOSED"


class ApprovalGate(str, Enum):
    LINKEDIN_PUBLIC_ACTION = "LINKEDIN_PUBLIC_ACTION"
    NOTION_CASE_WRITE = "NOTION_CASE_WRITE"
    EURIA_PROJECT_WRITE = "EURIA_PROJECT_WRITE"
    GITHUB_WORK_ITEM_WRITE = "GITHUB_WORK_ITEM_WRITE"
    CODEX_EXECUTION_PROPOSAL = "CODEX_EXECUTION_PROPOSAL"
    EXECUTIVE_REPORT_EXTERNAL_SHARE = "EXECUTIVE_REPORT_EXTERNAL_SHARE"


class AuthStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    UNKNOWN = "UNKNOWN"


class SensitiveDataPolicy(str, Enum):
    HASH_ONLY = "HASH_ONLY"
    REDACTED_METADATA_ONLY = "REDACTED_METADATA_ONLY"
    RAW_DATA_FORBIDDEN = "RAW_DATA_FORBIDDEN"


@dataclass(frozen=True)
class ConnectorAvailability:
    connector: str
    state: ConnectorState = ConnectorState.FAIL_CLOSED
    auth_status: AuthStatus = AuthStatus.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["state"] = self.state.value
        payload["auth_status"] = self.auth_status.value
        return payload


@dataclass(frozen=True)
class ConnectorContract:
    name: str
    state: GovernedConnectorState = GovernedConnectorState.DISABLED
    live_activation_allowed: bool = False
    external_calls_allowed: bool = False
    requires_human_approval: bool = True
    evidence_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        data["contract_version"] = CONNECTOR_CONTRACT_VERSION
        return data


@dataclass(frozen=True)
class ConnectorEvent:
    connector: str
    connector_type: ConnectorType
    connector_state: ConnectorState
    auth_status: AuthStatus
    event_type: str
    requested_action_hash: str
    policy_hash: str
    policy_decision: str
    audit_hash: str
    execution_status: str = "BLOCKED"
    approval_gate: ApprovalGate | None = None
    approval_id: str | None = None
    audit_evidence_present: bool = True
    sensitive_data_detected: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["connector_type"] = self.connector_type.value
        payload["connector_state"] = self.connector_state.value
        payload["auth_status"] = self.auth_status.value
        payload["approval_gate"] = self.approval_gate.value if self.approval_gate else None
        payload["contract_version"] = PB312_CONNECTOR_CONTRACT_VERSION
        return payload


APPROVAL_GATE_BY_CONNECTOR = {
    "LinkedIn": ApprovalGate.LINKEDIN_PUBLIC_ACTION,
    "Notion": ApprovalGate.NOTION_CASE_WRITE,
    "Euria": ApprovalGate.EURIA_PROJECT_WRITE,
    "GitHub": ApprovalGate.GITHUB_WORK_ITEM_WRITE,
    "Codex": ApprovalGate.CODEX_EXECUTION_PROPOSAL,
    "Evidence Layer": ApprovalGate.EXECUTIVE_REPORT_EXTERNAL_SHARE,
}

READ_ONLY_CONNECTORS = frozenset(("LinkedIn", "USBAY Control Plane", "Evidence Layer"))
PROPOSAL_CONNECTORS = frozenset(("Notion", "Euria", "GitHub", "Codex", "Evidence Layer"))
WRITE_CONNECTORS = frozenset(("Notion", "Euria", "GitHub"))
EXECUTION_CONNECTORS = frozenset(("Codex",))


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sha256_payload(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value.lower())


def _contains_sensitive_marker(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_sensitive_marker(key) or _contains_sensitive_marker(item) for key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_sensitive_marker(item) for item in value)
    if isinstance(value, str):
        normalized = value.lower()
        return any(marker in normalized for marker in SENSITIVE_MARKERS)
    return False


def default_connector_contracts() -> dict[str, ConnectorContract]:
    return {name: ConnectorContract(name=name) for name in CONNECTOR_NAMES}


def connector_contracts_json() -> dict[str, Any]:
    return {
        "contract_version": CONNECTOR_CONTRACT_VERSION,
        "production_activation_allowed": False,
        "external_calls_allowed": False,
        "connectors": {name: contract.to_dict() for name, contract in default_connector_contracts().items()},
    }


def transition_connector_state(
    contract: ConnectorContract,
    requested_state: GovernedConnectorState,
    *,
    human_approved: bool = False,
) -> ConnectorContract:
    if requested_state == GovernedConnectorState.DISABLED:
        return ConnectorContract(name=contract.name)
    if requested_state == GovernedConnectorState.DRY_RUN:
        return ConnectorContract(name=contract.name, state=GovernedConnectorState.DRY_RUN)
    if requested_state == GovernedConnectorState.HUMAN_APPROVAL_REQUIRED:
        return ConnectorContract(name=contract.name, state=GovernedConnectorState.HUMAN_APPROVAL_REQUIRED)
    if requested_state == GovernedConnectorState.BLOCKED:
        return ConnectorContract(name=contract.name, state=GovernedConnectorState.BLOCKED)
    return ConnectorContract(name=contract.name, state=GovernedConnectorState.BLOCKED)


def connector_event_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "USBAY Connector Event Evidence",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "contract_version",
            "connector",
            "connector_type",
            "connector_state",
            "auth_status",
            "event_type",
            "requested_action_hash",
            "policy_hash",
            "policy_decision",
            "audit_hash",
            "execution_status",
            "audit_evidence_present",
        ],
        "properties": {
            "contract_version": {"type": "string", "const": PB312_CONNECTOR_CONTRACT_VERSION},
            "connector": {"type": "string", "enum": list(CONNECTOR_SYSTEMS)},
            "connector_type": {"type": "string", "enum": [item.value for item in ConnectorType]},
            "connector_state": {"type": "string", "enum": [item.value for item in ConnectorState]},
            "auth_status": {"type": "string", "enum": [item.value for item in AuthStatus]},
            "event_type": {"type": "string", "minLength": 1},
            "requested_action_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "policy_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "policy_decision": {"type": "string", "enum": ["ALLOW", "DENY", "BLOCK", "FAIL_CLOSED"]},
            "audit_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "execution_status": {"type": "string", "enum": ["BLOCKED", "DRY_RUN_READY", "PENDING_HUMAN_APPROVAL", "EVIDENCE_READY"]},
            "approval_gate": {"type": ["string", "null"], "enum": [item.value for item in ApprovalGate] + [None]},
            "approval_id": {"type": ["string", "null"]},
            "audit_evidence_present": {"type": "boolean"},
            "sensitive_data_detected": {"type": "boolean"},
            "metadata": {"type": "object"},
        },
    }


def approval_record_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "USBAY Connector Approval Record",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "approval_id",
            "approval_gate",
            "actor_hash",
            "requested_action_hash",
            "policy_hash",
            "status",
            "expires_at",
            "audit_hash",
        ],
        "properties": {
            "approval_id": {"type": "string", "minLength": 1},
            "approval_gate": {"type": "string", "enum": [item.value for item in ApprovalGate]},
            "actor_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "requested_action_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "policy_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "status": {"type": "string", "enum": ["PENDING", "APPROVED", "REJECTED", "EXPIRED", "BLOCKED"]},
            "expires_at": {"type": "string", "minLength": 1},
            "audit_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
        },
    }


def execution_proposal_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "USBAY Connector Execution Proposal",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "proposal_id",
            "connector",
            "approval_gate",
            "requested_action_hash",
            "policy_hash",
            "risk_level",
            "execution_status",
            "audit_hash",
        ],
        "properties": {
            "proposal_id": {"type": "string", "minLength": 1},
            "connector": {"type": "string", "enum": list(CONNECTOR_SYSTEMS)},
            "approval_gate": {"type": "string", "enum": [item.value for item in ApprovalGate]},
            "requested_action_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "policy_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
            "risk_level": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
            "execution_status": {"type": "string", "enum": ["BLOCKED", "PENDING_HUMAN_APPROVAL", "DRY_RUN_READY"]},
            "audit_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
        },
    }


def connector_evidence_schemas() -> dict[str, Any]:
    return {
        "contract_version": PB312_CONNECTOR_CONTRACT_VERSION,
        "artifacts": {
            "connector_event.json": connector_event_schema(),
            "approval_record.json": approval_record_schema(),
            "execution_proposal.json": execution_proposal_schema(),
        },
        "raw_payloads_allowed": False,
        "sensitive_data_allowed": False,
        "external_calls_allowed": False,
    }


def connector_type_for(connector: str, requested_action: str) -> ConnectorType:
    action = requested_action.lower()
    if connector in EXECUTION_CONNECTORS or "execute" in action:
        return ConnectorType.EXECUTION
    if "write" in action or "create" in action or "share" in action:
        if connector in WRITE_CONNECTORS:
            return ConnectorType.WRITE
        return ConnectorType.PROPOSAL
    if connector in PROPOSAL_CONNECTORS and "proposal" in action:
        return ConnectorType.PROPOSAL
    return ConnectorType.READ_ONLY


def approval_gate_for(connector: str, requested_action: str) -> ApprovalGate | None:
    connector_type = connector_type_for(connector, requested_action)
    if connector_type == ConnectorType.READ_ONLY:
        return None
    return APPROVAL_GATE_BY_CONNECTOR.get(connector)


def build_connector_event(
    *,
    connector: str,
    event_type: str,
    requested_action: str,
    policy_hash: str,
    policy_decision: str,
    audit_hash: str,
    connector_state: ConnectorState = ConnectorState.FAIL_CLOSED,
    auth_status: AuthStatus = AuthStatus.UNKNOWN,
    approval_id: str | None = None,
    audit_evidence_present: bool = True,
    sensitive_data_detected: bool = False,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    connector_type = connector_type_for(connector, requested_action)
    approval_gate = approval_gate_for(connector, requested_action)
    event = ConnectorEvent(
        connector=connector,
        connector_type=connector_type,
        connector_state=connector_state,
        auth_status=auth_status,
        event_type=event_type,
        requested_action_hash=sha256_payload(requested_action),
        policy_hash=policy_hash,
        policy_decision=policy_decision,
        audit_hash=audit_hash,
        execution_status="BLOCKED",
        approval_gate=approval_gate,
        approval_id=approval_id,
        audit_evidence_present=audit_evidence_present,
        sensitive_data_detected=sensitive_data_detected,
        metadata=metadata or {},
    )
    return event.to_dict()


def validate_connector_event(event: dict[str, Any]) -> dict[str, Any]:
    gaps: list[str] = []
    if event.get("connector") not in CONNECTOR_SYSTEMS:
        gaps.append("UNKNOWN_CONNECTOR")
    if event.get("connector_type") not in {item.value for item in ConnectorType}:
        gaps.append("UNKNOWN_CONNECTOR_TYPE")
    if event.get("connector_state") != ConnectorState.AVAILABLE.value:
        if event.get("connector_state") in {ConnectorState.UNAVAILABLE.value, ConnectorState.FAIL_CLOSED.value}:
            gaps.append("CONNECTOR_UNAVAILABLE")
        elif event.get("connector_state") == ConnectorState.AUTH_INVALID.value:
            gaps.append("AUTH_INVALID")
        elif event.get("connector_state") == ConnectorState.AUTH_UNKNOWN.value:
            gaps.append("AUTH_UNKNOWN")
        else:
            gaps.append("UNKNOWN_CONNECTOR_STATE")
    if event.get("auth_status") != AuthStatus.VALID.value:
        if event.get("auth_status") == AuthStatus.INVALID.value:
            gaps.append("AUTH_INVALID")
        else:
            gaps.append("AUTH_UNKNOWN")
    for field_name in ("event_type", "requested_action_hash", "policy_hash", "audit_hash", "policy_decision"):
        if field_name not in event or event.get(field_name) in (None, ""):
            gaps.append(f"MISSING_{field_name.upper()}")
    if not _is_sha256(event.get("requested_action_hash")):
        gaps.append("REQUESTED_ACTION_HASH_MALFORMED")
    if not _is_sha256(event.get("policy_hash")):
        gaps.append("POLICY_HASH_MALFORMED")
    if not _is_sha256(event.get("audit_hash")):
        gaps.append("AUDIT_HASH_MALFORMED")
    if event.get("policy_decision") != "ALLOW":
        gaps.append("POLICY_DENY")
    if event.get("audit_evidence_present") is not True:
        gaps.append("AUDIT_EVIDENCE_MISSING")
    if event.get("connector_type") in {ConnectorType.PROPOSAL.value, ConnectorType.WRITE.value, ConnectorType.EXECUTION.value}:
        if not event.get("approval_gate") or not event.get("approval_id"):
            gaps.append("APPROVAL_MISSING")
    metadata = event.get("metadata", {})
    if not isinstance(metadata, dict):
        gaps.append("METADATA_MALFORMED")
        metadata = {}
    if event.get("sensitive_data_detected") is True or _contains_sensitive_marker(metadata):
        gaps.append("SENSITIVE_DATA_DETECTED")

    decision = "VERIFIED" if not gaps else "FAIL_CLOSED"
    return {
        "contract_version": PB312_CONNECTOR_CONTRACT_VERSION,
        "decision": decision,
        "execution_status": "DRY_RUN_READY" if decision == "VERIFIED" else "BLOCKED",
        "gaps": sorted(set(gaps)),
        "external_calls_performed": False,
        "sensitive_data_logged": False if "SENSITIVE_DATA_DETECTED" not in gaps else True,
        "validation_hash": sha256_payload(
            {
                "decision": decision,
                "gaps": sorted(set(gaps)),
                "connector": event.get("connector"),
                "requested_action_hash": event.get("requested_action_hash"),
            }
        ),
    }


def example_connector_event() -> dict[str, Any]:
    return build_connector_event(
        connector="GitHub",
        event_type="github_work_item_write_proposed",
        requested_action="create_governed_github_issue_proposal",
        policy_hash=sha256_payload({"policy": "pb312", "version": PB312_CONNECTOR_CONTRACT_VERSION}),
        policy_decision="ALLOW",
        audit_hash=sha256_payload({"audit": "pb312-example"}),
        connector_state=ConnectorState.AVAILABLE,
        auth_status=AuthStatus.VALID,
        approval_id="approval_pb312_example",
    )


@dataclass(frozen=True)
class ConnectorCapability:
    connector_id: str
    connector_version: str
    allowed_actions: tuple[str, ...]
    approval_required_actions: tuple[str, ...] = field(default_factory=tuple)
    dry_run_only: bool = True
    external_mutation_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "connector_id": self.connector_id,
            "connector_version": self.connector_version,
            "allowed_actions": list(self.allowed_actions),
            "approval_required_actions": list(self.approval_required_actions),
            "dry_run_only": self.dry_run_only,
            "external_mutation_allowed": self.external_mutation_allowed,
        }


@dataclass(frozen=True)
class ConnectorRequest:
    connector_id: str
    requested_action: str
    actor: str
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    policy_decision: str = "ALLOW"
    approval_evidence: dict[str, Any] | None = None
    audit_evidence: dict[str, Any] | None = None
    dry_run: bool = True
    connector_error: str | None = None

    def to_redacted_dict(self) -> dict[str, Any]:
        return {
            "connector_id": self.connector_id,
            "requested_action": self.requested_action,
            "actor": self.actor,
            "capabilities": list(self.capabilities),
            "policy_decision": self.policy_decision,
            "approval_evidence_hash": _evidence_hash_or_none(self.approval_evidence),
            "audit_evidence_hash": _evidence_hash_or_none(self.audit_evidence),
            "dry_run": self.dry_run,
            "connector_error_present": bool(self.connector_error),
        }


@dataclass(frozen=True)
class ConnectorDecision:
    decision: str
    status: str
    blockers: tuple[str, ...]
    audit_evidence: dict[str, Any]
    external_mutation_performed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": PB355_CONNECTOR_CONTRACT_VERSION,
            "decision": self.decision,
            "status": self.status,
            "blockers": list(self.blockers),
            "audit_evidence": self.audit_evidence,
            "external_mutation_performed": self.external_mutation_performed,
        }


def connector_capability_registry() -> dict[str, ConnectorCapability]:
    capabilities = (
        ConnectorCapability(
            connector_id="github",
            connector_version="github.connector.v1",
            allowed_actions=("prepare_pr", "read_checks", "request_review"),
            approval_required_actions=("prepare_pr", "request_review"),
        ),
        ConnectorCapability(
            connector_id="notion",
            connector_version="notion.connector.v1",
            allowed_actions=("prepare_page_update", "read_page_metadata"),
            approval_required_actions=("prepare_page_update",),
        ),
        ConnectorCapability(
            connector_id="linkedin",
            connector_version="linkedin.connector.v1",
            allowed_actions=("prepare_post", "read_public_profile"),
            approval_required_actions=("prepare_post",),
        ),
        ConnectorCapability(
            connector_id="email",
            connector_version="email.connector.v1",
            allowed_actions=("prepare_draft", "read_delivery_status"),
            approval_required_actions=("prepare_draft",),
        ),
        ConnectorCapability(
            connector_id="tasks",
            connector_version="tasks.connector.v1",
            allowed_actions=("prepare_task_update", "read_task_status"),
            approval_required_actions=("prepare_task_update",),
        ),
    )
    return {capability.connector_id: capability for capability in capabilities}


def policy_evaluation_hook(
    request: ConnectorRequest,
    registry: dict[str, ConnectorCapability] | None = None,
) -> tuple[str, ...]:
    blockers: list[str] = []
    capabilities = registry or connector_capability_registry()
    connector = capabilities.get(request.connector_id)
    if connector is None:
        blockers.append("unknown_connector")
        return tuple(blockers)
    if request.requested_action not in connector.allowed_actions:
        blockers.append("unsupported_action")
    if request.requested_action not in request.capabilities:
        blockers.append("missing_capability")
    if request.policy_decision != "ALLOW":
        blockers.append("policy_not_allow")
    if request.dry_run is not True:
        blockers.append("live_external_mutation_disabled")
    if request.connector_error:
        blockers.append("connector_failure")
    return tuple(blockers)


def approval_gate_hook(
    request: ConnectorRequest,
    registry: dict[str, ConnectorCapability] | None = None,
) -> tuple[str, ...]:
    connector = (registry or connector_capability_registry()).get(request.connector_id)
    if connector is None:
        return ("unknown_connector",)
    if request.requested_action not in connector.approval_required_actions:
        return ()
    approval = request.approval_evidence
    if not isinstance(approval, dict):
        return ("missing_approval",)
    if approval.get("status") != "APPROVED":
        return ("missing_approval",)
    if not _is_sha256(approval.get("evidence_hash")):
        return ("approval_evidence_hash_missing",)
    return ()


def audit_evidence_contract(request: ConnectorRequest, blockers: tuple[str, ...]) -> dict[str, Any]:
    audit = request.audit_evidence if isinstance(request.audit_evidence, dict) else {}
    evidence = {
        "schema": "usbay.connector_layer.audit_evidence.v1",
        "contract_version": PB355_CONNECTOR_CONTRACT_VERSION,
        "action_id": sha256_payload(request.to_redacted_dict()),
        "actor": request.actor,
        "connector": request.connector_id,
        "requested_action": request.requested_action,
        "policy_decision": request.policy_decision,
        "approval_state": _approval_state(request.approval_evidence),
        "blocked_reason": list(blockers),
        "outcome": ACTION_BLOCKED if blockers else ACTION_APPROVED_DRY_RUN,
        "external_mutation_performed": False,
        "raw_payload_logged": False,
        "source_audit_evidence_hash": _evidence_hash_or_none(audit),
    }
    evidence["evidence_hash"] = sha256_payload(evidence)
    return evidence


def evaluate_connector_request(
    request: ConnectorRequest,
    registry: dict[str, ConnectorCapability] | None = None,
) -> ConnectorDecision:
    blockers = list(policy_evaluation_hook(request, registry))
    blockers.extend(approval_gate_hook(request, registry))
    if not isinstance(request.audit_evidence, dict) or not _is_sha256(request.audit_evidence.get("evidence_hash")):
        blockers.append("missing_audit_evidence")
    unique_blockers = tuple(sorted(set(blockers)))
    evidence = audit_evidence_contract(request, unique_blockers)
    blocked = bool(unique_blockers)
    return ConnectorDecision(
        decision=ACTION_BLOCKED if blocked else ACTION_APPROVED_DRY_RUN,
        status=STATUS_FAIL_CLOSED if blocked else STATUS_READY_FOR_REVIEW,
        blockers=unique_blockers,
        audit_evidence=evidence,
        external_mutation_performed=False,
    )


def _evidence_hash_or_none(evidence: dict[str, Any] | None) -> str | None:
    if not isinstance(evidence, dict):
        return None
    value = evidence.get("evidence_hash")
    return value if _is_sha256(value) else None


def _approval_state(evidence: dict[str, Any] | None) -> str:
    if not isinstance(evidence, dict):
        return "MISSING"
    return str(evidence.get("status", "UNKNOWN"))
