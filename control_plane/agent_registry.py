from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


AGENT_REGISTRY_VERSION = "pb353-agent-registry-v1"


class AgentName(str, Enum):
    CODEX = "Codex Agent"
    RUNTIME = "Runtime Agent"
    HYDRA = "Hydra Agent"
    GOVERNANCE = "Governance Agent"
        usbay/pb-353a-euria-registry-extension
    EURIA = "EURIA"

        main


class AgentHealth(str, Enum):
    UNKNOWN = "UNKNOWN"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"


class ApprovalState(str, Enum):
    UNKNOWN = "UNKNOWN"
    NOT_REQUIRED = "NOT_REQUIRED"
    REQUIRED = "REQUIRED"
    APPROVED = "APPROVED"
    DENIED = "DENIED"


class AuditState(str, Enum):
    UNKNOWN = "UNKNOWN"
    EVIDENCE_READY = "EVIDENCE_READY"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"
    EVIDENCE_INVALID = "EVIDENCE_INVALID"


class RegistryDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCKED = "BLOCKED"


SUPPORTED_AGENTS = tuple(agent.value for agent in AgentName)
 usbay/pb-353a-euria-registry-extension
AGENT_CAPABILITY_MAP = {
    AgentName.CODEX.value: ("workspace_prepare",),
    AgentName.RUNTIME.value: ("runtime_status",),
    AgentName.HYDRA.value: ("consensus_status",),
    AgentName.GOVERNANCE.value: ("governance_review",),
    AgentName.EURIA.value: ("project_dispatch",),
}

 main


@dataclass(frozen=True)
class AgentRecord:
    name: str
    enabled: bool = False
    health: AgentHealth = AgentHealth.UNKNOWN
    approval_state: ApprovalState = ApprovalState.UNKNOWN
    audit_state: AuditState = AuditState.UNKNOWN
    registered_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["health"] = self.health.value
        payload["approval_state"] = self.approval_state.value
        payload["audit_state"] = self.audit_state.value
        payload["registry_version"] = AGENT_REGISTRY_VERSION
        return payload


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sha256_payload(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _coerce_health(value: str | AgentHealth) -> AgentHealth:
    try:
        return value if isinstance(value, AgentHealth) else AgentHealth(str(value))
    except ValueError as exc:
        raise ValueError("UNKNOWN_AGENT_HEALTH") from exc


def _coerce_approval(value: str | ApprovalState) -> ApprovalState:
    try:
        return value if isinstance(value, ApprovalState) else ApprovalState(str(value))
    except ValueError as exc:
        raise ValueError("UNKNOWN_APPROVAL_STATE") from exc


def _coerce_audit(value: str | AuditState) -> AuditState:
    try:
        return value if isinstance(value, AuditState) else AuditState(str(value))
    except ValueError as exc:
        raise ValueError("UNKNOWN_AUDIT_STATE") from exc


def _evidence(
    *,
    action: str,
    agent_name: str,
    actor: str,
    outcome: str,
    blocked_reason: list[str] | None = None,
    before: AgentRecord | None = None,
    after: AgentRecord | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    record = {
        "schema": "usbay.control_plane.agent_registry_evidence.v1",
        "registry_version": AGENT_REGISTRY_VERSION,
        "action": action,
        "agent": agent_name,
        "actor": actor,
        "timestamp": timestamp or _now_utc(),
        "outcome": outcome,
        "blocked_reason": blocked_reason or [],
        "before_hash": sha256_payload(before.to_dict()) if before else None,
        "after_hash": sha256_payload(after.to_dict()) if after else None,
    }
    record["evidence_hash"] = sha256_payload(record)
    return record


class AgentRegistry:
    def __init__(self, *, actor: str = "codex") -> None:
        self.actor = actor
        self._records: dict[str, AgentRecord] = {}
        self._audit_events: list[dict[str, Any]] = []

    @property
    def audit_events(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._audit_events)

    def _append_event(
        self,
        *,
        action: str,
        agent_name: str,
        outcome: str,
        blocked_reason: list[str] | None = None,
        before: AgentRecord | None = None,
        after: AgentRecord | None = None,
    ) -> dict[str, Any]:
        event = _evidence(
            action=action,
            agent_name=agent_name,
            actor=self.actor,
            outcome=outcome,
            blocked_reason=blocked_reason,
            before=before,
            after=after,
        )
        if not event.get("evidence_hash"):
            raise RuntimeError("AGENT_REGISTRY_AUDIT_EVIDENCE_MISSING")
        self._audit_events.append(event)
        return event

    def register(self, agent_name: str) -> dict[str, Any]:
        if agent_name not in SUPPORTED_AGENTS:
            event = self._append_event(
                action="register",
                agent_name=agent_name,
                outcome=RegistryDecision.BLOCKED.value,
                blocked_reason=["unknown_agent"],
            )
            return _result(RegistryDecision.BLOCKED, ["unknown_agent"], None, event)
        existing = self._records.get(agent_name)
        timestamp = _now_utc()
        record = AgentRecord(
            name=agent_name,
            enabled=False,
            health=AgentHealth.UNKNOWN,
            approval_state=ApprovalState.UNKNOWN,
            audit_state=AuditState.UNKNOWN,
            registered_at=existing.registered_at if existing else timestamp,
            updated_at=timestamp,
        )
        self._records[agent_name] = record
        event = self._append_event(
            action="register",
            agent_name=agent_name,
            outcome=RegistryDecision.ALLOW.value,
            before=existing,
            after=record,
        )
        return _result(RegistryDecision.ALLOW, [], record, event)

    def enable(self, agent_name: str) -> dict[str, Any]:
        record = self._records.get(agent_name)
        blocked = self._precondition_blockers(agent_name, require_enabled=False)
        if blocked:
            event = self._append_event(
                action="enable",
                agent_name=agent_name,
                outcome=RegistryDecision.BLOCKED.value,
                blocked_reason=blocked,
                before=record,
            )
            return _result(RegistryDecision.BLOCKED, blocked, record, event)
        assert record is not None
        after = AgentRecord(
            name=record.name,
            enabled=True,
            health=record.health,
            approval_state=record.approval_state,
            audit_state=record.audit_state,
            registered_at=record.registered_at,
            updated_at=_now_utc(),
        )
        self._records[agent_name] = after
        event = self._append_event(action="enable", agent_name=agent_name, outcome=RegistryDecision.ALLOW.value, before=record, after=after)
        return _result(RegistryDecision.ALLOW, [], after, event)

    def disable(self, agent_name: str) -> dict[str, Any]:
        record = self._records.get(agent_name)
        blocked = self._precondition_blockers(agent_name, require_enabled=False)
        if blocked:
            event = self._append_event(
                action="disable",
                agent_name=agent_name,
                outcome=RegistryDecision.BLOCKED.value,
                blocked_reason=blocked,
                before=record,
            )
            return _result(RegistryDecision.BLOCKED, blocked, record, event)
        assert record is not None
        after = AgentRecord(
            name=record.name,
            enabled=False,
            health=record.health,
            approval_state=record.approval_state,
            audit_state=record.audit_state,
            registered_at=record.registered_at,
            updated_at=_now_utc(),
        )
        self._records[agent_name] = after
        event = self._append_event(action="disable", agent_name=agent_name, outcome=RegistryDecision.ALLOW.value, before=record, after=after)
        return _result(RegistryDecision.ALLOW, [], after, event)

    def set_health(self, agent_name: str, health: str | AgentHealth) -> dict[str, Any]:
        record = self._records.get(agent_name)
        blocked = self._precondition_blockers(agent_name, require_enabled=False)
        if blocked:
            event = self._append_event(
                action="health",
                agent_name=agent_name,
                outcome=RegistryDecision.BLOCKED.value,
                blocked_reason=blocked,
                before=record,
            )
            return _result(RegistryDecision.BLOCKED, blocked, record, event)
        assert record is not None
        after = AgentRecord(
            name=record.name,
            enabled=record.enabled,
            health=_coerce_health(health),
            approval_state=record.approval_state,
            audit_state=record.audit_state,
            registered_at=record.registered_at,
            updated_at=_now_utc(),
        )
        self._records[agent_name] = after
        event = self._append_event(action="health", agent_name=agent_name, outcome=RegistryDecision.ALLOW.value, before=record, after=after)
        return _result(RegistryDecision.ALLOW, [], after, event)

    def set_approval_state(self, agent_name: str, approval_state: str | ApprovalState) -> dict[str, Any]:
        return self._update_approval_or_audit(agent_name, "approval_state", _coerce_approval(approval_state))

    def set_audit_state(self, agent_name: str, audit_state: str | AuditState) -> dict[str, Any]:
        return self._update_approval_or_audit(agent_name, "audit_state", _coerce_audit(audit_state))

        usbay/pb-353a-euria-registry-extension
    def decision_for(
        self,
        agent_name: str,
        *,
        requested_action: str | None = None,
        capabilities: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        return self._readiness_decision(
            agent_name,
            action="decision",
            requested_action=requested_action,
            capabilities=capabilities,
        )

    def project_dispatch(
        self,
        agent_name: str,
        *,
        project_id: str | None = None,
        capabilities: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        reasons = [] if project_id else ["project_dispatch_project_id_missing"]
        result = self._readiness_decision(
            agent_name,
            action="project_dispatch",
            extra_reasons=reasons,
            requested_action="project_dispatch",
            capabilities=capabilities,
        )
        return {
            **result,
            "project_dispatch": {
                "project_id_hash": sha256_payload(project_id) if project_id else None,
                "connector_execution_performed": False,
                "external_mutation_performed": False,
            },
        }

    def _readiness_decision(
        self,
        agent_name: str,
        *,
        action: str,
        extra_reasons: list[str] | None = None,
        requested_action: str | None = None,
        capabilities: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        record = self._records.get(agent_name)
        reasons = self._precondition_blockers(agent_name, require_enabled=True) + list(extra_reasons or [])

    def decision_for(self, agent_name: str) -> dict[str, Any]:
        record = self._records.get(agent_name)
        reasons = self._precondition_blockers(agent_name, require_enabled=True)
        main
        if record:
            if record.health != AgentHealth.HEALTHY:
                reasons.append("agent_unhealthy")
            if record.approval_state not in {ApprovalState.NOT_REQUIRED, ApprovalState.APPROVED}:
                reasons.append("agent_approval_not_ready")
            if record.audit_state != AuditState.EVIDENCE_READY:
                reasons.append("agent_audit_not_ready")
        usbay/pb-353a-euria-registry-extension
        reasons.extend(_capability_blockers(agent_name, requested_action, capabilities))
        decision = RegistryDecision.BLOCKED if reasons else RegistryDecision.ALLOW
        event = self._append_event(
            action=action,

        decision = RegistryDecision.BLOCKED if reasons else RegistryDecision.ALLOW
        event = self._append_event(
            action="decision",
          main
            agent_name=agent_name,
            outcome=decision.value,
            blocked_reason=sorted(set(reasons)),
            before=record,
            after=record,
        )
        return _result(decision, sorted(set(reasons)), record, event)

    def get(self, agent_name: str) -> AgentRecord | None:
        return self._records.get(agent_name)

    def _precondition_blockers(self, agent_name: str, *, require_enabled: bool) -> list[str]:
        if agent_name not in SUPPORTED_AGENTS:
            return ["unknown_agent"]
        record = self._records.get(agent_name)
        if record is None:
            return ["agent_not_registered"]
        if require_enabled and record.enabled is not True:
            return ["agent_disabled"]
        return []

    def _update_approval_or_audit(
        self,
        agent_name: str,
        field_name: str,
        value: ApprovalState | AuditState,
    ) -> dict[str, Any]:
        record = self._records.get(agent_name)
        blocked = self._precondition_blockers(agent_name, require_enabled=False)
        if blocked:
            event = self._append_event(
                action=field_name,
                agent_name=agent_name,
                outcome=RegistryDecision.BLOCKED.value,
                blocked_reason=blocked,
                before=record,
            )
            return _result(RegistryDecision.BLOCKED, blocked, record, event)
        assert record is not None
        after = AgentRecord(
            name=record.name,
            enabled=record.enabled,
            health=record.health,
            approval_state=value if field_name == "approval_state" else record.approval_state,  # type: ignore[arg-type]
            audit_state=value if field_name == "audit_state" else record.audit_state,  # type: ignore[arg-type]
            registered_at=record.registered_at,
            updated_at=_now_utc(),
        )
        self._records[agent_name] = after
        event = self._append_event(action=field_name, agent_name=agent_name, outcome=RegistryDecision.ALLOW.value, before=record, after=after)
        return _result(RegistryDecision.ALLOW, [], after, event)


def _result(
    decision: RegistryDecision,
    reason_codes: list[str],
    record: AgentRecord | None,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "registry_version": AGENT_REGISTRY_VERSION,
        "decision": decision.value,
        "reason_codes": reason_codes,
        "agent": record.to_dict() if record else None,
        "audit_evidence": evidence,
    }


def default_agent_registry(*, actor: str = "codex") -> AgentRegistry:
    registry = AgentRegistry(actor=actor)
    for agent_name in SUPPORTED_AGENTS:
        registry.register(agent_name)
    return registry


def agent_registry_contract() -> dict[str, Any]:
    return {
        "registry_version": AGENT_REGISTRY_VERSION,
        "supported_agents": list(SUPPORTED_AGENTS),
        usbay/pb-353a-euria-registry-extension
        "agent_capabilities": {agent: list(capabilities) for agent, capabilities in AGENT_CAPABILITY_MAP.items()},
        "capabilities": [
            "register",
            "enable",
            "disable",
            "health",
            "approval_state",
            "audit_state",
            "project_dispatch",
        ],

        "capabilities": ["register", "enable", "disable", "health", "approval_state", "audit_state"],
        main
        "fail_closed": [
            "unknown_agent",
            "agent_disabled",
            "agent_not_registered",
            "agent_unhealthy",
            "agent_approval_not_ready",
            "agent_audit_not_ready",
        usbay/pb-353a-euria-registry-extension
            "project_dispatch_project_id_missing",
            "missing_euria_capability",
            "unsupported_euria_action",

        main
        ],
        "connector_execution_allowed": False,
        "github_execution_allowed": False,
        "notion_execution_allowed": False,
        "linkedin_execution_allowed": False,
        "email_execution_allowed": False,
        "audit_evidence_required": True,
    }
      usbay/pb-353a-euria-registry-extension


def _capability_blockers(
    agent_name: str,
    requested_action: str | None,
    capabilities: tuple[str, ...],
) -> list[str]:
    if requested_action is None or agent_name not in SUPPORTED_AGENTS:
        return []
    supported = AGENT_CAPABILITY_MAP.get(agent_name, ())
    if requested_action not in supported:
        if agent_name == AgentName.EURIA.value:
            return ["unsupported_euria_action"]
        return ["unsupported_agent_action"]
    if requested_action not in capabilities:
        if agent_name == AgentName.EURIA.value:
            return ["missing_euria_capability"]
        return ["missing_agent_capability"]
    return []

        main
