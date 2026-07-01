from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


AUTOMATION_OPERATOR_VERSION = "pb352-governed-automation-operator-dry-run-v1"


class AutomationAgent(str, Enum):
    CODEX = "Codex Agent"
    RUNTIME = "Runtime Agent"
    HYDRA = "Hydra Agent"
    GOVERNANCE = "Governance Agent"


class AutomationConnector(str, Enum):
    TERMINAL = "Terminal"
    CODEX = "Codex"
    GITHUB = "GitHub"
    NOTION = "Notion"
    LINKEDIN = "LinkedIn"
    EMAIL = "Email"
    TASKS = "Tasks"
    AUDIT_EVIDENCE = "Audit Evidence"


class ApprovalGate(str, Enum):
    TERMINAL_EXECUTION_APPROVAL = "TERMINAL_EXECUTION_APPROVAL"
    CODEX_TASK_APPROVAL = "CODEX_TASK_APPROVAL"
    GITHUB_MUTATION_APPROVAL = "GITHUB_MUTATION_APPROVAL"
    NOTION_WRITE_APPROVAL = "NOTION_WRITE_APPROVAL"
    LINKEDIN_PUBLICATION_APPROVAL = "LINKEDIN_PUBLICATION_APPROVAL"
    EMAIL_SEND_APPROVAL = "EMAIL_SEND_APPROVAL"
    TASK_STATUS_MUTATION_APPROVAL = "TASK_STATUS_MUTATION_APPROVAL"


class OperatorDecision(str, Enum):
    APPROVED_DRY_RUN = "APPROVED_DRY_RUN"
    BLOCKED = "BLOCKED"


MUTATION_ACTIONS = {
    "terminal.execute",
    "codex.dispatch_task",
    "github.create_pr",
    "github.request_review",
    "github.merge_pr",
    "notion.update_page",
    "linkedin.publish_post",
    "email.send",
    "tasks.create",
    "tasks.update_status",
}

SAFE_DRY_RUN_ACTIONS = {
    "terminal.plan",
    "terminal.validate_command",
    "codex.prepare_task",
    "github.observe_pr",
    "github.draft_pr",
    "github.check_status",
    "notion.draft_update",
    "linkedin.draft_post",
    "email.draft",
    "tasks.draft",
    "audit.generate_evidence",
}

CONNECTOR_ACTIONS = {
    AutomationConnector.TERMINAL.value: {"terminal.plan", "terminal.validate_command", "terminal.execute"},
    AutomationConnector.CODEX.value: {"codex.prepare_task", "codex.dispatch_task"},
    AutomationConnector.GITHUB.value: {
        "github.observe_pr",
        "github.draft_pr",
        "github.check_status",
        "github.create_pr",
        "github.request_review",
        "github.merge_pr",
    },
    AutomationConnector.NOTION.value: {"notion.draft_update", "notion.update_page"},
    AutomationConnector.LINKEDIN.value: {"linkedin.draft_post", "linkedin.publish_post"},
    AutomationConnector.EMAIL.value: {"email.draft", "email.send"},
    AutomationConnector.TASKS.value: {"tasks.draft", "tasks.create", "tasks.update_status"},
    AutomationConnector.AUDIT_EVIDENCE.value: {"audit.generate_evidence"},
}

APPROVAL_GATE_BY_ACTION = {
    "terminal.execute": ApprovalGate.TERMINAL_EXECUTION_APPROVAL,
    "codex.dispatch_task": ApprovalGate.CODEX_TASK_APPROVAL,
    "github.create_pr": ApprovalGate.GITHUB_MUTATION_APPROVAL,
    "github.request_review": ApprovalGate.GITHUB_MUTATION_APPROVAL,
    "github.merge_pr": ApprovalGate.GITHUB_MUTATION_APPROVAL,
    "notion.update_page": ApprovalGate.NOTION_WRITE_APPROVAL,
    "linkedin.publish_post": ApprovalGate.LINKEDIN_PUBLICATION_APPROVAL,
    "email.send": ApprovalGate.EMAIL_SEND_APPROVAL,
    "tasks.create": ApprovalGate.TASK_STATUS_MUTATION_APPROVAL,
    "tasks.update_status": ApprovalGate.TASK_STATUS_MUTATION_APPROVAL,
}

UNSAFE_TERMINAL_MARKERS = (
    " rm ",
    "rm -",
    "sudo ",
    "chmod ",
    "chown ",
    "dd ",
    "mkfs",
    "diskutil erase",
    "git reset --hard",
    "git push --force",
    "curl ",
    "wget ",
)

SENSITIVE_KEYS = (
    "authorization",
    "api_key",
    "approval_contents",
    "password",
    "private_key",
    "raw_payload",
    "secret",
    "token",
)


@dataclass(frozen=True)
class AutomationRequest:
    action_id: str
    actor: str
    agent: str
    connector: str
    requested_action: str
    policy_version: str | None
    policy_decision: str = "ALLOW"
    command: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    connector_error: str | None = None
    dry_run: bool = True
    simulate_evidence_failure: bool = False


@dataclass(frozen=True)
class ApprovalEvidence:
    approval_gate: str
    approver: str
    approved: bool
    approval_id: str


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sha256_payload(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            any(marker in str(key).lower() for marker in SENSITIVE_KEYS) or _contains_sensitive_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list | tuple):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _is_unsafe_terminal_command(command: str | None) -> bool:
    normalized = f" {(command or '').strip().lower()} "
    return any(marker in normalized for marker in UNSAFE_TERMINAL_MARKERS)


def _approval_state(
    request: AutomationRequest,
    approval: ApprovalEvidence | None,
) -> tuple[str, str | None]:
    gate = APPROVAL_GATE_BY_ACTION.get(request.requested_action)
    if gate is None:
        return "NOT_REQUIRED", None
    if approval is None:
        return "MISSING", gate.value
    if approval.approval_gate != gate.value:
        return "INVALID_GATE", gate.value
    if approval.approver == request.actor:
        return "SELF_APPROVAL_BLOCKED", gate.value
    if approval.approved is not True:
        return "DENIED", gate.value
    if not approval.approval_id:
        return "MISSING_APPROVAL_ID", gate.value
    return "APPROVED", gate.value


def _block_reasons(request: AutomationRequest, approval: ApprovalEvidence | None) -> list[str]:
    reasons: list[str] = []
    if request.agent not in {agent.value for agent in AutomationAgent}:
        reasons.append("unknown_agent")
    if request.connector not in CONNECTOR_ACTIONS:
        reasons.append("unknown_connector")
    elif request.requested_action not in CONNECTOR_ACTIONS[request.connector]:
        reasons.append("unknown_connector_action")
    if not request.policy_version:
        reasons.append("missing_policy")
    if str(request.policy_decision).upper() not in {"ALLOW", "ALLOW_DRY_RUN"}:
        reasons.append("policy_blocked")
    if request.connector_error:
        reasons.append("connector_api_failure")
    if _contains_sensitive_key(request.payload):
        reasons.append("sensitive_payload_forbidden")
    if request.connector == AutomationConnector.TERMINAL.value and _is_unsafe_terminal_command(request.command):
        approval_state, _ = _approval_state(request, approval)
        if approval_state != "APPROVED":
            reasons.append("unsafe_terminal_command")
    approval_state, _ = _approval_state(request, approval)
    if approval_state not in {"NOT_REQUIRED", "APPROVED"}:
        reasons.append("missing_approval" if approval_state == "MISSING" else approval_state.lower())
    if request.dry_run is not True:
        reasons.append("live_external_mutation_disabled")
    if request.simulate_evidence_failure:
        reasons.append("missing_audit_hash")
    return sorted(set(reasons))


def evaluate_automation_request(
    request: AutomationRequest,
    approval: ApprovalEvidence | None = None,
    *,
    timestamp: str | None = None,
) -> dict[str, Any]:
    blocked_reason = _block_reasons(request, approval)
    approval_state, approval_gate = _approval_state(request, approval)
    outcome = OperatorDecision.BLOCKED.value if blocked_reason else OperatorDecision.APPROVED_DRY_RUN.value
    evidence = {
        "schema": "usbay.control_plane.automation_operator_evidence.v1",
        "operator_version": AUTOMATION_OPERATOR_VERSION,
        "action_id": request.action_id,
        "actor": request.actor,
        "connector": request.connector,
        "requested_action": request.requested_action,
        "policy_version": request.policy_version,
        "policy_decision": str(request.policy_decision).upper(),
        "approval_state": approval_state,
        "approval_gate": approval_gate,
        "timestamp": timestamp or _now_utc(),
        "outcome": outcome,
        "blocked_reason": blocked_reason,
        "external_mutation_performed": False,
        "dry_run": request.dry_run,
        "request_hash": sha256_payload(
            {
                "action_id": request.action_id,
                "actor": request.actor,
                "agent": request.agent,
                "connector": request.connector,
                "requested_action": request.requested_action,
                "policy_version": request.policy_version,
                "policy_decision": str(request.policy_decision).upper(),
                "command_hash": sha256_payload(request.command or ""),
                "payload_hash": sha256_payload(request.payload),
            }
        ),
    }
    evidence["evidence_hash"] = "" if request.simulate_evidence_failure else sha256_payload(evidence)
    if not evidence["evidence_hash"] and "missing_audit_hash" not in blocked_reason:
        blocked_reason.append("missing_audit_hash")
        evidence["blocked_reason"] = sorted(set(blocked_reason))
        evidence["outcome"] = OperatorDecision.BLOCKED.value
    return {
        "decision": evidence["outcome"],
        "status": "FAIL_CLOSED" if evidence["outcome"] == OperatorDecision.BLOCKED.value else "DRY_RUN_READY",
        "blocked_reason": evidence["blocked_reason"],
        "approval_gate": approval_gate,
        "audit_evidence": evidence,
    }


def automation_operator_contract() -> dict[str, Any]:
    return {
        "operator_version": AUTOMATION_OPERATOR_VERSION,
        "status": "PB-352_GOVERNED_AUTOMATION_OPERATOR_DRY_RUN",
        "agents": [agent.value for agent in AutomationAgent],
        "connectors": [connector.value for connector in AutomationConnector],
        "approval_gates": [gate.value for gate in ApprovalGate],
        "safe_dry_run_actions": sorted(SAFE_DRY_RUN_ACTIONS),
        "mutation_actions": sorted(MUTATION_ACTIONS),
        "live_external_mutation_allowed": False,
        "fail_closed_reasons": [
            "unknown_agent",
            "unknown_connector",
            "missing_policy",
            "missing_approval",
            "missing_audit_hash",
            "connector_api_failure",
            "unsafe_terminal_command",
        ],
        "required_evidence_fields": [
            "action_id",
            "actor",
            "connector",
            "requested_action",
            "policy_decision",
            "approval_state",
            "timestamp",
            "evidence_hash",
            "outcome",
            "blocked_reason",
        ],
    }


def default_dry_run_plan(actor: str = "codex") -> list[AutomationRequest]:
    return [
        AutomationRequest("terminal-plan", actor, AutomationAgent.CODEX.value, "Terminal", "terminal.plan", AUTOMATION_OPERATOR_VERSION),
        AutomationRequest("codex-prepare", actor, AutomationAgent.CODEX.value, "Codex", "codex.prepare_task", AUTOMATION_OPERATOR_VERSION),
        AutomationRequest("github-observe", actor, AutomationAgent.GOVERNANCE.value, "GitHub", "github.observe_pr", AUTOMATION_OPERATOR_VERSION),
        AutomationRequest("notion-draft", actor, AutomationAgent.GOVERNANCE.value, "Notion", "notion.draft_update", AUTOMATION_OPERATOR_VERSION),
        AutomationRequest("linkedin-draft", actor, AutomationAgent.GOVERNANCE.value, "LinkedIn", "linkedin.draft_post", AUTOMATION_OPERATOR_VERSION),
        AutomationRequest("email-draft", actor, AutomationAgent.GOVERNANCE.value, "Email", "email.draft", AUTOMATION_OPERATOR_VERSION),
        AutomationRequest("task-draft", actor, AutomationAgent.GOVERNANCE.value, "Tasks", "tasks.draft", AUTOMATION_OPERATOR_VERSION),
        AutomationRequest("audit-evidence", actor, AutomationAgent.GOVERNANCE.value, "Audit Evidence", "audit.generate_evidence", AUTOMATION_OPERATOR_VERSION),
    ]


def evaluate_dry_run_plan(requests: list[AutomationRequest] | None = None) -> dict[str, Any]:
    decisions = [evaluate_automation_request(request) for request in (requests or default_dry_run_plan())]
    blocked = [decision for decision in decisions if decision["decision"] == OperatorDecision.BLOCKED.value]
    return {
        "schema": "usbay.control_plane.automation_operator_plan.v1",
        "operator_version": AUTOMATION_OPERATOR_VERSION,
        "status": "FAIL_CLOSED" if blocked else "DRY_RUN_READY",
        "decision": "BLOCKED" if blocked else "VERIFIED",
        "external_mutation_performed": False,
        "actions": decisions,
        "plan_hash": sha256_payload([decision["audit_evidence"]["evidence_hash"] for decision in decisions]),
    }

