from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DECISION_VERIFIED = "VERIFIED"
DECISION_BLOCKED = "BLOCKED"
STATUS_READY_FOR_REVIEW = "READY_FOR_REVIEW"
STATUS_FAIL_CLOSED = "FAIL_CLOSED"
ACTION_APPROVED_DRY_RUN = "APPROVED_DRY_RUN"
ACTION_BLOCKED = "BLOCKED"
REDACTED = "[REDACTED]"

SENSITIVE_FIELD_NAMES = {
    "api_key",
    "approval_contents",
    "authorization",
    "client_secret",
    "credential",
    "password",
    "private_key",
    "raw_payload",
    "secret",
    "session",
    "token",
}


@dataclass(frozen=True)
class ConnectorPolicy:
    connector_name: str
    action_type: str
    required_permission: str
    approval_required: bool
    fail_closed_on_error: bool
    audit_output: str
    dry_run_supported: bool
    sensitive_fields_redacted: bool


@dataclass(frozen=True)
class ConnectorAction:
    connector_name: str
    action_type: str
    permissions: tuple[str, ...] = field(default_factory=tuple)
    approval_id: str | None = None
    dry_run: bool = True
    payload: dict[str, Any] = field(default_factory=dict)
    connector_error: str | None = None


def connector_registry() -> dict[str, ConnectorPolicy]:
    policies = (
        ConnectorPolicy(
            connector_name="GitHub",
            action_type="sync_pr_metadata",
            required_permission="github:metadata:write",
            approval_required=False,
            fail_closed_on_error=True,
            audit_output="governance/evidence/connectors/github_audit.json",
            dry_run_supported=True,
            sensitive_fields_redacted=True,
        ),
        ConnectorPolicy(
            connector_name="Codex",
            action_type="prepare_governance_task",
            required_permission="codex:workspace:write",
            approval_required=False,
            fail_closed_on_error=True,
            audit_output="governance/evidence/connectors/codex_audit.json",
            dry_run_supported=True,
            sensitive_fields_redacted=True,
        ),
        ConnectorPolicy(
            connector_name="Notion",
            action_type="sync_evidence_page",
            required_permission="notion:workspace:write",
            approval_required=True,
            fail_closed_on_error=True,
            audit_output="governance/evidence/connectors/notion_audit.json",
            dry_run_supported=True,
            sensitive_fields_redacted=True,
        ),
        ConnectorPolicy(
            connector_name="Euria",
            action_type="sync_project_context",
            required_permission="euria:project:update",
            approval_required=True,
            fail_closed_on_error=True,
            audit_output="governance/evidence/connectors/euria_audit.json",
            dry_run_supported=True,
            sensitive_fields_redacted=True,
        ),
        ConnectorPolicy(
            connector_name="LinkedIn",
            action_type="prepare_profile_update",
            required_permission="linkedin:profile:write",
            approval_required=True,
            fail_closed_on_error=True,
            audit_output="governance/evidence/connectors/linkedin_audit.json",
            dry_run_supported=True,
            sensitive_fields_redacted=True,
        ),
        ConnectorPolicy(
            connector_name="USBAY Control Plane",
            action_type="sync_runtime_status",
            required_permission="usbay_control_plane:status:write",
            approval_required=False,
            fail_closed_on_error=True,
            audit_output="governance/evidence/connectors/control_plane_audit.json",
            dry_run_supported=True,
            sensitive_fields_redacted=True,
        ),
    )
    return {policy.connector_name: policy for policy in policies}


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sha256_payload(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in SENSITIVE_FIELD_NAMES or any(marker in lowered for marker in ("secret", "token", "password", "private_key"))


def contains_sensitive_data(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_is_sensitive_key(str(key)) or contains_sensitive_data(item) for key, item in value.items())
    if isinstance(value, list | tuple):
        return any(contains_sensitive_data(item) for item in value)
    return False


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): REDACTED if _is_sensitive_key(str(key)) else redact_sensitive(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive(item) for item in value)
    return value


def evaluate_connector_action(
    action: ConnectorAction,
    registry: dict[str, ConnectorPolicy] | None = None,
) -> dict[str, Any]:
    policies = registry or connector_registry()
    blockers: list[str] = []
    policy = policies.get(action.connector_name)
    if policy is None:
        blockers.append("unknown_connector")
        audit_payload = redact_sensitive(action.payload)
        return _decision(action, None, blockers, audit_payload)

    if action.action_type != policy.action_type:
        blockers.append("unsupported_action_type")
    if policy.required_permission not in action.permissions:
        blockers.append("missing_permission")
    if policy.approval_required and not action.approval_id:
        blockers.append("approval_required")
    if action.connector_error:
        blockers.append("connector_error")
    if not policy.dry_run_supported:
        blockers.append("dry_run_not_supported")
    if action.dry_run is not True:
        blockers.append("live_external_mutation_disabled")

    sensitive_detected = contains_sensitive_data(action.payload)
    if sensitive_detected and not policy.sensitive_fields_redacted:
        blockers.append("sensitive_data_unredacted")
    audit_payload = redact_sensitive(action.payload) if policy.sensitive_fields_redacted else action.payload
    return _decision(action, policy, blockers, audit_payload, sensitive_detected=sensitive_detected)


def _decision(
    action: ConnectorAction,
    policy: ConnectorPolicy | None,
    blockers: list[str],
    audit_payload: Any,
    *,
    sensitive_detected: bool = False,
) -> dict[str, Any]:
    raw_payload_hash = sha256_payload(action.payload)
    audit_payload_hash = sha256_payload(audit_payload)
    audit_record = {
        "schema": "usbay.connector.audit.v1",
        "connector_name": action.connector_name,
        "action_type": action.action_type,
        "dry_run": action.dry_run,
        "approval_id_present": bool(action.approval_id),
        "payload_hash": raw_payload_hash,
        "audit_payload": audit_payload,
        "audit_payload_hash": audit_payload_hash,
        "sensitive_data_detected": sensitive_detected,
        "sensitive_fields_redacted": bool(policy.sensitive_fields_redacted) if policy else True,
        "raw_payload_logged": False,
        "external_mutation_performed": False,
        "evaluated_at_utc": _now_utc(),
    }
    audit_record["audit_hash"] = sha256_payload(audit_record)
    blocked = bool(blockers)
    return {
        "decision": ACTION_BLOCKED if blocked else ACTION_APPROVED_DRY_RUN,
        "status": STATUS_FAIL_CLOSED if blocked else STATUS_READY_FOR_REVIEW,
        "blockers": blockers,
        "connector": asdict(policy) if policy else None,
        "audit_record": audit_record,
    }


def run_dry_run_actions(actions: list[ConnectorAction], registry: dict[str, ConnectorPolicy] | None = None) -> dict[str, Any]:
    decisions = [evaluate_connector_action(action, registry) for action in actions]
    blocked = [decision for decision in decisions if decision["decision"] == ACTION_BLOCKED]
    return {
        "schema": "usbay.connector.execution_report.v1",
        "decision": DECISION_BLOCKED if blocked else DECISION_VERIFIED,
        "status": STATUS_FAIL_CLOSED if blocked else STATUS_READY_FOR_REVIEW,
        "dry_run_default": True,
        "external_mutation_performed": False,
        "actions": decisions,
        "blocked_count": len(blocked),
        "action_count": len(decisions),
        "report_hash": sha256_payload([decision["audit_record"]["audit_hash"] for decision in decisions]),
    }


def generated_pr_body() -> str:
    return """## PURPOSE
PB-038 defines a governed connector framework for GitHub, Codex, Notion, Euria, LinkedIn, and the USBAY Control Plane.

## RISK
External connectors can mutate systems, publish public content, expose sensitive data, or create false audit state if actions are not policy-gated and dry-run-first.

## POLICY LINK
AGENTS.md fail-closed, audit-first, network governance, human oversight, and secret/data hygiene rules. PB-037 closure evidence: governance/evidence/pb037/release_governance_closure_report.json.

## REQUIRED APPROVALS
USBAY-AUDIT and USBAY-GLOBAL23 review are required before merge. No live connector execution, auto-approval, admin merge, or branch protection bypass is permitted.

## GOVERNANCE CHECKS
Tests must prove known connector dry-runs pass, unknown connectors block, missing permissions block, required approval blocks without approval, connector errors block, sensitive fields are redacted, and no live external mutation occurs.

## AUDIT
PB-038 generates governance/evidence/pb038/connector_framework_report.json with the connector registry, allowed dry-run actions, blocked examples, approval-required examples, redaction behavior, and fail-closed behavior.

## IMPACT
USBAY gains a framework-first connector governance layer that can coordinate external systems only through policy-gated, audit-producing, dry-run-first execution.

## Decision
VERIFIED

## Status
READY_FOR_REVIEW
"""


def generate_pb038_report(output_dir: Path) -> dict[str, Any]:
    registry = connector_registry()
    allowed_actions = [
        ConnectorAction(policy.connector_name, policy.action_type, permissions=(policy.required_permission,), approval_id="APPROVAL-DRY-RUN" if policy.approval_required else None)
        for policy in registry.values()
    ]
    blocked_examples = [
        evaluate_connector_action(ConnectorAction("Unknown", "sync", permissions=("unknown:write",)), registry),
        evaluate_connector_action(ConnectorAction("GitHub", "sync_pr_metadata"), registry),
        evaluate_connector_action(ConnectorAction("Notion", "sync_evidence_page", permissions=("notion:workspace:write",)), registry),
        evaluate_connector_action(
            ConnectorAction(
                "GitHub",
                "sync_pr_metadata",
                permissions=("github:metadata:write",),
                connector_error="simulated_connector_error",
            ),
            registry,
        ),
        evaluate_connector_action(
            ConnectorAction(
                "LinkedIn",
                "prepare_profile_update",
                permissions=("linkedin:profile:write",),
                approval_id="APPROVAL-DRY-RUN",
                dry_run=False,
            ),
            registry,
        ),
    ]
    allowed_report = run_dry_run_actions(allowed_actions, registry)
    redaction_example = evaluate_connector_action(
        ConnectorAction(
            "GitHub",
            "sync_pr_metadata",
            permissions=("github:metadata:write",),
            payload={"token": "raw-token-value", "safe": "metadata"},
        ),
        registry,
    )
    report = {
        "schema": "usbay.pb038.connector_framework.v1",
        "pb": "PB-038",
        "title": "Governed Connector Framework",
        "decision": DECISION_VERIFIED,
        "status": STATUS_READY_FOR_REVIEW,
        "dry_run_default": True,
        "live_external_mutations_allowed": False,
        "connectors": [asdict(policy) for policy in registry.values()],
        "allowed_dry_run_actions": allowed_report,
        "blocked_examples": blocked_examples,
        "approval_required_examples": [
            {
                "connector_name": policy.connector_name,
                "action_type": policy.action_type,
                "required_permission": policy.required_permission,
            }
            for policy in registry.values()
            if policy.approval_required
        ],
        "redaction_behavior": redaction_example,
        "fail_closed_behavior": {
            "unknown_connector": "BLOCK",
            "missing_permission": "BLOCK",
            "approval_required_without_approval": "BLOCK",
            "connector_error": "BLOCK",
            "sensitive_data": "REDACT",
            "non_dry_run": "BLOCK",
        },
        "generated_pr_body": generated_pr_body(),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "connector_framework_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "generated_pr_body.md").write_text(generated_pr_body(), encoding="utf-8")
    return report
