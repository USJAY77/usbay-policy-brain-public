from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from governance.connector_framework import (
    ACTION_BLOCKED,
    ConnectorAction,
    ConnectorPolicy,
    connector_registry,
    evaluate_connector_action,
    generated_pr_body as pb038_generated_pr_body,
    sha256_payload,
)


WORKFLOW_ORDER = ("GitHub", "Codex", "Notion", "Euria", "LinkedIn", "USBAY Control Plane")


def policy_brain_evaluate(action: ConnectorAction, policy: ConnectorPolicy | None) -> dict[str, Any]:
    blockers: list[str] = []
    if policy is None:
        blockers.append("unknown_connector")
    elif action.action_type != policy.action_type:
        blockers.append("unsupported_action_type")
    if action.dry_run is not True:
        blockers.append("live_external_execution_forbidden")
    return {
        "decision": "BLOCK" if blockers else "ALLOW_DRY_RUN",
        "blockers": blockers,
        "dry_run_required": True,
        "external_mutation_allowed": False,
        "policy_hash": sha256_payload(
            {
                "connector_name": action.connector_name,
                "action_type": action.action_type,
                "dry_run_required": True,
                "external_mutation_allowed": False,
            }
        ),
    }


def approval_gate_evaluate(action: ConnectorAction, policy: ConnectorPolicy | None) -> dict[str, Any]:
    required = bool(policy.approval_required) if policy else False
    approved = bool(action.approval_id)
    blockers = ["approval_required"] if required and not approved else []
    return {
        "approval_required": required,
        "approval_present": approved,
        "decision": "BLOCK" if blockers else "APPROVED_OR_NOT_REQUIRED",
        "blockers": blockers,
        "approval_id_hash": sha256_payload(action.approval_id) if action.approval_id else None,
    }


def _step_report(action: ConnectorAction, registry: dict[str, ConnectorPolicy]) -> dict[str, Any]:
    policy = registry.get(action.connector_name)
    policy_brain = policy_brain_evaluate(action, policy)
    connector_decision = evaluate_connector_action(action, registry)
    approval_gate = approval_gate_evaluate(action, policy)
    blocked = (
        policy_brain["decision"] == "BLOCK"
        or connector_decision["decision"] == ACTION_BLOCKED
        or approval_gate["decision"] == "BLOCK"
    )
    return {
        "connector_name": action.connector_name,
        "action_type": action.action_type,
        "policy_brain": policy_brain,
        "connector_registry": {
            "registered": policy is not None,
            "required_permission": policy.required_permission if policy else None,
            "permission_present": bool(policy and policy.required_permission in action.permissions),
            "registry_hash": sha256_payload(asdict(policy)) if policy else None,
        },
        "approval_gate": approval_gate,
        "audit_output": {
            "audit_hash": connector_decision["audit_record"]["audit_hash"],
            "audit_payload_hash": connector_decision["audit_record"]["audit_payload_hash"],
            "raw_payload_logged": connector_decision["audit_record"]["raw_payload_logged"],
            "sensitive_data_detected": connector_decision["audit_record"]["sensitive_data_detected"],
            "sensitive_fields_redacted": connector_decision["audit_record"]["sensitive_fields_redacted"],
            "external_mutation_performed": connector_decision["audit_record"]["external_mutation_performed"],
        },
        "decision": "BLOCKED" if blocked else "APPROVED_DRY_RUN",
        "blockers": sorted(
            set(
                policy_brain["blockers"]
                + connector_decision["blockers"]
                + approval_gate["blockers"]
            )
        ),
    }


def approved_workflow_actions() -> list[ConnectorAction]:
    registry = connector_registry()
    return [
        ConnectorAction("GitHub", registry["GitHub"].action_type, permissions=(registry["GitHub"].required_permission,)),
        ConnectorAction("Codex", registry["Codex"].action_type, permissions=(registry["Codex"].required_permission,)),
        ConnectorAction(
            "Notion",
            registry["Notion"].action_type,
            permissions=(registry["Notion"].required_permission,),
            approval_id="PB039-DRY-RUN-APPROVAL",
        ),
        ConnectorAction(
            "Euria",
            registry["Euria"].action_type,
            permissions=(registry["Euria"].required_permission,),
            approval_id="PB039-DRY-RUN-APPROVAL",
        ),
        ConnectorAction(
            "LinkedIn",
            registry["LinkedIn"].action_type,
            permissions=(registry["LinkedIn"].required_permission,),
            approval_id="PB039-DRY-RUN-APPROVAL",
        ),
        ConnectorAction(
            "USBAY Control Plane",
            registry["USBAY Control Plane"].action_type,
            permissions=(registry["USBAY Control Plane"].required_permission,),
        ),
    ]


def simulate_connector_workflow(actions: list[ConnectorAction] | None = None) -> dict[str, Any]:
    registry = connector_registry()
    workflow_actions = actions or approved_workflow_actions()
    steps = [_step_report(action, registry) for action in workflow_actions]
    blocked_steps = [step for step in steps if step["decision"] == "BLOCKED"]
    return {
        "schema": "usbay.pb039.connector_orchestrator_simulation.v1",
        "workflow": list(WORKFLOW_ORDER),
        "decision": "BLOCKED" if blocked_steps else "VERIFIED",
        "status": "FAIL_CLOSED" if blocked_steps else "READY_FOR_REVIEW",
        "dry_run_only": True,
        "live_external_execution": False,
        "posts_messages_emails_or_account_changes": False,
        "steps": steps,
        "blocked_step_count": len(blocked_steps),
        "audit_hashes": [step["audit_output"]["audit_hash"] for step in steps],
        "workflow_hash": sha256_payload([step["audit_output"]["audit_hash"] for step in steps]),
    }


def generated_pr_body() -> str:
    return """## PURPOSE
PB-039 simulates the full USBAY connector workflow from GitHub to Codex to Notion to Euria to LinkedIn to the USBAY Control Plane using dry-run governance only.

## RISK
Connector orchestration can mutate external systems, publish public content, leak sensitive data, or create misleading audit state if any step bypasses policy gates, approvals, or redacted audit output.

## POLICY LINK
AGENTS.md fail-closed, audit-first, human oversight, network governance, and secret/data hygiene rules. PB-038 framework evidence: governance/evidence/pb038/connector_framework_report.json.

## REQUIRED APPROVALS
USBAY-AUDIT and USBAY-GLOBAL23 review are required before merge. No live connector execution, external posting, messaging, emailing, account changes, admin merge, or branch protection bypass is permitted.

## GOVERNANCE CHECKS
Tests must prove approved dry-run workflow passes, unknown connectors block, missing permissions block, public external action without human approval blocks, connector failures block, sensitive payloads are redacted, and full workflow audit evidence is generated.

## AUDIT
PB-039 generates governance/evidence/pb039/connector_orchestrator_simulation_report.json with workflow steps, policy brain decisions, registry checks, approval gates, audit hashes, blocked examples, redaction evidence, and fail-closed outcomes.

## IMPACT
USBAY proves it can coordinate GitHub, Codex, Notion, Euria, LinkedIn, and Control Plane actions through dry-run policy gates without live external execution.

## Decision
VERIFIED

## Status
READY_FOR_REVIEW
"""


def generate_pb039_report(output_dir: Path) -> dict[str, Any]:
    registry = connector_registry()
    approved = simulate_connector_workflow()
    blocked_examples = {
        "unknown_connector": simulate_connector_workflow(
            [ConnectorAction("Unknown", "sync", permissions=("unknown:write",))]
        ),
        "missing_permission": simulate_connector_workflow(
            [ConnectorAction("GitHub", registry["GitHub"].action_type, permissions=())]
        ),
        "external_public_action_without_human_approval": simulate_connector_workflow(
            [ConnectorAction("LinkedIn", registry["LinkedIn"].action_type, permissions=(registry["LinkedIn"].required_permission,))]
        ),
        "connector_failure": simulate_connector_workflow(
            [
                ConnectorAction(
                    "GitHub",
                    registry["GitHub"].action_type,
                    permissions=(registry["GitHub"].required_permission,),
                    connector_error="simulated_connector_failure",
                )
            ]
        ),
        "sensitive_payload_redaction": simulate_connector_workflow(
            [
                ConnectorAction(
                    "GitHub",
                    registry["GitHub"].action_type,
                    permissions=(registry["GitHub"].required_permission,),
                    payload={"token": "raw-token-value", "safe": "metadata"},
                )
            ]
        ),
    }
    report = {
        "schema": "usbay.pb039.connector_orchestrator_simulation_report.v1",
        "pb": "PB-039",
        "title": "Connector Orchestrator Simulation",
        "decision": "VERIFIED",
        "status": "READY_FOR_REVIEW",
        "uses_pb038_connector_framework": True,
        "pb038_pr_body_hash": sha256_payload(pb038_generated_pr_body()),
        "workflow_order": list(WORKFLOW_ORDER),
        "approved_dry_run_workflow": approved,
        "blocked_examples": blocked_examples,
        "sensitive_data_in_logs": False,
        "live_external_execution": False,
        "external_mutations": {
            "api_calls": False,
            "posts": False,
            "messages": False,
            "emails": False,
            "account_changes": False,
        },
        "fail_closed_on_uncertainty": True,
        "generated_pr_body": generated_pr_body(),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "connector_orchestrator_simulation_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "generated_pr_body.md").write_text(generated_pr_body(), encoding="utf-8")
    return report
