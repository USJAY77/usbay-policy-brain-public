from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


ORCHESTRATOR_VERSION = "pb261-265-cross-system-governance-orchestrator-v1"
WORKFLOW = ("LinkedIn", "Notion", "Euria", "USBAY Control Plane", "GitHub", "Codex", "Mac", "Terminal")
DEFAULT_POLICY_HASH = "88d1aaa62bbe011c9f51d7f159a7526a2fe283b94314e8c9b9cce73b199f04d1"


class WorkflowState(str, Enum):
    READ_ONLY = "READ_ONLY"
    DRY_RUN = "DRY_RUN"
    BLOCKED = "BLOCKED"


class ApprovalRoute(str, Enum):
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
    BLOCKED = "BLOCKED"


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sha256_json(data: Any) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class WorkflowStep:
    sequence: int
    system: str
    state: WorkflowState = WorkflowState.READ_ONLY
    dry_run_only: bool = True
    production_activation_allowed: bool = False
    connector_activation_allowed: bool = False
    browser_automation_allowed: bool = False
    desktop_automation_allowed: bool = False
    terminal_write_allowed: bool = False
    external_api_execution_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["state"] = self.state.value
        return payload


def workflow_registry_json() -> dict[str, Any]:
    return {
        "contract_version": ORCHESTRATOR_VERSION,
        "workflow": list(WORKFLOW),
        "default_state": WorkflowState.READ_ONLY.value,
        "dry_run_only": True,
        "production_activation_allowed": False,
        "steps": [WorkflowStep(index, system).to_dict() for index, system in enumerate(WORKFLOW, start=1)],
    }


def evaluate_workflow_state(step: dict[str, Any]) -> dict[str, Any]:
    state = str(step.get("state", "UNKNOWN"))
    gaps: list[str] = []
    if state not in {WorkflowState.READ_ONLY.value, WorkflowState.DRY_RUN.value, WorkflowState.BLOCKED.value}:
        gaps.append("UNKNOWN_STATE")
    for flag in (
        "production_activation_allowed",
        "connector_activation_allowed",
        "browser_automation_allowed",
        "desktop_automation_allowed",
        "terminal_write_allowed",
        "external_api_execution_allowed",
    ):
        if step.get(flag) is not False:
            gaps.append(f"{flag.upper()}_MUST_BE_FALSE")
    return {
        "decision": "VERIFIED" if not gaps else "FAIL_CLOSED",
        "state": state if not gaps else WorkflowState.BLOCKED.value,
        "gaps": sorted(set(gaps)),
        "contract_version": ORCHESTRATOR_VERSION,
    }


def workflow_state_engine_report() -> dict[str, Any]:
    registry = workflow_registry_json()
    evaluations = [evaluate_workflow_state(step) for step in registry["steps"]]
    gaps = sorted({gap for result in evaluations for gap in result["gaps"]})
    return {
        "contract_version": ORCHESTRATOR_VERSION,
        "decision": "VERIFIED" if not gaps else "FAIL_CLOSED",
        "default_state": WorkflowState.READ_ONLY.value,
        "allowed_states": [state.value for state in WorkflowState],
        "unknown_state_outcome": "FAIL_CLOSED",
        "evaluations": evaluations,
        "gaps": gaps,
    }


def approval_route_for_step(step: dict[str, Any]) -> dict[str, Any]:
    state_result = evaluate_workflow_state(step)
    if state_result["decision"] != "VERIFIED":
        route = ApprovalRoute.BLOCKED
    else:
        route = ApprovalRoute.HUMAN_APPROVAL_REQUIRED
    return {
        "system": step.get("system", "UNKNOWN"),
        "route": route.value,
        "approval_required": route == ApprovalRoute.HUMAN_APPROVAL_REQUIRED,
        "execution_allowed": False,
        "gaps": state_result["gaps"],
        "contract_version": ORCHESTRATOR_VERSION,
    }


def approval_routing_report() -> dict[str, Any]:
    registry = workflow_registry_json()
    return {
        "contract_version": ORCHESTRATOR_VERSION,
        "decision": "VERIFIED",
        "routes": [approval_route_for_step(step) for step in registry["steps"]],
        "default_route": ApprovalRoute.HUMAN_APPROVAL_REQUIRED.value,
        "execution_allowed": False,
    }


def build_cross_system_audit_chain(records: list[dict[str, Any]]) -> dict[str, Any]:
    chain: list[dict[str, Any]] = []
    previous_hash = "GENESIS"
    for index, record in enumerate(records):
        safe_record = {
            "system": record.get("system"),
            "state": record.get("state"),
            "decision": record.get("decision"),
            "policy_hash": record.get("policy_hash", DEFAULT_POLICY_HASH),
        }
        record_hash = sha256_json(safe_record)
        current_hash = sha256_json({"index": index, "previous_hash": previous_hash, "record_hash": record_hash})
        chain.append(
            {
                "index": index,
                "system": safe_record["system"],
                "previous_hash": previous_hash,
                "record_hash": record_hash,
                "current_hash": current_hash,
            }
        )
        previous_hash = current_hash
    return {
        "contract_version": ORCHESTRATOR_VERSION,
        "decision": "VERIFIED",
        "record_count": len(chain),
        "latest_hash": previous_hash,
        "hash_chain": chain,
        "sensitive_data_stored": False,
        "external_execution_performed": False,
    }


def simulate_end_to_end_dry_run() -> dict[str, Any]:
    registry = workflow_registry_json()
    step_reports: list[dict[str, Any]] = []
    for step in registry["steps"]:
        state_result = evaluate_workflow_state(step)
        route = approval_route_for_step(step)
        step_reports.append(
            {
                "system": step["system"],
                "state": step["state"],
                "decision": state_result["decision"],
                "approval_route": route["route"],
                "execution_allowed": False,
                "policy_hash": DEFAULT_POLICY_HASH,
            }
        )
    audit_chain = build_cross_system_audit_chain(step_reports)
    return {
        "contract_version": ORCHESTRATOR_VERSION,
        "decision": "VERIFIED",
        "status": "READY_FOR_REVIEW",
        "workflow": list(WORKFLOW),
        "steps": step_reports,
        "audit_chain": audit_chain,
        "read_only_default": True,
        "dry_run_only": True,
        "production_activation_performed": False,
        "connector_activation_performed": False,
        "browser_automation_performed": False,
        "desktop_automation_performed": False,
        "terminal_write_commands_performed": False,
        "external_api_execution_performed": False,
    }
