from __future__ import annotations

from pathlib import Path
from typing import Any

from orchestration.cross_system_orchestrator import (
    DEFAULT_POLICY_HASH,
    WORKFLOW,
    build_cross_system_audit_chain,
    evaluate_workflow_state,
    sha256_json,
    workflow_registry_json,
)
from pilot_operations.controlled_pilot_operations import (
    PILOT_OPERATIONS_VERSION,
    certify_pilot_readiness,
    validate_pilot_device,
    validate_pilot_operator,
)


END_TO_END_DRY_RUN_VERSION = "pb276-280-first-controlled-end-to-end-dry-run-v1"


def build_end_to_end_dry_run_scenario() -> dict[str, Any]:
    registry = workflow_registry_json()
    steps: list[dict[str, Any]] = []
    for step in registry["steps"]:
        state_result = evaluate_workflow_state(step)
        evidence_payload = {
            "sequence": step["sequence"],
            "system": step["system"],
            "state": step["state"],
            "decision": state_result["decision"],
            "policy_hash": DEFAULT_POLICY_HASH,
        }
        steps.append(
            {
                **evidence_payload,
                "audit_evidence_hash": sha256_json(evidence_payload),
                "execution_allowed": False,
                "connector_activation_allowed": False,
                "browser_automation_allowed": False,
                "desktop_execution_allowed": False,
                "terminal_write_allowed": False,
                "external_api_calls_allowed": False,
                "gaps": state_result["gaps"],
            }
        )
    gaps = sorted({gap for step in steps for gap in step["gaps"]})
    return {
        "contract_version": END_TO_END_DRY_RUN_VERSION,
        "uses_controls": ["PB-241", "PB-245", "PB-261", "PB-265", "PB-271", "PB-275"],
        "workflow": list(WORKFLOW),
        "default_state": "READ_ONLY",
        "runtime_mode": "DRY_RUN",
        "decision": "VERIFIED" if not gaps else "FAIL_CLOSED",
        "status": "READY_FOR_REVIEW" if not gaps else "REVIEW_REQUIRED",
        "steps": steps,
        "gaps": gaps,
        "production_activation_allowed": False,
        "connector_activation_allowed": False,
        "browser_automation_allowed": False,
        "desktop_execution_allowed": False,
        "terminal_write_commands_allowed": False,
        "external_api_calls_allowed": False,
    }


def simulate_operator_approval(operator_id: str | None, *, approval_present: bool = True) -> dict[str, Any]:
    validation = validate_pilot_operator(operator_id)
    gaps = list(validation["gaps"])
    if not approval_present:
        gaps.append("MISSING_OPERATOR_APPROVAL")
    evidence = {
        "operator_id_hash": sha256_json(operator_id or "MISSING"),
        "approval_present": approval_present,
        "validation_decision": validation["decision"],
        "policy_hash": DEFAULT_POLICY_HASH,
    }
    return {
        "contract_version": END_TO_END_DRY_RUN_VERSION,
        "control": "PB-277 Operator Approval Simulation",
        "decision": "VERIFIED" if not gaps else "BLOCKED",
        "state": "READ_ONLY" if not gaps else "BLOCKED",
        "approval_required": True,
        "execution_allowed": False,
        "gaps": sorted(set(gaps)),
        "operator_evidence_hash": sha256_json(evidence),
    }


def simulate_device_approval(
    device_id: str | None,
    *,
    approval_present: bool = True,
    registry_present: bool = True,
) -> dict[str, Any]:
    validation = validate_pilot_device(device_id) if registry_present else {"decision": "BLOCKED", "gaps": ["MISSING_DEVICE_REGISTRY"]}
    gaps = list(validation["gaps"])
    if not approval_present:
        gaps.append("MISSING_DEVICE_APPROVAL")
    evidence = {
        "device_id_hash": sha256_json(device_id or "MISSING"),
        "approval_present": approval_present,
        "registry_present": registry_present,
        "validation_decision": validation["decision"],
        "policy_hash": DEFAULT_POLICY_HASH,
    }
    return {
        "contract_version": END_TO_END_DRY_RUN_VERSION,
        "control": "PB-278 Device Approval Simulation",
        "decision": "VERIFIED" if not gaps else "BLOCKED",
        "state": "READ_ONLY" if not gaps else "BLOCKED",
        "approval_required": True,
        "execution_allowed": False,
        "gaps": sorted(set(gaps)),
        "device_evidence_hash": sha256_json(evidence),
    }


def build_cross_system_evidence_trace(scenario: dict[str, Any] | None = None) -> dict[str, Any]:
    scenario = scenario or build_end_to_end_dry_run_scenario()
    steps = scenario.get("steps", []) if isinstance(scenario, dict) else []
    trace_records: list[dict[str, Any]] = []
    gaps: list[str] = []
    expected_systems = list(WORKFLOW)
    if len(steps) != len(expected_systems):
        gaps.append("MISSING_WORKFLOW_STEPS")
    for index, system in enumerate(expected_systems, start=1):
        matching = next((step for step in steps if step.get("system") == system), None)
        if not matching:
            gaps.append(f"MISSING_EVIDENCE_{system.upper().replace(' ', '_')}")
            continue
        if not matching.get("audit_evidence_hash"):
            gaps.append(f"MISSING_AUDIT_EVIDENCE_{system.upper().replace(' ', '_')}")
        if matching.get("decision") != "VERIFIED":
            gaps.append(f"UNVERIFIED_STEP_{system.upper().replace(' ', '_')}")
        trace_records.append(
            {
                "sequence": index,
                "system": system,
                "state": matching.get("state", "UNKNOWN"),
                "decision": matching.get("decision", "FAIL_CLOSED"),
                "policy_hash": DEFAULT_POLICY_HASH,
                "audit_evidence_hash": matching.get("audit_evidence_hash"),
            }
        )
    audit_chain = build_cross_system_audit_chain(trace_records)
    return {
        "contract_version": END_TO_END_DRY_RUN_VERSION,
        "control": "PB-279 Cross-System Evidence Trace",
        "decision": "VERIFIED" if not gaps else "FAIL_CLOSED",
        "status": "READY_FOR_REVIEW" if not gaps else "REVIEW_REQUIRED",
        "record_count": len(trace_records),
        "trace_records": trace_records,
        "audit_chain": audit_chain,
        "gaps": sorted(set(gaps)),
        "sensitive_data_stored": False,
        "external_execution_performed": False,
    }


def build_pilot_go_no_go_report(
    evidence_root: str | Path,
    *,
    operator_id: str | None = "pilot-operator-usbay-governance-001",
    device_id: str | None = "pilot-device-mac-local-001",
) -> dict[str, Any]:
    readiness = certify_pilot_readiness(evidence_root)
    scenario = build_end_to_end_dry_run_scenario()
    operator = simulate_operator_approval(operator_id)
    device = simulate_device_approval(device_id)
    trace = build_cross_system_evidence_trace(scenario)
    gaps = sorted(
        set(readiness["gaps"])
        | set(scenario["gaps"])
        | set(operator["gaps"])
        | set(device["gaps"])
        | set(trace["gaps"])
    )
    dry_run_ready = not gaps and readiness["decision"] == "VERIFIED"
    return {
        "contract_version": END_TO_END_DRY_RUN_VERSION,
        "control": "PB-280 Pilot Go/No-Go Report",
        "decision": "VERIFIED" if dry_run_ready else "FAIL_CLOSED",
        "status": "READY_FOR_REVIEW" if dry_run_ready else "REVIEW_REQUIRED",
        "go_no_go_decision": "GO_FOR_REVIEW_NO_GO_FOR_LIVE_ACTIVATION" if dry_run_ready else "NO_GO",
        "dry_run_ready_for_review": dry_run_ready,
        "live_pilot_activation_allowed": False,
        "production_activation_allowed": False,
        "connector_activation_allowed": False,
        "desktop_execution_allowed": False,
        "terminal_write_commands_allowed": False,
        "external_api_calls_allowed": False,
        "gaps": gaps,
        "control_versions": {
            "pilot_operations": PILOT_OPERATIONS_VERSION,
            "dry_run": END_TO_END_DRY_RUN_VERSION,
        },
    }
