from __future__ import annotations

from pathlib import Path
from typing import Any

from orchestration.cross_system_orchestrator import DEFAULT_POLICY_HASH, WORKFLOW, sha256_json
from pilot_operations.controlled_pilot_operations import APPROVED_DEVICE_IDS, APPROVED_OPERATOR_IDS
from pilot_operations.end_to_end_dry_run import build_pilot_go_no_go_report


LIVE_PILOT_AUTHORIZATION_VERSION = "pb281-285-controlled-live-pilot-authorization-v1"
REQUIRED_BOARD_ROLES = ("governance_owner", "security_owner", "pilot_operator", "incident_owner")


def pilot_scope_authorization_contract_json() -> dict[str, Any]:
    scope = {
        "workflow": list(WORKFLOW),
        "allowed_mode": "CONTROLLED_LIVE_PILOT_REVIEW_ONLY",
        "default_state": "BLOCKED",
        "policy_hash": DEFAULT_POLICY_HASH,
        "human_board_approval_required": True,
    }
    return {
        "contract_version": LIVE_PILOT_AUTHORIZATION_VERSION,
        "control": "PB-281 Pilot Scope Authorization",
        "decision": "READY_FOR_REVIEW",
        "scope": scope,
        "scope_hash": sha256_json(scope),
        "production_activation_allowed": False,
        "connector_activation_allowed": False,
        "browser_automation_allowed": False,
        "desktop_automation_allowed": False,
        "terminal_write_execution_allowed": False,
        "external_api_calls_allowed": False,
    }


def evaluate_pilot_scope_authorization(payload: dict[str, Any] | None) -> dict[str, Any]:
    gaps: list[str] = []
    if not isinstance(payload, dict):
        return {
            "decision": "FAIL_CLOSED",
            "state": "BLOCKED",
            "gaps": ["MALFORMED_SCOPE_AUTHORIZATION"],
            "contract_version": LIVE_PILOT_AUTHORIZATION_VERSION,
        }
    if payload.get("policy_hash") != DEFAULT_POLICY_HASH:
        gaps.append("UNKNOWN_POLICY_HASH")
    if payload.get("workflow") != list(WORKFLOW):
        gaps.append("UNAUTHORIZED_WORKFLOW_SCOPE")
    if payload.get("human_board_approval_required") is not True:
        gaps.append("MISSING_BOARD_APPROVAL_REQUIREMENT")
    for flag in (
        "production_activation_allowed",
        "connector_activation_allowed",
        "browser_automation_allowed",
        "desktop_automation_allowed",
        "terminal_write_execution_allowed",
        "external_api_calls_allowed",
    ):
        if payload.get(flag) is not False:
            gaps.append(f"{flag.upper()}_MUST_BE_FALSE")
    return {
        "decision": "READY_FOR_REVIEW" if not gaps else "FAIL_CLOSED",
        "state": "BLOCKED" if gaps else "BOARD_REVIEW_REQUIRED",
        "gaps": sorted(set(gaps)),
        "activation_allowed": False,
        "contract_version": LIVE_PILOT_AUTHORIZATION_VERSION,
    }


def operator_approval_authority_contract_json() -> dict[str, Any]:
    authority = {
        "approved_operator_ids": sorted(APPROVED_OPERATOR_IDS),
        "authority_state": "BOARD_REVIEW_REQUIRED",
        "unknown_operator_outcome": "BLOCKED",
        "delegation_allowed": False,
    }
    return {
        "contract_version": LIVE_PILOT_AUTHORIZATION_VERSION,
        "control": "PB-282 Operator Approval Authority",
        "default_state": "BLOCKED",
        "authority": authority,
        "authority_hash": sha256_json(authority),
        "activation_allowed": False,
    }


def evaluate_operator_approval_authority(operator_id: str | None, *, board_approved: bool = False) -> dict[str, Any]:
    gaps: list[str] = []
    if not operator_id:
        gaps.append("MISSING_OPERATOR")
    elif operator_id not in APPROVED_OPERATOR_IDS:
        gaps.append("UNKNOWN_OPERATOR")
    if not board_approved:
        gaps.append("MISSING_BOARD_OPERATOR_APPROVAL")
    return {
        "decision": "READY_FOR_REVIEW" if not gaps else "BLOCKED",
        "state": "BOARD_REVIEW_REQUIRED" if not gaps else "BLOCKED",
        "gaps": sorted(set(gaps)),
        "activation_allowed": False,
        "contract_version": LIVE_PILOT_AUTHORIZATION_VERSION,
    }


def device_approval_authority_contract_json() -> dict[str, Any]:
    authority = {
        "approved_device_ids": sorted(APPROVED_DEVICE_IDS),
        "authority_state": "BOARD_REVIEW_REQUIRED",
        "unknown_device_outcome": "BLOCKED",
        "delegation_allowed": False,
    }
    return {
        "contract_version": LIVE_PILOT_AUTHORIZATION_VERSION,
        "control": "PB-283 Device Approval Authority",
        "default_state": "BLOCKED",
        "authority": authority,
        "authority_hash": sha256_json(authority),
        "activation_allowed": False,
    }


def evaluate_device_approval_authority(device_id: str | None, *, board_approved: bool = False) -> dict[str, Any]:
    gaps: list[str] = []
    if not device_id:
        gaps.append("MISSING_DEVICE")
    elif device_id not in APPROVED_DEVICE_IDS:
        gaps.append("UNKNOWN_DEVICE")
    if not board_approved:
        gaps.append("MISSING_BOARD_DEVICE_APPROVAL")
    return {
        "decision": "READY_FOR_REVIEW" if not gaps else "BLOCKED",
        "state": "BOARD_REVIEW_REQUIRED" if not gaps else "BLOCKED",
        "gaps": sorted(set(gaps)),
        "activation_allowed": False,
        "contract_version": LIVE_PILOT_AUTHORIZATION_VERSION,
    }


def incident_ownership_matrix_json() -> dict[str, Any]:
    matrix = [
        {
            "incident_type": "approval_failure",
            "owner_role": "governance_owner",
            "required_action": "activate_kill_switch_and_preserve_evidence",
        },
        {
            "incident_type": "nonce_failure",
            "owner_role": "security_owner",
            "required_action": "block_replay_and_preserve_nonce_evidence",
        },
        {
            "incident_type": "replay_failure",
            "owner_role": "security_owner",
            "required_action": "block_action_and_record_replay_evidence",
        },
        {
            "incident_type": "audit_failure",
            "owner_role": "incident_owner",
            "required_action": "disable_pilot_and_preserve_audit_gap",
        },
        {
            "incident_type": "device_failure",
            "owner_role": "incident_owner",
            "required_action": "disable_device_authority_and_preserve_attestation_gap",
        },
    ]
    return {
        "contract_version": LIVE_PILOT_AUTHORIZATION_VERSION,
        "control": "PB-284 Incident Ownership Matrix",
        "default_state": "BLOCKED",
        "matrix": matrix,
        "matrix_hash": sha256_json(matrix),
        "kill_switch_required": True,
        "activation_allowed": False,
    }


def evaluate_incident_ownership_matrix(matrix: list[dict[str, Any]] | None) -> dict[str, Any]:
    required_incidents = {"approval_failure", "nonce_failure", "replay_failure", "audit_failure", "device_failure"}
    gaps: list[str] = []
    if not isinstance(matrix, list):
        return {
            "decision": "FAIL_CLOSED",
            "gaps": ["MALFORMED_INCIDENT_MATRIX"],
            "contract_version": LIVE_PILOT_AUTHORIZATION_VERSION,
        }
    covered = {entry.get("incident_type") for entry in matrix if isinstance(entry, dict)}
    for missing in sorted(required_incidents - covered):
        gaps.append(f"MISSING_INCIDENT_OWNER_{missing.upper()}")
    for entry in matrix:
        if not isinstance(entry, dict):
            gaps.append("MALFORMED_INCIDENT_OWNER")
            continue
        if not entry.get("owner_role"):
            gaps.append("MISSING_OWNER_ROLE")
        if not entry.get("required_action"):
            gaps.append("MISSING_REQUIRED_ACTION")
    return {
        "decision": "READY_FOR_REVIEW" if not gaps else "FAIL_CLOSED",
        "gaps": sorted(set(gaps)),
        "activation_allowed": False,
        "contract_version": LIVE_PILOT_AUTHORIZATION_VERSION,
    }


def pilot_go_no_go_governance_board_json(evidence_root: str | Path) -> dict[str, Any]:
    dry_run_report = build_pilot_go_no_go_report(evidence_root)
    board = {
        "required_roles": list(REQUIRED_BOARD_ROLES),
        "approval_status": "BOARD_REVIEW_REQUIRED",
        "default_decision": "NO_GO",
        "dry_run_go_no_go_decision": dry_run_report["go_no_go_decision"],
    }
    return {
        "contract_version": LIVE_PILOT_AUTHORIZATION_VERSION,
        "control": "PB-285 Pilot Go/No-Go Governance Board",
        "decision": "READY_FOR_REVIEW" if dry_run_report["decision"] == "VERIFIED" else "FAIL_CLOSED",
        "status": "READY_FOR_REVIEW" if dry_run_report["decision"] == "VERIFIED" else "REVIEW_REQUIRED",
        "go_no_go_decision": "NO_GO_PENDING_BOARD_APPROVAL",
        "board": board,
        "board_hash": sha256_json(board),
        "live_pilot_activation_allowed": False,
        "production_activation_allowed": False,
        "connector_activation_allowed": False,
        "browser_automation_allowed": False,
        "desktop_automation_allowed": False,
        "terminal_write_execution_allowed": False,
        "external_api_calls_allowed": False,
        "gaps": dry_run_report["gaps"],
    }
