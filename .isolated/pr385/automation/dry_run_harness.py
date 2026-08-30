from __future__ import annotations

from pathlib import Path
from typing import Any

from audit.audit_writer import AuditWriteError, write_audit_record
from connectors.connector_contracts import GovernedConnectorState, default_connector_contracts


DRY_RUN_HARNESS_VERSION = "pb215-dry-run-automation-harness-v1"
FLOW = ("LinkedIn", "Notion", "Euria", "USBAY Control Plane", "GitHub", "Codex")


def simulate_dry_run_flow(
    *,
    actor: str,
    policy_hash: str,
    audit_path: str | Path = "tmp/pb215_dry_run_automation_audit.json",
) -> dict[str, Any]:
    contracts = default_connector_contracts()
    steps: list[dict[str, Any]] = []
    for index, system in enumerate(FLOW, start=1):
        contract = contracts.get(system)
        connector_state = contract.state.value if contract else GovernedConnectorState.DRY_RUN.value
        steps.append(
            {
                "sequence": index,
                "system": system,
                "mode": "DRY_RUN",
                "connector_state": connector_state,
                "live_action_performed": False,
                "external_call_performed": False,
                "status": "SIMULATED" if connector_state != GovernedConnectorState.BLOCKED.value else "BLOCKED",
            }
        )

    audit_payload = {
        "actor": actor,
        "device": "dry_run_harness",
        "decision": "DENY",
        "policy_hash": policy_hash,
        "policy_version": "1.0.0",
        "flow": [step["system"] for step in steps],
        "step_count": len(steps),
        "dry_run_only": True,
        "live_browser_actions": False,
        "live_desktop_actions": False,
        "live_api_actions": False,
        "live_connector_actions": False,
        "production_actions": False,
        "harness_version": DRY_RUN_HARNESS_VERSION,
    }
    try:
        audit = write_audit_record("pb215_dry_run_automation", audit_payload, audit_path=audit_path)
    except AuditWriteError as exc:
        return {
            "decision": "FAIL_CLOSED",
            "status": "AUDIT_FAILED",
            "gaps": [str(exc)],
            "steps": steps,
            "audit": None,
            "harness_version": DRY_RUN_HARNESS_VERSION,
            "production_automation_activated": False,
        }

    return {
        "decision": "VERIFIED",
        "status": "DRY_RUN_ONLY",
        "gaps": [],
        "steps": steps,
        "audit": {
            "audit_hash": audit["audit_hash"],
            "payload_hash": audit["payload_hash"],
            "timestamp": audit["timestamp"],
        },
        "harness_version": DRY_RUN_HARNESS_VERSION,
        "external_calls_performed": False,
        "production_automation_activated": False,
    }
