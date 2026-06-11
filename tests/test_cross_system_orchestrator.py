from __future__ import annotations

from orchestration.cross_system_orchestrator import (
    WORKFLOW,
    approval_routing_report,
    build_cross_system_audit_chain,
    evaluate_workflow_state,
    simulate_end_to_end_dry_run,
    workflow_registry_json,
    workflow_state_engine_report,
)


def test_workflow_registry_defaults_read_only_and_dry_run_only() -> None:
    registry = workflow_registry_json()
    assert registry["workflow"] == list(WORKFLOW)
    assert registry["default_state"] == "READ_ONLY"
    assert registry["dry_run_only"] is True
    assert all(step["state"] == "READ_ONLY" for step in registry["steps"])
    assert all(step["connector_activation_allowed"] is False for step in registry["steps"])


def test_workflow_state_engine_fails_closed_on_unknown_state() -> None:
    result = evaluate_workflow_state({"system": "Mac", "state": "LIVE"})
    assert result["decision"] == "FAIL_CLOSED"
    assert result["state"] == "BLOCKED"
    assert "UNKNOWN_STATE" in result["gaps"]


def test_state_engine_blocks_any_activation_flag() -> None:
    step = workflow_registry_json()["steps"][0]
    step["external_api_execution_allowed"] = True
    result = evaluate_workflow_state(step)
    assert result["decision"] == "FAIL_CLOSED"
    assert "EXTERNAL_API_EXECUTION_ALLOWED_MUST_BE_FALSE" in result["gaps"]


def test_state_engine_report_verifies_default_registry() -> None:
    report = workflow_state_engine_report()
    assert report["decision"] == "VERIFIED"
    assert report["unknown_state_outcome"] == "FAIL_CLOSED"


def test_approval_routing_requires_human_approval_without_execution() -> None:
    report = approval_routing_report()
    assert report["decision"] == "VERIFIED"
    assert all(route["approval_required"] is True for route in report["routes"])
    assert all(route["execution_allowed"] is False for route in report["routes"])


def test_cross_system_audit_chain_links_records() -> None:
    chain = build_cross_system_audit_chain(
        [
            {"system": "LinkedIn", "state": "READ_ONLY", "decision": "VERIFIED"},
            {"system": "Terminal", "state": "READ_ONLY", "decision": "VERIFIED"},
        ]
    )
    assert chain["record_count"] == 2
    assert chain["hash_chain"][0]["previous_hash"] == "GENESIS"
    assert chain["hash_chain"][1]["previous_hash"] == chain["hash_chain"][0]["current_hash"]
    assert chain["sensitive_data_stored"] is False


def test_full_end_to_end_dry_run_performs_no_live_execution() -> None:
    result = simulate_end_to_end_dry_run()
    assert result["decision"] == "VERIFIED"
    assert result["workflow"] == list(WORKFLOW)
    assert result["production_activation_performed"] is False
    assert result["connector_activation_performed"] is False
    assert result["browser_automation_performed"] is False
    assert result["desktop_automation_performed"] is False
    assert result["terminal_write_commands_performed"] is False
    assert result["external_api_execution_performed"] is False
