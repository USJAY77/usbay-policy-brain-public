from __future__ import annotations

import json

from governance.connector_framework import ConnectorAction, connector_registry
from governance.connector_orchestrator_simulation import (
    WORKFLOW_ORDER,
    generate_pb039_report,
    generated_pr_body,
    simulate_connector_workflow,
)


def test_approved_dry_run_workflow_passes() -> None:
    report = simulate_connector_workflow()

    assert report["decision"] == "VERIFIED"
    assert report["status"] == "READY_FOR_REVIEW"
    assert report["dry_run_only"] is True
    assert report["live_external_execution"] is False
    assert [step["connector_name"] for step in report["steps"]] == list(WORKFLOW_ORDER)
    assert all(step["decision"] == "APPROVED_DRY_RUN" for step in report["steps"])
    assert all(step["audit_output"]["external_mutation_performed"] is False for step in report["steps"])


def test_unknown_connector_blocks() -> None:
    report = simulate_connector_workflow([ConnectorAction("Unknown", "sync", permissions=("unknown:write",))])

    assert report["decision"] == "BLOCKED"
    assert report["status"] == "FAIL_CLOSED"
    assert "unknown_connector" in report["steps"][0]["blockers"]


def test_missing_permission_blocks() -> None:
    registry = connector_registry()
    report = simulate_connector_workflow([ConnectorAction("GitHub", registry["GitHub"].action_type)])

    assert report["decision"] == "BLOCKED"
    assert "missing_permission" in report["steps"][0]["blockers"]


def test_external_public_action_without_human_approval_blocks() -> None:
    registry = connector_registry()
    report = simulate_connector_workflow(
        [
            ConnectorAction(
                "LinkedIn",
                registry["LinkedIn"].action_type,
                permissions=(registry["LinkedIn"].required_permission,),
            )
        ]
    )

    assert report["decision"] == "BLOCKED"
    assert "approval_required" in report["steps"][0]["blockers"]


def test_connector_failure_blocks() -> None:
    registry = connector_registry()
    report = simulate_connector_workflow(
        [
            ConnectorAction(
                "GitHub",
                registry["GitHub"].action_type,
                permissions=(registry["GitHub"].required_permission,),
                connector_error="simulated_connector_failure",
            )
        ]
    )

    assert report["decision"] == "BLOCKED"
    assert "connector_error" in report["steps"][0]["blockers"]


def test_sensitive_payloads_are_redacted() -> None:
    registry = connector_registry()
    report = simulate_connector_workflow(
        [
            ConnectorAction(
                "GitHub",
                registry["GitHub"].action_type,
                permissions=(registry["GitHub"].required_permission,),
                payload={"token": "raw-token-value", "nested": {"api_key": "raw-api-key"}},
            )
        ]
    )
    encoded = json.dumps(report)

    assert report["decision"] == "VERIFIED"
    assert report["steps"][0]["audit_output"]["sensitive_data_detected"] is True
    assert report["steps"][0]["audit_output"]["raw_payload_logged"] is False
    assert "raw-token-value" not in encoded
    assert "raw-api-key" not in encoded


def test_full_workflow_produces_audit_evidence() -> None:
    report = simulate_connector_workflow()

    assert len(report["audit_hashes"]) == 6
    assert report["workflow_hash"]
    for step in report["steps"]:
        assert step["policy_brain"]["policy_hash"]
        assert step["connector_registry"]["registry_hash"]
        assert step["audit_output"]["audit_hash"]
        assert step["audit_output"]["audit_payload_hash"]


def test_non_dry_run_action_blocks_without_mutation() -> None:
    registry = connector_registry()
    report = simulate_connector_workflow(
        [
            ConnectorAction(
                "GitHub",
                registry["GitHub"].action_type,
                permissions=(registry["GitHub"].required_permission,),
                dry_run=False,
            )
        ]
    )

    assert report["decision"] == "BLOCKED"
    assert "live_external_execution_forbidden" in report["steps"][0]["blockers"]
    assert "live_external_mutation_disabled" in report["steps"][0]["blockers"]
    assert report["steps"][0]["audit_output"]["external_mutation_performed"] is False


def test_generated_pr_body_has_required_sections_without_placeholders() -> None:
    body = generated_pr_body()
    required = [
        "PURPOSE",
        "RISK",
        "POLICY LINK",
        "REQUIRED APPROVALS",
        "GOVERNANCE CHECKS",
        "AUDIT",
        "IMPACT",
        "Decision",
        "Status",
    ]
    forbidden = [
        "Describe what is changing and why.",
        "System impact:",
        "User impact:",
        "Risk level:",
        "Policy ID:",
        "Policy version/hash:",
        "Policy version / hash:",
    ]

    assert all(f"## {section}" in body for section in required)
    assert not any(value in body for value in forbidden)


def test_pb039_report_contains_required_evidence(tmp_path) -> None:
    report = generate_pb039_report(tmp_path)
    encoded = json.dumps(report)

    assert report["decision"] == "VERIFIED"
    assert report["status"] == "READY_FOR_REVIEW"
    assert report["uses_pb038_connector_framework"] is True
    assert report["approved_dry_run_workflow"]["decision"] == "VERIFIED"
    assert report["blocked_examples"]["unknown_connector"]["decision"] == "BLOCKED"
    assert report["blocked_examples"]["missing_permission"]["decision"] == "BLOCKED"
    assert report["blocked_examples"]["external_public_action_without_human_approval"]["decision"] == "BLOCKED"
    assert report["blocked_examples"]["connector_failure"]["decision"] == "BLOCKED"
    assert report["external_mutations"] == {
        "api_calls": False,
        "posts": False,
        "messages": False,
        "emails": False,
        "account_changes": False,
    }
    assert report["sensitive_data_in_logs"] is False
    assert "raw-token-value" not in encoded
    assert (tmp_path / "connector_orchestrator_simulation_report.json").is_file()
    assert (tmp_path / "generated_pr_body.md").is_file()
