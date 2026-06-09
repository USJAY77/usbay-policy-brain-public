from __future__ import annotations

import json

from governance.connector_framework import (
    ACTION_APPROVED_DRY_RUN,
    ACTION_BLOCKED,
    ConnectorAction,
    connector_registry,
    contains_sensitive_data,
    evaluate_connector_action,
    generate_pb038_report,
    run_dry_run_actions,
)


def test_known_connector_dry_run_passes() -> None:
    result = evaluate_connector_action(
        ConnectorAction(
            connector_name="GitHub",
            action_type="sync_pr_metadata",
            permissions=("github:metadata:write",),
        )
    )

    assert result["decision"] == ACTION_APPROVED_DRY_RUN
    assert result["blockers"] == []
    assert result["audit_record"]["dry_run"] is True
    assert result["audit_record"]["external_mutation_performed"] is False


def test_unknown_connector_blocks() -> None:
    result = evaluate_connector_action(
        ConnectorAction(
            connector_name="Unknown",
            action_type="sync_pr_metadata",
            permissions=("github:metadata:write",),
        )
    )

    assert result["decision"] == ACTION_BLOCKED
    assert "unknown_connector" in result["blockers"]


def test_missing_permission_blocks() -> None:
    result = evaluate_connector_action(
        ConnectorAction(
            connector_name="GitHub",
            action_type="sync_pr_metadata",
            permissions=(),
        )
    )

    assert result["decision"] == ACTION_BLOCKED
    assert "missing_permission" in result["blockers"]


def test_required_approval_blocks_without_approval() -> None:
    result = evaluate_connector_action(
        ConnectorAction(
            connector_name="Notion",
            action_type="sync_evidence_page",
            permissions=("notion:workspace:write",),
        )
    )

    assert result["decision"] == ACTION_BLOCKED
    assert "approval_required" in result["blockers"]


def test_connector_error_blocks() -> None:
    result = evaluate_connector_action(
        ConnectorAction(
            connector_name="GitHub",
            action_type="sync_pr_metadata",
            permissions=("github:metadata:write",),
            connector_error="simulated failure",
        )
    )

    assert result["decision"] == ACTION_BLOCKED
    assert "connector_error" in result["blockers"]


def test_sensitive_fields_are_not_written_raw_to_audit() -> None:
    result = evaluate_connector_action(
        ConnectorAction(
            connector_name="GitHub",
            action_type="sync_pr_metadata",
            permissions=("github:metadata:write",),
            payload={"token": "raw-token-value", "nested": {"api_key": "raw-api-key"}, "safe": "metadata"},
        )
    )
    encoded = json.dumps(result)

    assert contains_sensitive_data({"token": "raw-token-value"}) is True
    assert result["audit_record"]["sensitive_data_detected"] is True
    assert result["audit_record"]["raw_payload_logged"] is False
    assert "raw-token-value" not in encoded
    assert "raw-api-key" not in encoded
    assert "[REDACTED]" in encoded


def test_no_live_external_mutation_occurs() -> None:
    result = evaluate_connector_action(
        ConnectorAction(
            connector_name="LinkedIn",
            action_type="prepare_profile_update",
            permissions=("linkedin:profile:write",),
            approval_id="APPROVAL-DRY-RUN",
            dry_run=False,
        )
    )

    assert result["decision"] == ACTION_BLOCKED
    assert "live_external_mutation_disabled" in result["blockers"]
    assert result["audit_record"]["external_mutation_performed"] is False


def test_all_registry_connectors_have_required_governance_fields() -> None:
    registry = connector_registry()

    assert set(registry) == {"GitHub", "Codex", "Notion", "Euria", "LinkedIn", "USBAY Control Plane"}
    for policy in registry.values():
        assert policy.connector_name
        assert policy.action_type
        assert policy.required_permission
        assert policy.audit_output
        assert policy.fail_closed_on_error is True
        assert policy.dry_run_supported is True
        assert policy.sensitive_fields_redacted is True


def test_dry_run_execution_report_blocks_when_any_action_blocks() -> None:
    report = run_dry_run_actions(
        [
            ConnectorAction("GitHub", "sync_pr_metadata", permissions=("github:metadata:write",)),
            ConnectorAction("GitHub", "sync_pr_metadata", permissions=()),
        ]
    )

    assert report["decision"] == "BLOCKED"
    assert report["blocked_count"] == 1
    assert report["external_mutation_performed"] is False


def test_pb038_report_contains_required_evidence(tmp_path) -> None:
    report = generate_pb038_report(tmp_path)
    encoded = json.dumps(report)

    assert report["decision"] == "VERIFIED"
    assert report["dry_run_default"] is True
    assert report["live_external_mutations_allowed"] is False
    assert len(report["connectors"]) == 6
    assert report["allowed_dry_run_actions"]["decision"] == "VERIFIED"
    assert report["blocked_examples"]
    assert report["approval_required_examples"]
    assert report["fail_closed_behavior"]["unknown_connector"] == "BLOCK"
    assert "raw-token-value" not in encoded
    assert (tmp_path / "connector_framework_report.json").is_file()
    assert (tmp_path / "generated_pr_body.md").is_file()
