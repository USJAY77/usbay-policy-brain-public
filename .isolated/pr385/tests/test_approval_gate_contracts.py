from __future__ import annotations

from datetime import datetime, timezone

from approval_gate_contracts import (
    APPROVAL_GATE_CONTRACT_VERSION,
    ApprovalState,
    HumanReviewStep,
    approval_gate_for_orchestration_event,
    approval_record_schema,
    build_approval_identifier,
    build_approval_record,
    example_approval_gate_mapping,
    human_review_workflow,
    sha256_payload,
    validate_approval_gate_mapping,
)
from connectors.connector_contracts import ApprovalGate


NOW = datetime(2026, 6, 13, tzinfo=timezone.utc)
FUTURE = "2026-06-14T00:00:00Z"
PAST = "2026-06-12T00:00:00Z"


def _example_parts() -> tuple[dict, dict, dict]:
    example = example_approval_gate_mapping()
    return example["orchestration_event"], example["connector_event"], example["approval_record"]


def test_approval_gate_for_orchestration_event_maps_pb310_to_pb312_gate() -> None:
    event, _connector, _approval = _example_parts()

    assert approval_gate_for_orchestration_event(event) == ApprovalGate.GITHUB_WORK_ITEM_WRITE

    report_event = dict(event, source_system="Executive Report", requested_action="share_report_externally")
    assert approval_gate_for_orchestration_event(report_event) == ApprovalGate.EXECUTIVE_REPORT_EXTERNAL_SHARE


def test_approval_identifier_is_deterministic_and_hash_linked() -> None:
    event, _connector, _approval = _example_parts()

    first = build_approval_identifier(event)
    second = build_approval_identifier(event)

    assert first == second
    assert first["approval_id"].startswith("approval_")
    assert len(first["approval_id"]) == 41
    assert first["approval_gate"] == ApprovalGate.GITHUB_WORK_ITEM_WRITE.value
    assert first["requested_action_hash"] == sha256_payload(event["requested_action"])
    assert first["policy_hash"] == event["policy_hash"]
    assert first["audit_hash"] == event["audit_hash"]


def test_approval_record_schema_is_hash_only_and_human_review_required() -> None:
    schema = approval_record_schema()

    assert schema["title"] == "USBAY Approval Gate Record"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["human_review_required"]["const"] is True
    assert "actor" not in schema["properties"]
    assert "reviewer" not in schema["properties"]
    assert "actor_hash" in schema["required"]
    assert "reviewer_hash" in schema["required"]


def test_human_review_workflow_blocks_auto_approval() -> None:
    workflow = human_review_workflow()

    assert workflow["contract_version"] == APPROVAL_GATE_CONTRACT_VERSION
    assert workflow["requires_explicit_human_decision"] is True
    assert workflow["auto_approval_allowed"] is False
    assert workflow["missing_review_outcome"] == "FAIL_CLOSED"
    assert set(workflow["steps"]) == {step.value for step in HumanReviewStep}


def test_valid_approval_gate_mapping_verifies_without_execution() -> None:
    event, connector, approval = _example_parts()

    result = validate_approval_gate_mapping(
        orchestration_event=event,
        connector_event=connector,
        approval_record=approval,
        now=NOW,
    )

    assert result["contract_version"] == APPROVAL_GATE_CONTRACT_VERSION
    assert result["decision"] == "VERIFIED"
    assert result["execution_status"] == "PENDING_HUMAN_APPROVAL_VERIFIED"
    assert result["approval_id"] == approval["approval_id"]
    assert result["approval_gate"] == ApprovalGate.GITHUB_WORK_ITEM_WRITE.value
    assert result["external_calls_performed"] is False
    assert result["gaps"] == []


def test_missing_approval_fails_closed() -> None:
    event, connector, _approval = _example_parts()

    result = validate_approval_gate_mapping(
        orchestration_event=event,
        connector_event=connector,
        approval_record=None,
        now=NOW,
    )

    assert result["decision"] == "FAIL_CLOSED"
    assert result["execution_status"] == "BLOCKED"
    assert "APPROVAL_RECORD_MISSING" in result["gaps"]


def test_rejected_approval_fails_closed() -> None:
    event, connector, approval = _example_parts()
    approval["approval_state"] = ApprovalState.REJECTED.value

    result = validate_approval_gate_mapping(
        orchestration_event=event,
        connector_event=connector,
        approval_record=approval,
        now=NOW,
    )

    assert result["decision"] == "FAIL_CLOSED"
    assert "APPROVAL_NOT_APPROVED" in result["gaps"]


def test_expired_approval_fails_closed() -> None:
    event, connector, approval = _example_parts()
    approval["expires_at"] = PAST

    result = validate_approval_gate_mapping(
        orchestration_event=event,
        connector_event=connector,
        approval_record=approval,
        now=NOW,
    )

    assert result["decision"] == "FAIL_CLOSED"
    assert "APPROVAL_EXPIRED" in result["gaps"]


def test_mismatched_approval_id_fails_closed() -> None:
    event, connector, approval = _example_parts()
    approval["approval_id"] = "approval_" + "0" * 32

    result = validate_approval_gate_mapping(
        orchestration_event=event,
        connector_event=connector,
        approval_record=approval,
        now=NOW,
    )

    assert result["decision"] == "FAIL_CLOSED"
    assert "APPROVAL_ID_MISMATCH" in result["gaps"]
    assert "CONNECTOR_APPROVAL_LINK_MISMATCH" in result["gaps"]


def test_missing_approval_evidence_fails_closed() -> None:
    event, connector, approval = _example_parts()
    approval["evidence_hash"] = ""

    result = validate_approval_gate_mapping(
        orchestration_event=event,
        connector_event=connector,
        approval_record=approval,
        now=NOW,
    )

    assert result["decision"] == "FAIL_CLOSED"
    assert "APPROVAL_EVIDENCE_MISSING" in result["gaps"]


def test_connector_policy_deny_fails_closed() -> None:
    event, connector, approval = _example_parts()
    connector["policy_decision"] = "DENY"

    result = validate_approval_gate_mapping(
        orchestration_event=event,
        connector_event=connector,
        approval_record=approval,
        now=NOW,
    )

    assert result["decision"] == "FAIL_CLOSED"
    assert "CONNECTOR_EVENT_INVALID" in result["gaps"]
    assert "POLICY_NOT_ALLOW" in result["gaps"]


def test_build_approval_record_hashes_actor_and_reviewer() -> None:
    event, _connector, _approval = _example_parts()

    record = build_approval_record(
        event,
        approval_state=ApprovalState.APPROVED,
        actor="operator:local",
        reviewer="human:reviewer",
        created_at="2026-06-13T00:00:00Z",
        expires_at=FUTURE,
        evidence_hash=sha256_payload({"evidence": "record"}),
    )

    assert record["contract_version"] == APPROVAL_GATE_CONTRACT_VERSION
    assert record["actor_hash"] == sha256_payload("operator:local")
    assert record["reviewer_hash"] == sha256_payload("human:reviewer")
    assert "operator:local" not in str(record)
    assert "human:reviewer" not in str(record)
