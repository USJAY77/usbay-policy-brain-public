from __future__ import annotations

import json

from orchestration.orchestration_contracts import (
    APPROVAL_CHECKPOINTS,
    ORCHESTRATION_CONTRACT_VERSION,
    REQUIRED_AUDIT_FIELDS,
    REQUIRED_EVENT_FIELDS,
    audit_evidence_contract,
    audit_evidence_contract_schema,
    approval_checkpoints_contract,
    build_audit_evidence,
    example_orchestration_event,
    orchestration_contract_schema,
    sha256_payload,
    validate_orchestration_event,
)


def test_orchestration_contract_schema_defines_required_fields() -> None:
    schema = orchestration_contract_schema()

    assert schema["title"] == "USBAY Orchestration Event Contract"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(REQUIRED_EVENT_FIELDS)
    assert "LinkedIn" in schema["properties"]["source_system"]["enum"]
    assert "Evidence Layer" in schema["properties"]["source_system"]["enum"]
    assert "BLOCKED" in schema["properties"]["execution_status"]["enum"]


def test_audit_evidence_schema_is_hash_only() -> None:
    schema = audit_evidence_contract_schema()

    assert set(schema["required"]) == set(REQUIRED_AUDIT_FIELDS)
    assert "actor" not in schema["properties"]
    assert "requested_action" not in schema["properties"]
    assert schema["properties"]["actor_hash"]["pattern"] == "^[0-9a-fA-F]{64}$"
    assert schema["properties"]["requested_action_hash"]["pattern"] == "^[0-9a-fA-F]{64}$"


def test_example_orchestration_event_verifies_locally() -> None:
    event = example_orchestration_event()

    result = validate_orchestration_event(event)

    assert result["contract_version"] == ORCHESTRATION_CONTRACT_VERSION
    assert result["decision"] == "VERIFIED"
    assert result["execution_status"] == "DRY_RUN_READY"
    assert result["external_execution_performed"] is False
    assert result["gaps"] == []


def test_missing_connector_fails_closed() -> None:
    event = example_orchestration_event()
    event["connector_available"] = False

    result = validate_orchestration_event(event)

    assert result["decision"] == "FAIL_CLOSED"
    assert result["execution_status"] == "BLOCKED"
    assert "CONNECTOR_MISSING" in result["gaps"]


def test_missing_policy_fails_closed() -> None:
    event = example_orchestration_event()
    event["policy_hash"] = ""

    result = validate_orchestration_event(event)

    assert result["decision"] == "FAIL_CLOSED"
    assert "POLICY_HASH_MISSING_OR_MALFORMED" in result["gaps"]


def test_missing_approval_fails_closed_for_high_risk_action() -> None:
    event = example_orchestration_event()
    event["approval_id"] = None

    result = validate_orchestration_event(event)

    assert result["decision"] == "FAIL_CLOSED"
    assert result["execution_status"] == "BLOCKED"
    assert "HUMAN_APPROVAL_REQUIRED" in result["gaps"]


def test_missing_audit_evidence_fails_closed() -> None:
    event = example_orchestration_event()
    event["audit_evidence_present"] = False

    result = validate_orchestration_event(event)

    assert result["decision"] == "FAIL_CLOSED"
    assert "AUDIT_EVIDENCE_MISSING" in result["gaps"]


def test_sensitive_log_metadata_fails_closed_without_exporting_raw_value() -> None:
    event = example_orchestration_event()
    event["log_metadata"] = {"token": "raw-token-value"}

    result = validate_orchestration_event(event)

    assert result["decision"] == "FAIL_CLOSED"
    assert "SENSITIVE_DATA_IN_LOGS" in result["gaps"]
    assert "raw-token-value" not in json.dumps(result)


def test_critical_risk_always_blocks() -> None:
    event = example_orchestration_event()
    event["risk_level"] = "CRITICAL"

    result = validate_orchestration_event(event)

    assert result["decision"] == "FAIL_CLOSED"
    assert "CRITICAL_RISK_BLOCKED" in result["gaps"]


def test_approval_checkpoints_contract_lists_human_gates() -> None:
    contract = approval_checkpoints_contract()

    assert contract["contract_version"] == ORCHESTRATION_CONTRACT_VERSION
    assert contract["missing_approval_outcome"] == "FAIL_CLOSED"
    assert set(contract["approval_checkpoints"]) == set(APPROVAL_CHECKPOINTS)
    assert "LINKEDIN_PUBLIC_ACTION" in contract["approval_checkpoints"]
    assert "CODEX_EXECUTION_PROPOSAL" in contract["approval_checkpoints"]
    assert contract["non_read_actions_require_human_approval"] is True


def test_audit_evidence_contract_requires_no_raw_payloads() -> None:
    contract = audit_evidence_contract()

    assert contract["raw_payloads_allowed"] is False
    assert contract["sensitive_data_allowed"] is False
    assert contract["hash_only_actor_and_action"] is True
    assert contract["missing_audit_outcome"] == "FAIL_CLOSED"


def test_build_audit_evidence_hashes_actor_and_action() -> None:
    event = example_orchestration_event()

    evidence = build_audit_evidence(event, timestamp="2026-06-12T00:00:00Z")

    assert evidence["actor_hash"] == sha256_payload(event["actor"])
    assert evidence["requested_action_hash"] == sha256_payload(event["requested_action"])
    assert "actor" not in evidence
    assert "requested_action" not in evidence
    assert len(evidence["audit_hash"]) == 64


def test_build_audit_evidence_refuses_invalid_event() -> None:
    event = example_orchestration_event()
    event["policy_decision"] = "DENY"

    evidence = build_audit_evidence(event, timestamp="2026-06-12T00:00:00Z")

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["audit_evidence_created"] is False
    assert "POLICY_NOT_ALLOW" in evidence["gaps"]
