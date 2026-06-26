from __future__ import annotations

import json

from connectors.connector_contracts import (
    APPROVAL_GATE_BY_CONNECTOR,
    CONNECTOR_NAMES,
    CONNECTOR_SYSTEMS,
    PB312_CONNECTOR_CONTRACT_VERSION,
    ApprovalGate,
    AuthStatus,
    ConnectorState,
    ConnectorType,
    GovernedConnectorState,
    SensitiveDataPolicy,
    approval_gate_for,
    build_connector_event,
    connector_contracts_json,
    connector_evidence_schemas,
    connector_type_for,
    default_connector_contracts,
    example_connector_event,
    sha256_payload,
    transition_connector_state,
    validate_connector_event,
)


def test_legacy_connector_contracts_default_to_disabled() -> None:
    contracts = default_connector_contracts()

    assert set(contracts) == set(CONNECTOR_NAMES)
    assert all(contract.state == GovernedConnectorState.DISABLED for contract in contracts.values())
    assert all(contract.live_activation_allowed is False for contract in contracts.values())
    assert all(contract.external_calls_allowed is False for contract in contracts.values())


def test_legacy_connector_contract_export_disallows_external_calls() -> None:
    exported = connector_contracts_json()

    assert exported["production_activation_allowed"] is False
    assert exported["external_calls_allowed"] is False
    assert exported["connectors"]["LinkedIn"]["state"] == "DISABLED"


def test_legacy_transition_never_enables_live_activation() -> None:
    contract = default_connector_contracts()["GitHub"]

    transitioned = transition_connector_state(contract, GovernedConnectorState.DRY_RUN)

    assert transitioned.state == GovernedConnectorState.DRY_RUN
    assert transitioned.live_activation_allowed is False
    assert transitioned.external_calls_allowed is False


def test_pb312_defines_canonical_connector_enums() -> None:
    assert {item.value for item in ConnectorType} == {"READ_ONLY", "PROPOSAL", "WRITE", "EXECUTION"}
    assert {item.value for item in ConnectorState} == {
        "AVAILABLE",
        "UNAVAILABLE",
        "AUTH_INVALID",
        "AUTH_UNKNOWN",
        "FAIL_CLOSED",
    }
    assert {item.value for item in AuthStatus} == {"VALID", "INVALID", "UNKNOWN"}
    assert SensitiveDataPolicy.RAW_DATA_FORBIDDEN.value == "RAW_DATA_FORBIDDEN"


def test_pb312_approval_gate_mapping_matches_architecture() -> None:
    assert APPROVAL_GATE_BY_CONNECTOR["LinkedIn"] == ApprovalGate.LINKEDIN_PUBLIC_ACTION
    assert APPROVAL_GATE_BY_CONNECTOR["Notion"] == ApprovalGate.NOTION_CASE_WRITE
    assert APPROVAL_GATE_BY_CONNECTOR["Euria"] == ApprovalGate.EURIA_PROJECT_WRITE
    assert APPROVAL_GATE_BY_CONNECTOR["GitHub"] == ApprovalGate.GITHUB_WORK_ITEM_WRITE
    assert APPROVAL_GATE_BY_CONNECTOR["Codex"] == ApprovalGate.CODEX_EXECUTION_PROPOSAL
    assert APPROVAL_GATE_BY_CONNECTOR["Evidence Layer"] == ApprovalGate.EXECUTIVE_REPORT_EXTERNAL_SHARE
    assert "USBAY Control Plane" in CONNECTOR_SYSTEMS


def test_connector_type_and_gate_are_deterministic() -> None:
    assert connector_type_for("LinkedIn", "read_public_signal") == ConnectorType.READ_ONLY
    assert approval_gate_for("LinkedIn", "read_public_signal") is None
    assert connector_type_for("Notion", "write_case_record") == ConnectorType.WRITE
    assert approval_gate_for("Notion", "write_case_record") == ApprovalGate.NOTION_CASE_WRITE
    assert connector_type_for("Codex", "execute_governed_proposal") == ConnectorType.EXECUTION
    assert approval_gate_for("Codex", "execute_governed_proposal") == ApprovalGate.CODEX_EXECUTION_PROPOSAL


def test_connector_evidence_schemas_define_required_artifacts() -> None:
    schemas = connector_evidence_schemas()

    assert schemas["contract_version"] == PB312_CONNECTOR_CONTRACT_VERSION
    assert schemas["raw_payloads_allowed"] is False
    assert schemas["sensitive_data_allowed"] is False
    assert schemas["external_calls_allowed"] is False
    assert set(schemas["artifacts"]) == {
        "connector_event.json",
        "approval_record.json",
        "execution_proposal.json",
    }
    connector_schema = schemas["artifacts"]["connector_event.json"]
    assert connector_schema["additionalProperties"] is False
    assert "requested_action_hash" in connector_schema["required"]


def test_example_connector_event_verifies_without_execution() -> None:
    event = example_connector_event()

    result = validate_connector_event(event)

    assert event["contract_version"] == PB312_CONNECTOR_CONTRACT_VERSION
    assert event["connector"] == "GitHub"
    assert event["connector_type"] == "WRITE"
    assert event["approval_gate"] == ApprovalGate.GITHUB_WORK_ITEM_WRITE.value
    assert result["decision"] == "VERIFIED"
    assert result["execution_status"] == "DRY_RUN_READY"
    assert result["external_calls_performed"] is False


def test_missing_approval_fails_closed_for_write_connector() -> None:
    event = example_connector_event()
    event["approval_id"] = None

    result = validate_connector_event(event)

    assert result["decision"] == "FAIL_CLOSED"
    assert result["execution_status"] == "BLOCKED"
    assert "APPROVAL_MISSING" in result["gaps"]


def test_unavailable_connector_fails_closed() -> None:
    event = example_connector_event()
    event["connector_state"] = ConnectorState.UNAVAILABLE.value

    result = validate_connector_event(event)

    assert result["decision"] == "FAIL_CLOSED"
    assert "CONNECTOR_UNAVAILABLE" in result["gaps"]


def test_invalid_auth_fails_closed() -> None:
    event = example_connector_event()
    event["auth_status"] = AuthStatus.INVALID.value

    result = validate_connector_event(event)

    assert result["decision"] == "FAIL_CLOSED"
    assert "AUTH_INVALID" in result["gaps"]


def test_malformed_metadata_and_hashes_fail_closed_without_leaking_raw_values() -> None:
    event = example_connector_event()
    event["requested_action_hash"] = "not-a-hash"
    event["metadata"] = "raw-token-value"

    result = validate_connector_event(event)

    serialized = json.dumps(result)
    assert result["decision"] == "FAIL_CLOSED"
    assert "REQUESTED_ACTION_HASH_MALFORMED" in result["gaps"]
    assert "METADATA_MALFORMED" in result["gaps"]
    assert "raw-token-value" not in serialized


def test_sensitive_metadata_fails_closed_without_leaking_raw_values() -> None:
    event = example_connector_event()
    event["metadata"] = {"token": "raw-token-value"}

    result = validate_connector_event(event)

    assert result["decision"] == "FAIL_CLOSED"
    assert "SENSITIVE_DATA_DETECTED" in result["gaps"]
    assert "raw-token-value" not in json.dumps(result)


def test_missing_audit_evidence_fails_closed() -> None:
    event = example_connector_event()
    event["audit_evidence_present"] = False

    result = validate_connector_event(event)

    assert result["decision"] == "FAIL_CLOSED"
    assert "AUDIT_EVIDENCE_MISSING" in result["gaps"]


def test_policy_deny_fails_closed() -> None:
    event = example_connector_event()
    event["policy_decision"] = "DENY"

    result = validate_connector_event(event)

    assert result["decision"] == "FAIL_CLOSED"
    assert "POLICY_DENY" in result["gaps"]


def test_build_read_only_connector_event_does_not_require_approval() -> None:
    event = build_connector_event(
        connector="LinkedIn",
        event_type="linkedin_public_signal_observed",
        requested_action="read_public_signal",
        policy_hash=sha256_payload({"policy": "pb312"}),
        policy_decision="ALLOW",
        audit_hash=sha256_payload({"audit": "read-only"}),
        connector_state=ConnectorState.AVAILABLE,
        auth_status=AuthStatus.VALID,
    )

    result = validate_connector_event(event)

    assert event["connector_type"] == "READ_ONLY"
    assert event["approval_gate"] is None
    assert result["decision"] == "VERIFIED"
