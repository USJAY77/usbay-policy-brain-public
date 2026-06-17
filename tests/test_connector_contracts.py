from __future__ import annotations

import json

import pytest

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
from governance.connector_contracts import (
    CONNECTOR_POLICY_VERSION,
    CONNECTOR_READ_REQUEST_SCHEMA,
    CONNECTOR_READ_RESULT_SCHEMA,
    build_connector_audit_record,
    validate_read_request,
    validate_read_result,
)


pytestmark = pytest.mark.governance


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


def request(**overrides):
    payload = {
        "schema": CONNECTOR_READ_REQUEST_SCHEMA,
        "connector_id": "github-1",
        "connector_type": "GITHUB",
        "source_system": "github",
        "requested_by": "operator-1",
        "requested_at": "2026-06-17T06:00:00Z",
        "read_scope": "READ_REPOSITORY_STATE",
        "policy_version": CONNECTOR_POLICY_VERSION,
        "audit_hash": "a" * 64,
        "lineage_hash": "l" * 64,
        "fail_closed": False,
        "reason_codes": [],
        "parameters": {},
    }
    payload.update(overrides)
    return payload


def result(**overrides):
    payload = request(schema=CONNECTOR_READ_RESULT_SCHEMA) | {
        "evidence_manifest_id": "manifest-1",
        "result_hash": "r" * 64,
        "redacted_summary": "repository state metadata",
        "raw_payload": "",
    }
    payload.update(overrides)
    return payload


def test_valid_read_only_request_and_result():
    assert validate_read_request(request()).valid is True
    assert validate_read_result(result()).valid is True


def test_unknown_connector_blocks():
    validation = validate_read_request(request(connector_type="UNKNOWN"))

    assert validation.valid is False
    assert "CONNECTOR_TYPE_UNKNOWN:UNKNOWN" in validation.reason_codes


@pytest.mark.parametrize("field", ["audit_hash", "lineage_hash", "policy_version"])
def test_missing_required_trust_fields_block(field):
    validation = validate_read_request(request(**{field: ""}))

    assert validation.valid is False


@pytest.mark.parametrize("action", ["CREATE", "SEND_MESSAGE", "SEND_EMAIL", "MERGE_PR", "PUSH_CODE", "DEPLOY", "TRIGGER_WORKFLOW", "LOGIN", "PAYMENT", "SHELL_EXECUTION"])
def test_write_actions_block(action):
    validation = validate_read_request(request(read_scope=action))

    assert validation.valid is False
    assert f"CONNECTOR_WRITE_ACTION_BLOCKED:{action}" in validation.reason_codes


def test_secret_access_and_credential_logging_block():
    validation = validate_read_request(request(read_scope="READ_SECRET", parameters={"api_token": "redacted"}))

    assert validation.valid is False
    assert "CONNECTOR_WRITE_ACTION_BLOCKED:READ_SECRET" in validation.reason_codes
    assert "CONNECTOR_SECRET_OR_CREDENTIAL_REQUEST_BLOCKED" in validation.reason_codes


def test_raw_payload_and_sensitive_result_block():
    validation = validate_read_result(result(raw_payload={"token": "not allowed"}, redacted_summary="contains credential"))

    assert validation.valid is False
    assert "CONNECTOR_RESULT_RAW_PAYLOAD_BLOCKED" in validation.reason_codes
    assert "CONNECTOR_RESULT_SENSITIVE_DATA_BLOCKED" in validation.reason_codes


def test_audit_record_is_hash_only_and_write_disabled():
    audit = build_connector_audit_record(request=request(), decision="CONNECTOR_READ_ALLOWED", reason_codes=[], generated_at="2026-06-17T06:00:00Z")

    assert audit["audit_hash"]
    assert audit["requested_by_hash"]
    assert "operator-1" not in str(audit)
    assert audit["raw_payload_logged"] is False
    assert audit["secrets_logged"] is False
    assert audit["tokens_logged"] is False
    assert audit["write_enabled"] is False
    assert audit["auto_authorized"] is False
