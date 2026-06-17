from __future__ import annotations

import pytest

from governance.connector_contracts import CONNECTOR_POLICY_VERSION, CONNECTOR_READ_REQUEST_SCHEMA, CONNECTOR_READ_RESULT_SCHEMA
from governance.connector_governance import DECISION_ALLOWED_READ_ONLY, DECISION_BLOCKED, evaluate_connector_read_request, evaluate_connector_read_result
from governance.connector_registry import build_connector_registry


pytestmark = pytest.mark.governance


def registry():
    return build_connector_registry(overrides={"GITHUB": {"enabled": True, "health_status": "HEALTHY", "reason_codes": []}})


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


def test_valid_read_only_request_allowed_when_registry_healthy():
    decision = evaluate_connector_read_request(request=request(), registry=registry())

    assert decision.decision == DECISION_ALLOWED_READ_ONLY
    assert decision.reason_codes == ()
    assert decision.audit_record["write_enabled"] is False


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (request(connector_id=""), "CONNECTOR_CONNECTOR_ID_MISSING"),
        (request(source_system=""), "CONNECTOR_SOURCE_SYSTEM_MISSING"),
        (request(read_scope=""), "CONNECTOR_READ_SCOPE_MISSING"),
        (request(audit_hash=""), "CONNECTOR_AUDIT_HASH_MISSING"),
        (request(lineage_hash=""), "CONNECTOR_LINEAGE_HASH_MISSING"),
        (request(policy_version=""), "CONNECTOR_POLICY_VERSION_MISSING"),
        (request(connector_type="UNKNOWN"), "CONNECTOR_TYPE_UNKNOWN:UNKNOWN"),
        (request(read_scope="CREATE_TICKET"), "CONNECTOR_WRITE_ACTION_BLOCKED:CREATE_TICKET"),
        (request(read_scope="READ_SECRET"), "CONNECTOR_WRITE_ACTION_BLOCKED:READ_SECRET"),
        (request(parameters={"credential": "redacted"}), "CONNECTOR_SECRET_OR_CREDENTIAL_REQUEST_BLOCKED"),
    ],
)
def test_fail_closed_request_paths(payload, reason):
    decision = evaluate_connector_read_request(request=payload, registry=registry())

    assert decision.decision == DECISION_BLOCKED
    assert reason in decision.reason_codes


def test_disabled_connector_blocks():
    decision = evaluate_connector_read_request(request=request(), registry=build_connector_registry())

    assert decision.decision == DECISION_BLOCKED
    assert "CONNECTOR_DISABLED:GITHUB" in decision.reason_codes


def test_unhealthy_connector_blocks():
    decision = evaluate_connector_read_request(
        request=request(),
        registry=build_connector_registry(overrides={"GITHUB": {"enabled": True, "health_status": "DEGRADED"}}),
    )

    assert decision.decision == DECISION_BLOCKED
    assert "CONNECTOR_UNHEALTHY:GITHUB" in decision.reason_codes


def test_valid_read_result_has_audit_and_evidence_linkage():
    valid, reasons = evaluate_connector_read_result(result())

    assert valid is True
    assert reasons == ()


def test_read_result_missing_evidence_and_raw_token_blocks():
    valid, reasons = evaluate_connector_read_result(result(evidence_manifest_id="", raw_payload={"token": "x"}))

    assert valid is False
    assert "CONNECTOR_RESULT_EVIDENCE_MANIFEST_ID_MISSING" in reasons
    assert "CONNECTOR_RESULT_RAW_PAYLOAD_BLOCKED" in reasons
