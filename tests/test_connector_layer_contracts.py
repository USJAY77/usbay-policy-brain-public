from __future__ import annotations

from connectors.connector_contracts import (
    ACTION_APPROVED_DRY_RUN,
    ACTION_BLOCKED,
    PB355_CONNECTOR_CONTRACT_VERSION,
    ConnectorRequest,
    evaluate_connector_request,
    sha256_payload,
)


def _approval() -> dict[str, str]:
    return {
        "status": "APPROVED",
        "evidence_hash": sha256_payload({"approval": "pb355"}),
    }


def _audit() -> dict[str, str]:
    return {
        "evidence_hash": sha256_payload({"audit": "pb355"}),
    }


def _request(**overrides: object) -> ConnectorRequest:
    values = {
        "connector_id": "github",
        "requested_action": "prepare_pr",
        "actor": "codex",
        "capabilities": ("prepare_pr",),
        "approval_evidence": _approval(),
        "audit_evidence": _audit(),
    }
    values.update(overrides)
    return ConnectorRequest(**values)  # type: ignore[arg-type]


def test_supported_connector_request_is_approved_for_dry_run_only() -> None:
    decision = evaluate_connector_request(_request())

    assert decision.decision == ACTION_APPROVED_DRY_RUN
    assert decision.status == "READY_FOR_REVIEW"
    assert decision.external_mutation_performed is False
    assert decision.audit_evidence["contract_version"] == PB355_CONNECTOR_CONTRACT_VERSION
    assert decision.audit_evidence["external_mutation_performed"] is False
    assert decision.audit_evidence["raw_payload_logged"] is False


def test_unknown_connector_blocks() -> None:
    decision = evaluate_connector_request(_request(connector_id="unknown"))

    assert decision.decision == ACTION_BLOCKED
    assert decision.status == "FAIL_CLOSED"
    assert "unknown_connector" in decision.blockers
    assert decision.external_mutation_performed is False


def test_unsupported_action_blocks() -> None:
    decision = evaluate_connector_request(_request(requested_action="delete_repository"))

    assert decision.decision == ACTION_BLOCKED
    assert "unsupported_action" in decision.blockers


def test_missing_capability_blocks() -> None:
    decision = evaluate_connector_request(_request(capabilities=()))

    assert decision.decision == ACTION_BLOCKED
    assert "missing_capability" in decision.blockers


def test_missing_approval_blocks() -> None:
    decision = evaluate_connector_request(_request(approval_evidence=None))

    assert decision.decision == ACTION_BLOCKED
    assert "missing_approval" in decision.blockers


def test_missing_audit_evidence_blocks() -> None:
    decision = evaluate_connector_request(_request(audit_evidence=None))

    assert decision.decision == ACTION_BLOCKED
    assert "missing_audit_evidence" in decision.blockers
    assert decision.audit_evidence["evidence_hash"]


def test_connector_failure_blocks() -> None:
    decision = evaluate_connector_request(_request(connector_error="simulated_api_failure"))

    assert decision.decision == ACTION_BLOCKED
    assert "connector_failure" in decision.blockers


def test_live_external_mutation_request_blocks() -> None:
    decision = evaluate_connector_request(_request(dry_run=False))

    assert decision.decision == ACTION_BLOCKED
    assert "live_external_mutation_disabled" in decision.blockers
    assert decision.external_mutation_performed is False
