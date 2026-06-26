from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pilot.approval_gate import default_pilot_approval_contract_json, validate_pilot_approval_contract


def _future() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _approved_payload() -> dict:
    payload = default_pilot_approval_contract_json()
    payload.update(
        {
            "approved_actor": "human-reviewer",
            "approval_status": "APPROVED",
            "connector_state": "PILOT_APPROVED",
            "deployment_attestation_id": "deploy-attestation-1",
            "expires_at": _future(),
        }
    )
    return payload


def test_default_pilot_approval_contract_is_blocked_and_limited_scope() -> None:
    contract = default_pilot_approval_contract_json()
    assert contract["approval_status"] == "BLOCKED"
    assert contract["pilot_scope"] == "GitHub -> USBAY Gateway -> Human Approval -> Codex"
    assert contract["live_execution_allowed"] is False


def test_pilot_approval_gate_blocks_missing_human_approval() -> None:
    contract = default_pilot_approval_contract_json()
    result = validate_pilot_approval_contract(contract)
    assert result["decision"] == "FAIL_CLOSED"
    assert result["status"] == "BLOCKED"
    assert "HUMAN_APPROVAL_REQUIRED" in result["gaps"]


def test_pilot_approval_gate_blocks_expired_approval() -> None:
    payload = _approved_payload()
    payload["expires_at"] = "2026-01-01T00:00:00Z"
    result = validate_pilot_approval_contract(payload)
    assert result["decision"] == "FAIL_CLOSED"
    assert "APPROVAL_EXPIRED" in result["gaps"]


def test_pilot_approval_gate_can_be_ready_for_review_without_live_execution() -> None:
    result = validate_pilot_approval_contract(_approved_payload())
    assert result["decision"] == "VERIFIED"
    assert result["status"] == "READY_FOR_REVIEW"
    assert result["live_execution_allowed"] is False
