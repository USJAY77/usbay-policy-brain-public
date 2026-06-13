from __future__ import annotations

from runtime_trust.pilot_activation import DEFAULT_POLICY_HASH, runtime_ledger_binding_contract_json, validate_runtime_ledger_record


def _record() -> dict:
    return {
        "ledger_id": "ledger-1",
        "policy_hash": DEFAULT_POLICY_HASH,
        "approval_id": "approval-1",
        "actor": "operator-1",
        "timestamp": "2026-06-11T00:00:00Z",
        "audit_hash": "a" * 64,
    }


def test_runtime_ledger_binding_contract_requires_all_fields() -> None:
    contract = runtime_ledger_binding_contract_json()
    assert contract["missing_ledger_record_outcome"] == "FAIL_CLOSED"
    assert set(contract["binds"]) == {"approvals", "actions", "decisions", "audit_events"}


def test_missing_ledger_record_fails_closed() -> None:
    result = validate_runtime_ledger_record(None)
    assert result["decision"] == "FAIL_CLOSED"
    assert "MISSING_LEDGER_RECORD" in result["gaps"]


def test_complete_ledger_record_verifies() -> None:
    result = validate_runtime_ledger_record(_record())
    assert result["decision"] == "VERIFIED"
    assert result["ledger_hash"]


def test_missing_ledger_field_fails_closed() -> None:
    record = _record()
    record.pop("approval_id")
    result = validate_runtime_ledger_record(record)
    assert result["decision"] == "FAIL_CLOSED"
    assert "MISSING_APPROVAL_ID" in result["gaps"]
