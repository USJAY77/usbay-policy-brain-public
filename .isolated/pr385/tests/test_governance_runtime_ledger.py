from __future__ import annotations

import pytest

from governance.runtime_ledger import (
    GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH,
    GovernanceRuntimeLedgerError,
    RuntimeLedgerDecisionContext,
    append_runtime_ledger_entry,
    build_runtime_ledger_entry,
    runtime_ledger_schema,
    serialize_runtime_ledger_entry,
    verify_runtime_ledger,
)


TIMESTAMP = "2026-05-12T00:20:00Z"
AUDIT_HASH = "sha256:" + ("a" * 64)
CORRELATION_ID = "sha256:" + ("c" * 64)


def _context(
    *,
    tenant: str = "tenant-ledger",
    policy_version: str = "policy.v1",
    decision: str = "BLOCKED",
    failure_code: str = "APPROVAL_REQUIRED",
    audit_hash: str = AUDIT_HASH,
    correlation_id: str = CORRELATION_ID,
) -> RuntimeLedgerDecisionContext:
    return RuntimeLedgerDecisionContext(
        timestamp=TIMESTAMP,
        tenant=tenant,
        policy_version=policy_version,
        validator="approvals",
        decision=decision,
        failure_code=failure_code,
        evidence_id="evidence://local-only/sha256/" + ("e" * 64),
        audit_hash=audit_hash,
        correlation_id=correlation_id,
    )


def test_runtime_ledger_schema_is_reference_only_and_fail_closed() -> None:
    schema = runtime_ledger_schema()

    assert schema["payload_policy"] == "hash-only"
    assert schema["storage_model"] == "append-only-reference-ledger"
    assert schema["execution_allowed"] is False
    assert schema["provider_execution"] is False
    assert schema["production_activation"] is False


def test_identical_decision_produces_identical_canonical_record() -> None:
    first = build_runtime_ledger_entry(_context())
    second = build_runtime_ledger_entry(_context())

    assert first == second
    assert serialize_runtime_ledger_entry(first) == serialize_runtime_ledger_entry(second)
    assert first["ledger_id"] == second["ledger_id"]
    assert first["entry_hash"] == second["entry_hash"]


@pytest.mark.parametrize(
    ("changed", "expected_different"),
    (
        ({"tenant": "tenant-b"}, "tenant"),
        ({"policy_version": "policy.v2"}, "policy_version"),
        ({"decision": "FAIL_CLOSED", "failure_code": "POLICY_MISMATCH"}, "decision"),
    ),
)
def test_tenant_policy_and_decision_changes_modify_hash(changed: dict, expected_different: str) -> None:
    base = build_runtime_ledger_entry(_context())
    changed_entry = build_runtime_ledger_entry(_context(**changed))

    assert changed_entry[expected_different] != base[expected_different]
    assert changed_entry["ledger_id"] != base["ledger_id"]
    assert changed_entry["entry_hash"] != base["entry_hash"]


def test_append_runtime_ledger_entry_hash_links_records() -> None:
    records = append_runtime_ledger_entry((), _context())
    records = append_runtime_ledger_entry(
        records,
        _context(tenant="tenant-b", audit_hash="sha256:" + ("b" * 64), correlation_id="sha256:" + ("d" * 64)),
    )

    assert len(records) == 2
    assert records[0]["previous_hash"] == GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH
    assert records[1]["previous_hash"] == records[0]["entry_hash"]
    assert verify_runtime_ledger(records) == ()
    assert all(record["execution_allowed"] is False for record in records)
    assert all(record["provider_execution"] is False for record in records)
    assert all(record["production_activation"] is False for record in records)


def test_duplicate_ledger_entry_detection() -> None:
    entry = build_runtime_ledger_entry(_context())

    assert "RUNTIME_LEDGER_DUPLICATE_ENTRY" in verify_runtime_ledger((entry, entry))


def test_reordered_ledger_detection() -> None:
    first = build_runtime_ledger_entry(_context())
    second = build_runtime_ledger_entry(
        _context(tenant="tenant-b", audit_hash="sha256:" + ("b" * 64), correlation_id="sha256:" + ("d" * 64)),
        previous_hash=first["entry_hash"],
        position=1,
    )

    errors = verify_runtime_ledger((second, first))

    assert "RUNTIME_LEDGER_POSITION_INVALID" in errors
    assert "RUNTIME_LEDGER_PREVIOUS_HASH_MISMATCH" in errors


def test_tampering_detection() -> None:
    entry = build_runtime_ledger_entry(_context())
    tampered = dict(entry)
    tampered["decision"] = "ALLOWED"

    errors = verify_runtime_ledger((tampered,))

    assert "RUNTIME_LEDGER_ID_MISMATCH" in errors
    assert "RUNTIME_LEDGER_ENTRY_HASH_MISMATCH" in errors


def test_missing_or_malformed_context_fails_closed() -> None:
    with pytest.raises(GovernanceRuntimeLedgerError, match="RUNTIME_LEDGER_CONTEXT_MISSING"):
        build_runtime_ledger_entry({**_context().__dict__, "tenant": ""})

    with pytest.raises(GovernanceRuntimeLedgerError, match="RUNTIME_LEDGER_DECISION_INVALID"):
        build_runtime_ledger_entry({**_context().__dict__, "decision": "ALLOW"})

    with pytest.raises(GovernanceRuntimeLedgerError, match="RUNTIME_LEDGER_HASH_INVALID"):
        build_runtime_ledger_entry({**_context().__dict__, "audit_hash": "a" * 64})


def test_raw_payload_markers_are_rejected_and_not_serialized() -> None:
    entry = build_runtime_ledger_entry(_context())
    contaminated = dict(entry)
    contaminated["raw_payload"] = "customer-secret"

    assert "raw_payload" not in serialize_runtime_ledger_entry(entry)
    assert "customer-secret" not in serialize_runtime_ledger_entry(entry)
    assert "RUNTIME_LEDGER_RAW_DATA_FORBIDDEN" in verify_runtime_ledger((contaminated,))


def test_append_blocks_when_existing_chain_is_invalid() -> None:
    entry = build_runtime_ledger_entry(_context())
    tampered = dict(entry)
    tampered["tenant"] = "tenant-tampered"

    with pytest.raises(GovernanceRuntimeLedgerError, match="RUNTIME_LEDGER_ENTRY_HASH_MISMATCH"):
        append_runtime_ledger_entry((tampered,), _context(tenant="tenant-b"))
