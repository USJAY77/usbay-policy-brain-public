from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3
from typing import Any

from audit import ledger
from governance.hashing import sha256_reference
from security.execution_lifecycle_store import (
    ALREADY_TERMINAL,
    COMPLETED,
    EXECUTION_STARTED,
    FAILED,
    LIFECYCLE_BINDING_INVALID,
    LIFECYCLE_BINDING_MISMATCH,
    LIFECYCLE_PARTIAL_UNKNOWN,
    LIFECYCLE_STATE_CORRUPTED,
    LIFECYCLE_STORAGE_TIMEOUT,
    PARTIAL_UNKNOWN,
    START_ACQUIRED,
    TERMINAL_RECORDED,
    SQLiteExecutionLifecycleStore,
)


def _hash(label: str) -> str:
    return sha256_reference({"label": label})


def _binding(**overrides: str) -> dict[str, str]:
    payload = {
        "execution_authorization_hash": _hash("exec-auth"),
        "authorization_id": "exec-auth-001",
        "consumed_decision_evidence_hash": _hash("consumed-decision"),
        "decision_evidence_hash": _hash("decision"),
        "decision_consumption_evidence_hash": _hash("decision-consumption"),
        "decision_replay_evidence_hash": _hash("decision-replay"),
        "policy_id": "ai-act-live-policy-v1",
        "policy_version": "2026.08.11",
        "policy_hash": _hash("policy"),
        "request_hash": _hash("request"),
        "command_hash": _hash("command"),
        "execution_contract_hash": _hash("contract"),
    }
    payload.update(overrides)
    return payload


def _store_completed_lifecycle(path, binding: dict[str, str] | None = None) -> dict[str, str]:
    binding = binding or _binding()
    store = SQLiteExecutionLifecycleStore(path)
    assert store.acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    assert store.record_terminal_outcome(
        binding,
        outcome_state=COMPLETED,
        outcome_hash=_hash("outcome"),
        current_evidence_hash=_hash("evidence"),
        attestation_payload_hash=_hash("attestation-payload"),
        attestation_signature_hash=_hash("attestation-signature"),
        signature_verification_result="VERIFIED",
        completed_at="2026-08-13T12:00:01Z",
    ).result == TERMINAL_RECORDED
    return binding


def _mutate_evidence_json(path, binding: dict[str, str], mutate) -> None:
    conn = sqlite3.connect(path)
    try:
        evidence_json = conn.execute(
            "SELECT evidence_json FROM execution_lifecycle WHERE execution_authorization_hash = ?",
            (binding["execution_authorization_hash"],),
        ).fetchone()[0]
        evidence = json.loads(evidence_json)
        mutate(evidence)
        with conn:
            conn.execute(
                "UPDATE execution_lifecycle SET evidence_json = ? WHERE execution_authorization_hash = ?",
                (ledger.canonical_json_bytes(evidence).decode("utf-8"), binding["execution_authorization_hash"]),
            )
    finally:
        conn.close()


def test_sqlite_lifecycle_success_completion_survives_restart(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _binding()
    store = SQLiteExecutionLifecycleStore(path)

    assert store.acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    terminal = store.record_terminal_outcome(
        binding,
        outcome_state=COMPLETED,
        outcome_hash=_hash("outcome"),
        current_evidence_hash=_hash("evidence"),
        attestation_payload_hash=_hash("attestation-payload"),
        attestation_signature_hash=_hash("attestation-signature"),
        signature_verification_result="VERIFIED",
        completed_at="2026-08-13T12:00:01Z",
    )

    assert terminal.result == TERMINAL_RECORDED
    assert terminal.evidence["attestation_payload_hash"] == _hash("attestation-payload")
    assert terminal.evidence["attestation_signature_hash"] == _hash("attestation-signature")
    assert terminal.evidence["signature_verification_result"] == "VERIFIED"
    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)
    assert recovered.result == ALREADY_TERMINAL
    assert recovered.state == COMPLETED
    assert recovered.evidence["attestation_signature_hash"] == _hash("attestation-signature")


def test_sqlite_lifecycle_failed_and_partial_unknown_never_become_completed(tmp_path) -> None:
    failed = _binding(execution_authorization_hash=_hash("failed-auth"))
    partial = _binding(execution_authorization_hash=_hash("partial-auth"))
    store = SQLiteExecutionLifecycleStore(tmp_path / "lifecycle.db")

    assert store.acquire_execution_start(failed, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    assert store.record_terminal_outcome(
        failed,
        outcome_state=FAILED,
        outcome_hash=_hash("failed-outcome"),
        current_evidence_hash=_hash("failed-evidence"),
        attestation_payload_hash=_hash("failed-attestation-payload"),
        attestation_signature_hash=_hash("failed-attestation-signature"),
        signature_verification_result="VERIFIED",
        completed_at="2026-08-13T12:00:01Z",
    ).state == FAILED
    assert store.record_terminal_outcome(
        failed,
        outcome_state=COMPLETED,
        outcome_hash=_hash("completed-outcome"),
        current_evidence_hash=_hash("completed-evidence"),
        attestation_payload_hash=_hash("completed-attestation-payload"),
        attestation_signature_hash=_hash("completed-attestation-signature"),
        signature_verification_result="VERIFIED",
        completed_at="2026-08-13T12:00:02Z",
    ).state == FAILED

    assert store.acquire_execution_start(partial, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    assert store.record_terminal_outcome(
        partial,
        outcome_state=PARTIAL_UNKNOWN,
        outcome_hash=_hash("partial-outcome"),
        current_evidence_hash=_hash("partial-evidence"),
        completed_at="2026-08-13T12:00:01Z",
    ).state == PARTIAL_UNKNOWN
    assert store.record_terminal_outcome(
        partial,
        outcome_state=COMPLETED,
        outcome_hash=_hash("completed-outcome"),
        current_evidence_hash=_hash("completed-evidence"),
        attestation_payload_hash=_hash("completed-attestation-payload"),
        attestation_signature_hash=_hash("completed-attestation-signature"),
        signature_verification_result="VERIFIED",
        completed_at="2026-08-13T12:00:02Z",
    ).state == PARTIAL_UNKNOWN


def test_restart_after_execution_started_without_outcome_is_partial_unknown(tmp_path) -> None:
    binding = _binding()
    store = SQLiteExecutionLifecycleStore(tmp_path / "lifecycle.db")

    assert store.acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").state == EXECUTION_STARTED

    recovered = SQLiteExecutionLifecycleStore(tmp_path / "lifecycle.db").recover(binding)
    assert recovered.result == LIFECYCLE_PARTIAL_UNKNOWN
    assert recovered.state == PARTIAL_UNKNOWN


def test_missing_lifecycle_record_is_partial_unknown(tmp_path) -> None:
    result = SQLiteExecutionLifecycleStore(tmp_path / "lifecycle.db").recover(_binding())

    assert result.result == LIFECYCLE_PARTIAL_UNKNOWN
    assert result.state == PARTIAL_UNKNOWN


def test_duplicate_and_concurrent_workers_cannot_both_start(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _binding()

    def start() -> str:
        return SQLiteExecutionLifecycleStore(path).acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").result

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(lambda _: start(), range(32)))

    assert results.count(START_ACQUIRED) == 1
    assert results.count(LIFECYCLE_PARTIAL_UNKNOWN) == 31
    assert LIFECYCLE_STORAGE_TIMEOUT not in results


def test_repeated_high_contention_duplicate_starts_are_deterministic(tmp_path) -> None:
    for attempt in range(20):
        path = tmp_path / f"lifecycle-{attempt}.db"
        binding = _binding(execution_authorization_hash=_hash(f"exec-auth-{attempt}"))

        def start() -> str:
            return SQLiteExecutionLifecycleStore(path).acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").result

        with ThreadPoolExecutor(max_workers=16) as executor:
            results = list(executor.map(lambda _: start(), range(32)))

        assert results.count(START_ACQUIRED) == 1
        assert results.count(LIFECYCLE_PARTIAL_UNKNOWN) == 31
        assert LIFECYCLE_STORAGE_TIMEOUT not in results


def test_lifecycle_binding_mismatch_and_tamper_block(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _binding()
    store = SQLiteExecutionLifecycleStore(path)

    assert store.acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    mismatch = dict(binding)
    mismatch["policy_hash"] = _hash("other-policy")
    assert store.recover(mismatch).result == LIFECYCLE_BINDING_MISMATCH

    conn = sqlite3.connect(path)
    try:
        with conn:
            conn.execute(
                "UPDATE execution_lifecycle SET state = ?, evidence_json = ? WHERE execution_authorization_hash = ?",
                (COMPLETED, "{not-json", binding["execution_authorization_hash"]),
            )
    finally:
        conn.close()
    assert store.recover(binding).result == LIFECYCLE_STATE_CORRUPTED


def test_lifecycle_rejects_missing_malformed_and_mismatched_binding(tmp_path) -> None:
    store = SQLiteExecutionLifecycleStore(tmp_path / "lifecycle.db")

    assert store.acquire_execution_start({}, started_at="2026-08-13T12:00:00Z").result == LIFECYCLE_BINDING_INVALID
    assert store.acquire_execution_start(_binding(command_hash="not-a-hash"), started_at="2026-08-13T12:00:00Z").result == LIFECYCLE_BINDING_INVALID
    assert store.acquire_execution_start(_binding(execution_contract_hash=_hash("other-contract")), started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED


def test_terminal_completed_requires_verified_signature_binding(tmp_path) -> None:
    store = SQLiteExecutionLifecycleStore(tmp_path / "lifecycle.db")
    binding = _binding()

    assert store.acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    result = store.record_terminal_outcome(
        binding,
        outcome_state=COMPLETED,
        outcome_hash=_hash("outcome"),
        current_evidence_hash=_hash("evidence"),
        completed_at="2026-08-13T12:00:01Z",
    )

    assert result.result == LIFECYCLE_BINDING_INVALID
    assert result.state == "BLOCKED"
    recovered = SQLiteExecutionLifecycleStore(tmp_path / "lifecycle.db").recover(binding)
    assert recovered.result == LIFECYCLE_PARTIAL_UNKNOWN
    assert recovered.state == PARTIAL_UNKNOWN


def test_signature_hash_tampering_is_detected_during_recovery(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_completed_lifecycle(path)

    conn = sqlite3.connect(path)
    try:
        with conn:
            conn.execute(
                "UPDATE execution_lifecycle SET attestation_signature_hash = ? WHERE execution_authorization_hash = ?",
                (_hash("substituted-attestation-signature"), binding["execution_authorization_hash"]),
            )
    finally:
        conn.close()

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)
    assert recovered.result != ALREADY_TERMINAL
    assert recovered.result == LIFECYCLE_STATE_CORRUPTED


def test_terminal_evidence_json_row_mismatch_is_detected(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_completed_lifecycle(path)

    _mutate_evidence_json(
        path,
        binding,
        lambda evidence: evidence.update({"attestation_signature_hash": _hash("json-substituted-signature")}),
    )

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)
    assert recovered.result != ALREADY_TERMINAL
    assert recovered.result == LIFECYCLE_STATE_CORRUPTED


def test_execution_lifecycle_evidence_hash_tampering_is_detected(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_completed_lifecycle(path)

    _mutate_evidence_json(
        path,
        binding,
        lambda evidence: evidence.update({"execution_lifecycle_evidence_hash": _hash("tampered-evidence-hash")}),
    )

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)
    assert recovered.result != ALREADY_TERMINAL
    assert recovered.result == LIFECYCLE_STATE_CORRUPTED


def test_terminal_binding_hash_drift_is_detected(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_completed_lifecycle(path)

    _mutate_evidence_json(
        path,
        binding,
        lambda evidence: evidence.update({"execution_lifecycle_binding_hash": _hash("binding-drift")}),
    )

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)
    assert recovered.result != ALREADY_TERMINAL
    assert recovered.result == LIFECYCLE_STATE_CORRUPTED


def test_missing_required_terminal_evidence_fields_fail_closed(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_completed_lifecycle(path)

    _mutate_evidence_json(path, binding, lambda evidence: evidence.pop("attestation_signature_hash"))

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)
    assert recovered.result != ALREADY_TERMINAL
    assert recovered.result == LIFECYCLE_STATE_CORRUPTED


def test_malformed_terminal_evidence_structure_fails_closed(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_completed_lifecycle(path)

    conn = sqlite3.connect(path)
    try:
        with conn:
            conn.execute(
                "UPDATE execution_lifecycle SET evidence_json = ? WHERE execution_authorization_hash = ?",
                ("[]", binding["execution_authorization_hash"]),
            )
    finally:
        conn.close()

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)
    assert recovered.result != ALREADY_TERMINAL
    assert recovered.result == LIFECYCLE_STATE_CORRUPTED


def test_persisted_row_evidence_disagreement_fails_closed(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_completed_lifecycle(path)

    conn = sqlite3.connect(path)
    try:
        with conn:
            conn.execute(
                "UPDATE execution_lifecycle SET outcome_hash = ? WHERE execution_authorization_hash = ?",
                (_hash("row-substituted-outcome"), binding["execution_authorization_hash"]),
            )
    finally:
        conn.close()

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)
    assert recovered.result != ALREADY_TERMINAL
    assert recovered.result == LIFECYCLE_STATE_CORRUPTED


def test_signature_payload_reference_disagreement_fails_closed(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_completed_lifecycle(path)

    _mutate_evidence_json(
        path,
        binding,
        lambda evidence: evidence.update({"attestation_payload_hash": _hash("json-substituted-payload")}),
    )

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)
    assert recovered.result != ALREADY_TERMINAL
    assert recovered.result == LIFECYCLE_STATE_CORRUPTED


def test_lifecycle_storage_unavailable_blocks(monkeypatch, tmp_path) -> None:
    store = SQLiteExecutionLifecycleStore(tmp_path / "lifecycle.db")

    def raise_locked(*args: Any, **kwargs: Any):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "_connect", raise_locked)

    assert store.acquire_execution_start(_binding(), started_at="2026-08-13T12:00:00Z").result == LIFECYCLE_STORAGE_TIMEOUT


def test_lifecycle_evidence_is_hash_only() -> None:
    raw_secret = "SECRET_SHOULD_NOT_APPEAR"
    evidence = SQLiteExecutionLifecycleStore(":memory:").acquire_execution_start(
        _binding(command_hash=_hash(raw_secret)),
        started_at="2026-08-13T12:00:00Z",
    ).evidence
    rendered = str(evidence).lower()

    assert raw_secret.lower() not in rendered
    assert "password" not in rendered
    assert "token" not in rendered
