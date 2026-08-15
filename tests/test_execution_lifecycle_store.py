from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3
import subprocess
from typing import Any

from audit import ledger
from governance.hashing import sha256_reference
from security.execution_lifecycle_store import (
    ALREADY_TERMINAL,
    COMPLETED,
    EXECUTION_STARTED,
    FAILED,
    FAILURE_CLASS_ATTESTATION_GENERATION_FAILED,
    FAILURE_CLASS_SIGNATURE_VERIFICATION_FAILED,
    FAILURE_CLASS_SUBPROCESS_EXECUTION_FAILED,
    LIFECYCLE_BINDING_INVALID,
    LIFECYCLE_BINDING_MISMATCH,
    LIFECYCLE_PARTIAL_UNKNOWN,
    LIFECYCLE_STATE_CORRUPTED,
    LIFECYCLE_STORAGE_TIMEOUT,
    PARTIAL_UNKNOWN,
    RECONCILIATION_PHASE_POST_SUBPROCESS_ATTESTATION_FAILURE,
    RECONCILIATION_PHASE_PRE_SIDE_EFFECT_SUBPROCESS_FAILURE,
    RECONCILIATION_PHASE_SIGNATURE_VERIFICATION_FAILURE,
    START_ACQUIRED,
    TERMINAL_RECORDED,
    SQLiteExecutionLifecycleStore,
)


def _hash(label: str) -> str:
    return sha256_reference({"label": label})


def _runtime_keypair(tmp_path) -> tuple[Any, Any]:
    private_key = tmp_path / "terminal_signature_fixture.key"
    public_key = tmp_path / "terminal_signature_public.pem"
    generated = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private_key)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert generated.returncode == 0
    derived = subprocess.run(
        ["openssl", "rsa", "-pubout", "-in", str(private_key), "-out", str(public_key)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert derived.returncode == 0
    return private_key, public_key


def _terminal_signature_proof(tmp_path, *, outcome_hash: str, current_evidence_hash: str) -> dict[str, Any]:
    private_key, public_key = _runtime_keypair(tmp_path)
    attestation_path = tmp_path / "terminal_attestation.json"
    signature_path = tmp_path / "terminal_attestation.sig"
    attestation_path.write_bytes(
        ledger.canonical_json_bytes(
            {
                "outcome_hash": outcome_hash,
                "current_evidence_hash": current_evidence_hash,
            }
        )
    )
    signed = subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            str(private_key),
            "-out",
            str(signature_path),
            str(attestation_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert signed.returncode == 0
    return {
        "attestation_payload_hash": "sha256:" + ledger.sha256_file(attestation_path),
        "attestation_signature_hash": "sha256:" + ledger.sha256_file(signature_path),
        "signature_verification_result": "VERIFIED",
        "attestation_path": attestation_path,
        "attestation_signature_path": signature_path,
        "signature_public_key": public_key,
        "signature_verification_cwd": tmp_path,
    }


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
    outcome_hash = _hash("outcome")
    current_evidence_hash = _hash("evidence")
    assert store.acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    assert store.record_terminal_outcome(
        binding,
        outcome_state=COMPLETED,
        outcome_hash=outcome_hash,
        current_evidence_hash=current_evidence_hash,
        **_terminal_signature_proof(path.parent, outcome_hash=outcome_hash, current_evidence_hash=current_evidence_hash),
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


def _update_lifecycle_row(path, binding: dict[str, str], **updates: Any) -> None:
    assignments = ", ".join(f"{column} = ?" for column in updates)
    conn = sqlite3.connect(path)
    try:
        with conn:
            conn.execute(
                f"UPDATE execution_lifecycle SET {assignments} WHERE execution_authorization_hash = ?",
                (*updates.values(), binding["execution_authorization_hash"]),
            )
    finally:
        conn.close()


def test_sqlite_lifecycle_success_completion_survives_restart(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _binding()
    store = SQLiteExecutionLifecycleStore(path)

    assert store.acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    outcome_hash = _hash("outcome")
    current_evidence_hash = _hash("evidence")
    terminal = store.record_terminal_outcome(
        binding,
        outcome_state=COMPLETED,
        outcome_hash=outcome_hash,
        current_evidence_hash=current_evidence_hash,
        **_terminal_signature_proof(tmp_path, outcome_hash=outcome_hash, current_evidence_hash=current_evidence_hash),
        completed_at="2026-08-13T12:00:01Z",
    )

    assert terminal.result == TERMINAL_RECORDED
    assert terminal.evidence["attestation_payload_hash"].startswith("sha256:")
    assert terminal.evidence["attestation_signature_hash"].startswith("sha256:")
    assert terminal.evidence["signature_verification_result"] == "VERIFIED"
    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)
    assert recovered.result == ALREADY_TERMINAL
    assert recovered.state == COMPLETED
    assert recovered.evidence["attestation_signature_hash"] == terminal.evidence["attestation_signature_hash"]


def test_terminal_recovery_valid_durable_completed_proof_survives_restart(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_completed_lifecycle(path)

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)
    assert recovered.result == ALREADY_TERMINAL
    assert recovered.state == COMPLETED


def test_terminal_recovery_valid_durable_failed_proof_survives_restart(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _binding()
    store = SQLiteExecutionLifecycleStore(path)
    outcome_hash = _hash("failed-outcome")
    current_evidence_hash = _hash("failed-evidence")

    assert store.acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    assert store.record_terminal_outcome(
        binding,
        outcome_state=FAILED,
        outcome_hash=outcome_hash,
        current_evidence_hash=current_evidence_hash,
        **_terminal_signature_proof(tmp_path, outcome_hash=outcome_hash, current_evidence_hash=current_evidence_hash),
        completed_at="2026-08-13T12:00:01Z",
    ).result == TERMINAL_RECORDED

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)
    assert recovered.result == ALREADY_TERMINAL
    assert recovered.state == FAILED


def test_terminal_recovery_blocks_when_signed_artifacts_disappear_after_recording(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _binding()
    store = SQLiteExecutionLifecycleStore(path)
    outcome_hash = _hash("outcome")
    current_evidence_hash = _hash("evidence")
    proof = _terminal_signature_proof(tmp_path, outcome_hash=outcome_hash, current_evidence_hash=current_evidence_hash)

    assert store.acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    assert store.record_terminal_outcome(
        binding,
        outcome_state=COMPLETED,
        outcome_hash=outcome_hash,
        current_evidence_hash=current_evidence_hash,
        **proof,
        completed_at="2026-08-13T12:00:01Z",
    ).result == TERMINAL_RECORDED

    proof["attestation_path"].unlink()
    proof["attestation_signature_path"].unlink()

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)
    assert recovered.result != ALREADY_TERMINAL
    assert recovered.state != COMPLETED


def test_terminal_recovery_blocks_when_persisted_proof_reference_is_missing(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_completed_lifecycle(path)

    _update_lifecycle_row(
        path,
        binding,
        attestation_path=None,
        attestation_signature_path=None,
        signature_public_key_path=None,
        signature_verification_cwd=None,
    )

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)
    assert recovered.result != ALREADY_TERMINAL
    assert recovered.result == LIFECYCLE_STATE_CORRUPTED


def test_terminal_recovery_blocks_when_signature_artifact_hash_mismatches(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _binding()
    store = SQLiteExecutionLifecycleStore(path)
    outcome_hash = _hash("outcome")
    current_evidence_hash = _hash("evidence")
    proof = _terminal_signature_proof(tmp_path, outcome_hash=outcome_hash, current_evidence_hash=current_evidence_hash)

    assert store.acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    assert store.record_terminal_outcome(
        binding,
        outcome_state=COMPLETED,
        outcome_hash=outcome_hash,
        current_evidence_hash=current_evidence_hash,
        **proof,
        completed_at="2026-08-13T12:00:01Z",
    ).result == TERMINAL_RECORDED

    proof["attestation_signature_path"].write_text("changed-after-recording", encoding="utf-8")

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)
    assert recovered.result != ALREADY_TERMINAL
    assert recovered.result == LIFECYCLE_STATE_CORRUPTED


def test_terminal_recovery_blocks_when_signature_artifact_is_malformed(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _binding()
    store = SQLiteExecutionLifecycleStore(path)
    outcome_hash = _hash("outcome")
    current_evidence_hash = _hash("evidence")
    proof = _terminal_signature_proof(tmp_path, outcome_hash=outcome_hash, current_evidence_hash=current_evidence_hash)

    assert store.acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    assert store.record_terminal_outcome(
        binding,
        outcome_state=COMPLETED,
        outcome_hash=outcome_hash,
        current_evidence_hash=current_evidence_hash,
        **proof,
        completed_at="2026-08-13T12:00:01Z",
    ).result == TERMINAL_RECORDED

    proof["attestation_signature_path"].write_text("not-a-valid-signature", encoding="utf-8")
    _update_lifecycle_row(
        path,
        binding,
        attestation_signature_hash="sha256:" + ledger.sha256_file(proof["attestation_signature_path"]),
    )

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)
    assert recovered.result != ALREADY_TERMINAL
    assert recovered.result == LIFECYCLE_STATE_CORRUPTED


def test_sqlite_lifecycle_failed_and_partial_unknown_never_become_completed(tmp_path) -> None:
    failed = _binding(execution_authorization_hash=_hash("failed-auth"))
    partial = _binding(execution_authorization_hash=_hash("partial-auth"))
    store = SQLiteExecutionLifecycleStore(tmp_path / "lifecycle.db")
    failed_proof_dir = tmp_path / "failed-proof"
    completed_proof_dir = tmp_path / "completed-proof"
    failed_proof_dir.mkdir()
    completed_proof_dir.mkdir()

    assert store.acquire_execution_start(failed, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    failed_outcome_hash = _hash("failed-outcome")
    failed_current_evidence_hash = _hash("failed-evidence")
    assert store.record_terminal_outcome(
        failed,
        outcome_state=FAILED,
        outcome_hash=failed_outcome_hash,
        current_evidence_hash=failed_current_evidence_hash,
        **_terminal_signature_proof(failed_proof_dir, outcome_hash=failed_outcome_hash, current_evidence_hash=failed_current_evidence_hash),
        completed_at="2026-08-13T12:00:01Z",
    ).state == FAILED
    completed_outcome_hash = _hash("completed-outcome")
    completed_current_evidence_hash = _hash("completed-evidence")
    assert store.record_terminal_outcome(
        failed,
        outcome_state=COMPLETED,
        outcome_hash=completed_outcome_hash,
        current_evidence_hash=completed_current_evidence_hash,
        **_terminal_signature_proof(completed_proof_dir, outcome_hash=completed_outcome_hash, current_evidence_hash=completed_current_evidence_hash),
        completed_at="2026-08-13T12:00:02Z",
    ).state == FAILED

    assert store.acquire_execution_start(partial, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    assert store.record_terminal_outcome(
        partial,
        outcome_state=PARTIAL_UNKNOWN,
        outcome_hash=_hash("partial-outcome"),
        current_evidence_hash=_hash("partial-evidence"),
        reconciliation_phase=RECONCILIATION_PHASE_PRE_SIDE_EFFECT_SUBPROCESS_FAILURE,
        failure_class=FAILURE_CLASS_SUBPROCESS_EXECUTION_FAILED,
        completed_at="2026-08-13T12:00:01Z",
    ).state == PARTIAL_UNKNOWN
    assert store.record_terminal_outcome(
        partial,
        outcome_state=COMPLETED,
        outcome_hash=completed_outcome_hash,
        current_evidence_hash=completed_current_evidence_hash,
        **_terminal_signature_proof(tmp_path, outcome_hash=completed_outcome_hash, current_evidence_hash=completed_current_evidence_hash),
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


def test_fabricated_terminal_signature_proof_blocks_completion(tmp_path) -> None:
    store = SQLiteExecutionLifecycleStore(tmp_path / "lifecycle.db")
    binding = _binding()

    assert store.acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    result = store.record_terminal_outcome(
        binding,
        outcome_state=COMPLETED,
        outcome_hash=_hash("fabricated-outcome"),
        current_evidence_hash=_hash("fabricated-current-evidence"),
        attestation_payload_hash=_hash("fabricated-payload-file-not-present"),
        attestation_signature_hash=_hash("fabricated-signature-file-not-present"),
        signature_verification_result="VERIFIED",
        completed_at="2026-08-13T12:00:01Z",
    )

    assert result.result == LIFECYCLE_BINDING_INVALID
    assert result.state == "BLOCKED"
    recovered = SQLiteExecutionLifecycleStore(tmp_path / "lifecycle.db").recover(binding)
    assert recovered.result == LIFECYCLE_PARTIAL_UNKNOWN
    assert recovered.state == PARTIAL_UNKNOWN


def test_malformed_terminal_signature_proof_blocks_completion(tmp_path) -> None:
    store = SQLiteExecutionLifecycleStore(tmp_path / "lifecycle.db")
    binding = _binding()
    outcome_hash = _hash("outcome")
    current_evidence_hash = _hash("evidence")
    proof = _terminal_signature_proof(tmp_path, outcome_hash=outcome_hash, current_evidence_hash=current_evidence_hash)
    proof["attestation_signature_path"].write_text("not-a-valid-signature", encoding="utf-8")
    proof["attestation_signature_hash"] = "sha256:" + ledger.sha256_file(proof["attestation_signature_path"])

    assert store.acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    result = store.record_terminal_outcome(
        binding,
        outcome_state=COMPLETED,
        outcome_hash=outcome_hash,
        current_evidence_hash=current_evidence_hash,
        **proof,
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


def _store_partial_unknown_lifecycle(path, binding: dict[str, str] | None = None) -> dict[str, str]:
    binding = binding or _binding()
    store = SQLiteExecutionLifecycleStore(path)
    assert store.acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED
    assert store.record_terminal_outcome(
        binding,
        outcome_state=PARTIAL_UNKNOWN,
        outcome_hash=_hash("partial-outcome"),
        current_evidence_hash=_hash("partial-evidence"),
        reconciliation_phase=RECONCILIATION_PHASE_POST_SUBPROCESS_ATTESTATION_FAILURE,
        failure_class=FAILURE_CLASS_ATTESTATION_GENERATION_FAILED,
        completed_at="2026-08-13T12:00:01Z",
    ).state == PARTIAL_UNKNOWN
    return binding


def _reconciliation_hash_for_test(evidence: dict[str, Any]) -> str:
    return sha256_reference(
        {
            "reconciliation_phase": evidence.get("reconciliation_phase"),
            "failure_class": evidence.get("failure_class"),
            "lifecycle_state": evidence.get("execution_lifecycle_state"),
            "execution_lifecycle_binding_hash": evidence.get("execution_lifecycle_binding_hash"),
            "execution_authorization_hash": evidence.get("execution_authorization_hash"),
            "decision_evidence_hash": evidence.get("decision_evidence_hash"),
            "execution_contract_hash": evidence.get("execution_contract_hash"),
            "request_hash": evidence.get("request_hash"),
            "command_hash": evidence.get("command_hash"),
            "outcome_hash": evidence.get("outcome_hash"),
            "current_outcome_evidence_hash": evidence.get("current_outcome_evidence_hash"),
            "attestation_payload_hash": evidence.get("attestation_payload_hash"),
            "attestation_signature_hash": evidence.get("attestation_signature_hash"),
            "signature_verification_result": evidence.get("signature_verification_result"),
        },
        default_to_str=True,
    )


def _persist_mismatched_reconciliation_pair(path, binding: dict[str, str]) -> None:
    conn = sqlite3.connect(path)
    try:
        evidence_json = conn.execute(
            "SELECT evidence_json FROM execution_lifecycle WHERE execution_authorization_hash = ?",
            (binding["execution_authorization_hash"],),
        ).fetchone()[0]
        evidence = json.loads(evidence_json)
        evidence["reconciliation_phase"] = RECONCILIATION_PHASE_PRE_SIDE_EFFECT_SUBPROCESS_FAILURE
        evidence["failure_class"] = FAILURE_CLASS_SIGNATURE_VERIFICATION_FAILED
        evidence["reconciliation_evidence_hash"] = _reconciliation_hash_for_test(evidence)
        hash_payload = dict(evidence)
        hash_payload.pop("execution_lifecycle_evidence_hash", None)
        evidence["execution_lifecycle_evidence_hash"] = sha256_reference(hash_payload, default_to_str=True)
        with conn:
            conn.execute(
                """
                UPDATE execution_lifecycle
                   SET reconciliation_phase = ?,
                       failure_class = ?,
                       evidence_json = ?
                 WHERE execution_authorization_hash = ?
                """,
                (
                    RECONCILIATION_PHASE_PRE_SIDE_EFFECT_SUBPROCESS_FAILURE,
                    FAILURE_CLASS_SIGNATURE_VERIFICATION_FAILED,
                    ledger.canonical_json_bytes(evidence).decode("utf-8"),
                    binding["execution_authorization_hash"],
                ),
            )
    finally:
        conn.close()


def test_partial_unknown_reconciliation_evidence_survives_restart(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_partial_unknown_lifecycle(path)

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)

    assert recovered.result == ALREADY_TERMINAL
    assert recovered.state == PARTIAL_UNKNOWN
    assert recovered.evidence["reconciliation_phase"] == RECONCILIATION_PHASE_POST_SUBPROCESS_ATTESTATION_FAILURE
    assert recovered.evidence["failure_class"] == FAILURE_CLASS_ATTESTATION_GENERATION_FAILED
    assert recovered.evidence["reconciliation_evidence_hash"].startswith("sha256:")


def test_mismatched_partial_unknown_reconciliation_pair_rejected_at_record_time(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _binding()
    store = SQLiteExecutionLifecycleStore(path)
    assert store.acquire_execution_start(binding, started_at="2026-08-13T12:00:00Z").result == START_ACQUIRED

    result = store.record_terminal_outcome(
        binding,
        outcome_state=PARTIAL_UNKNOWN,
        outcome_hash=_hash("partial-outcome"),
        current_evidence_hash=_hash("partial-evidence"),
        reconciliation_phase=RECONCILIATION_PHASE_PRE_SIDE_EFFECT_SUBPROCESS_FAILURE,
        failure_class=FAILURE_CLASS_SIGNATURE_VERIFICATION_FAILED,
        completed_at="2026-08-13T12:00:01Z",
    )

    assert result.result == LIFECYCLE_BINDING_INVALID
    assert result.state != PARTIAL_UNKNOWN


def test_mismatched_persisted_reconciliation_pair_fails_closed_on_recovery(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_partial_unknown_lifecycle(path)
    _persist_mismatched_reconciliation_pair(path, binding)

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)

    assert recovered.result == LIFECYCLE_STATE_CORRUPTED
    assert recovered.state != PARTIAL_UNKNOWN


def test_supported_partial_unknown_reconciliation_pairs_remain_accepted(tmp_path) -> None:
    store = SQLiteExecutionLifecycleStore(tmp_path / "lifecycle.db")
    pairs = (
        (RECONCILIATION_PHASE_PRE_SIDE_EFFECT_SUBPROCESS_FAILURE, FAILURE_CLASS_SUBPROCESS_EXECUTION_FAILED),
        (RECONCILIATION_PHASE_POST_SUBPROCESS_ATTESTATION_FAILURE, FAILURE_CLASS_ATTESTATION_GENERATION_FAILED),
        (RECONCILIATION_PHASE_SIGNATURE_VERIFICATION_FAILURE, FAILURE_CLASS_SIGNATURE_VERIFICATION_FAILED),
    )

    for index, (phase, failure_class) in enumerate(pairs):
        binding = _binding(execution_authorization_hash=_hash(f"pair-auth-{index}"))
        assert store.acquire_execution_start(binding, started_at=f"2026-08-13T12:00:0{index}Z").result == START_ACQUIRED

        result = store.record_terminal_outcome(
            binding,
            outcome_state=PARTIAL_UNKNOWN,
            outcome_hash=_hash(f"partial-outcome-{index}"),
            current_evidence_hash=_hash(f"partial-evidence-{index}"),
            reconciliation_phase=phase,
            failure_class=failure_class,
            completed_at=f"2026-08-13T12:00:1{index}Z",
        )

        assert result.result == TERMINAL_RECORDED
        assert result.state == PARTIAL_UNKNOWN
        assert result.evidence["reconciliation_phase"] == phase
        assert result.evidence["failure_class"] == failure_class


def test_partial_unknown_reconciliation_phase_tamper_fails_closed(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_partial_unknown_lifecycle(path)
    _mutate_evidence_json(path, binding, lambda evidence: evidence.update({"reconciliation_phase": RECONCILIATION_PHASE_SIGNATURE_VERIFICATION_FAILURE}))

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)

    assert recovered.result == LIFECYCLE_STATE_CORRUPTED


def test_partial_unknown_reconciliation_failure_class_tamper_fails_closed(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_partial_unknown_lifecycle(path)
    _mutate_evidence_json(path, binding, lambda evidence: evidence.update({"failure_class": FAILURE_CLASS_SIGNATURE_VERIFICATION_FAILED}))

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)

    assert recovered.result == LIFECYCLE_STATE_CORRUPTED


def test_partial_unknown_reconciliation_binding_tamper_fails_closed(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_partial_unknown_lifecycle(path)
    _mutate_evidence_json(path, binding, lambda evidence: evidence.update({"decision_evidence_hash": _hash("tampered-decision")}))

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)

    assert recovered.result == LIFECYCLE_STATE_CORRUPTED


def test_malformed_partial_unknown_reconciliation_evidence_fails_closed(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_partial_unknown_lifecycle(path)
    _mutate_evidence_json(path, binding, lambda evidence: evidence.update({"reconciliation_evidence_hash": "not-a-hash"}))

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)

    assert recovered.result == LIFECYCLE_STATE_CORRUPTED


def test_missing_partial_unknown_reconciliation_evidence_fails_closed(tmp_path) -> None:
    path = tmp_path / "lifecycle.db"
    binding = _store_partial_unknown_lifecycle(path)
    _mutate_evidence_json(path, binding, lambda evidence: evidence.pop("reconciliation_phase"))

    recovered = SQLiteExecutionLifecycleStore(path).recover(binding)

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
