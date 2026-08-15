from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
import json
import sqlite3
from pathlib import Path
from typing import Any, Mapping, Protocol

from audit import ledger
from governance.hashing import is_sha256_reference, sha256_reference


EXECUTION_STARTED = "EXECUTION_STARTED"
COMPLETED = "COMPLETED"
FAILED = "FAILED"
PARTIAL_UNKNOWN = "PARTIAL_UNKNOWN"
BLOCKED = "BLOCKED"

RECONCILIATION_PHASE_PRE_SIDE_EFFECT_SUBPROCESS_FAILURE = "PRE_SIDE_EFFECT_SUBPROCESS_FAILURE"
RECONCILIATION_PHASE_POST_SUBPROCESS_ATTESTATION_FAILURE = "POST_SUBPROCESS_ATTESTATION_FAILURE"
RECONCILIATION_PHASE_SIGNATURE_VERIFICATION_FAILURE = "SIGNATURE_VERIFICATION_FAILURE"

FAILURE_CLASS_SUBPROCESS_EXECUTION_FAILED = "SUBPROCESS_EXECUTION_FAILED"
FAILURE_CLASS_ATTESTATION_GENERATION_FAILED = "ATTESTATION_GENERATION_FAILED"
FAILURE_CLASS_SIGNATURE_VERIFICATION_FAILED = "SIGNATURE_VERIFICATION_FAILED"

SUPPORTED_RECONCILIATION_PHASES = frozenset(
    {
        RECONCILIATION_PHASE_PRE_SIDE_EFFECT_SUBPROCESS_FAILURE,
        RECONCILIATION_PHASE_POST_SUBPROCESS_ATTESTATION_FAILURE,
        RECONCILIATION_PHASE_SIGNATURE_VERIFICATION_FAILURE,
    }
)
SUPPORTED_FAILURE_CLASSES = frozenset(
    {
        FAILURE_CLASS_SUBPROCESS_EXECUTION_FAILED,
        FAILURE_CLASS_ATTESTATION_GENERATION_FAILED,
        FAILURE_CLASS_SIGNATURE_VERIFICATION_FAILED,
    }
)

START_ACQUIRED = "START_ACQUIRED"
TERMINAL_RECORDED = "TERMINAL_RECORDED"
ALREADY_TERMINAL = "ALREADY_TERMINAL"
LIFECYCLE_PARTIAL_UNKNOWN = "LIFECYCLE_PARTIAL_UNKNOWN"
LIFECYCLE_STORAGE_UNAVAILABLE = "LIFECYCLE_STORAGE_UNAVAILABLE"
LIFECYCLE_STORAGE_TIMEOUT = "LIFECYCLE_STORAGE_TIMEOUT"
LIFECYCLE_BINDING_INVALID = "LIFECYCLE_BINDING_INVALID"
LIFECYCLE_BINDING_MISMATCH = "LIFECYCLE_BINDING_MISMATCH"
LIFECYCLE_STATE_CORRUPTED = "LIFECYCLE_STATE_CORRUPTED"
UNSUPPORTED_LIFECYCLE_STORE = "UNSUPPORTED_LIFECYCLE_STORE"

DEFAULT_SQLITE_PATH = Path("tmp/execution_lifecycle.db")
ZERO_SHA256_REFERENCE = "sha256:" + ("0" * 64)
REQUIRED_BINDING_FIELDS = (
    "execution_authorization_hash",
    "authorization_id",
    "consumed_decision_evidence_hash",
    "decision_evidence_hash",
    "decision_consumption_evidence_hash",
    "decision_replay_evidence_hash",
    "policy_id",
    "policy_version",
    "policy_hash",
    "request_hash",
    "command_hash",
    "execution_contract_hash",
)
HASH_BINDING_FIELDS = (
    "execution_authorization_hash",
    "consumed_decision_evidence_hash",
    "decision_evidence_hash",
    "decision_consumption_evidence_hash",
    "decision_replay_evidence_hash",
    "policy_hash",
    "request_hash",
    "command_hash",
    "execution_contract_hash",
)
TERMINAL_STATES = frozenset({COMPLETED, FAILED, PARTIAL_UNKNOWN})
SUPPORTED_RESULTS = frozenset(
    {
        START_ACQUIRED,
        TERMINAL_RECORDED,
        ALREADY_TERMINAL,
        LIFECYCLE_PARTIAL_UNKNOWN,
        LIFECYCLE_STORAGE_UNAVAILABLE,
        LIFECYCLE_STORAGE_TIMEOUT,
        LIFECYCLE_BINDING_INVALID,
        LIFECYCLE_BINDING_MISMATCH,
        LIFECYCLE_STATE_CORRUPTED,
        UNSUPPORTED_LIFECYCLE_STORE,
    }
)


@dataclass(frozen=True)
class LifecycleResult:
    result: str
    reason_code: str
    state: str
    store_type: str
    evidence: dict[str, Any]


class ExecutionLifecycleStore(Protocol):
    store_type: str

    def acquire_execution_start(self, binding: Mapping[str, Any], *, started_at: str) -> LifecycleResult:
        ...

    def record_terminal_outcome(
        self,
        binding: Mapping[str, Any],
        *,
        outcome_state: str,
        outcome_hash: str,
        current_evidence_hash: str,
        attestation_payload_hash: str = ZERO_SHA256_REFERENCE,
        attestation_signature_hash: str = ZERO_SHA256_REFERENCE,
        signature_verification_result: str = "UNVERIFIED",
        reconciliation_phase: str | None = None,
        failure_class: str | None = None,
        completed_at: str,
    ) -> LifecycleResult:
        ...

    def recover(self, binding: Mapping[str, Any]) -> LifecycleResult:
        ...


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def lifecycle_binding(
    *,
    command: Mapping[str, Any],
    governed_execution_authorization: Mapping[str, Any] | None,
    governed_execution_contract: Mapping[str, Any] | None,
    consumed_decision_evidence_hash: str | None,
    command_hash: str,
    execution_contract_hash: str,
) -> dict[str, Any]:
    if not isinstance(governed_execution_authorization, Mapping):
        return {}
    return {
        "execution_authorization_hash": governed_execution_authorization.get("execution_authorization_hash"),
        "authorization_id": governed_execution_authorization.get("authorization_id"),
        "consumed_decision_evidence_hash": consumed_decision_evidence_hash,
        "decision_evidence_hash": governed_execution_authorization.get("decision_evidence_hash"),
        "decision_consumption_evidence_hash": governed_execution_authorization.get("decision_consumption_evidence_hash"),
        "decision_replay_evidence_hash": governed_execution_authorization.get("decision_replay_evidence_hash"),
        "policy_id": governed_execution_authorization.get("policy_id"),
        "policy_version": governed_execution_authorization.get("policy_version"),
        "policy_hash": governed_execution_authorization.get("policy_hash"),
        "request_hash": governed_execution_authorization.get("request_hash"),
        "command_hash": command_hash,
        "execution_contract_hash": execution_contract_hash,
    }


def validate_lifecycle_binding(binding: Mapping[str, Any] | None) -> bool:
    if not isinstance(binding, Mapping):
        return False
    for field in REQUIRED_BINDING_FIELDS:
        value = binding.get(field)
        if not isinstance(value, str) or not value:
            return False
    for field in HASH_BINDING_FIELDS:
        if not is_sha256_reference(binding.get(field)):
            return False
    return True


def _binding_hash(binding: Mapping[str, Any]) -> str:
    return sha256_reference({field: binding.get(field) for field in REQUIRED_BINDING_FIELDS}, default_to_str=True)


def _evidence_hash(payload: Mapping[str, Any]) -> str:
    return sha256_reference(dict(payload), default_to_str=True)


def _valid_reconciliation(phase: str | None, failure_class: str | None, *, state: str) -> bool:
    if state != PARTIAL_UNKNOWN:
        return phase is None and failure_class is None
    return phase in SUPPORTED_RECONCILIATION_PHASES and failure_class in SUPPORTED_FAILURE_CLASSES


def _reconciliation_hash(evidence: Mapping[str, Any]) -> str:
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


def _record_evidence(
    binding: Mapping[str, Any],
    *,
    state: str,
    reason_code: str,
    store_type: str,
    timestamp: str,
    outcome_hash: str = ZERO_SHA256_REFERENCE,
    current_outcome_evidence_hash: str = ZERO_SHA256_REFERENCE,
    attestation_payload_hash: str = ZERO_SHA256_REFERENCE,
    attestation_signature_hash: str = ZERO_SHA256_REFERENCE,
    signature_verification_result: str = "UNVERIFIED",
    reconciliation_phase: str | None = None,
    failure_class: str | None = None,
) -> dict[str, Any]:
    evidence = {
        "execution_lifecycle_schema_version": "usbay.execution_lifecycle.v1",
        "execution_lifecycle_state": state,
        "execution_lifecycle_reason_code": reason_code,
        "execution_lifecycle_store_type": store_type,
        "execution_lifecycle_timestamp": timestamp,
        "execution_lifecycle_binding_hash": _binding_hash(binding),
        "execution_authorization_hash": binding.get("execution_authorization_hash"),
        "authorization_id": binding.get("authorization_id"),
        "consumed_decision_evidence_hash": binding.get("consumed_decision_evidence_hash"),
        "decision_evidence_hash": binding.get("decision_evidence_hash"),
        "decision_consumption_evidence_hash": binding.get("decision_consumption_evidence_hash"),
        "decision_replay_evidence_hash": binding.get("decision_replay_evidence_hash"),
        "policy_id": binding.get("policy_id"),
        "policy_version": binding.get("policy_version"),
        "policy_hash": binding.get("policy_hash"),
        "request_hash": binding.get("request_hash"),
        "command_hash": binding.get("command_hash"),
        "execution_contract_hash": binding.get("execution_contract_hash"),
        "outcome_hash": outcome_hash,
        "current_outcome_evidence_hash": current_outcome_evidence_hash,
        "attestation_payload_hash": attestation_payload_hash,
        "attestation_signature_hash": attestation_signature_hash,
        "signature_verification_result": signature_verification_result,
        "reconciliation_phase": reconciliation_phase,
        "failure_class": failure_class,
    }
    evidence["reconciliation_evidence_hash"] = _reconciliation_hash(evidence) if state == PARTIAL_UNKNOWN else None
    evidence["execution_lifecycle_evidence_hash"] = _evidence_hash(evidence)
    return evidence


def _terminal_evidence_corrupted(
    evidence_json: str,
    binding: Mapping[str, Any],
    *,
    binding_hash: str,
    state: str,
    store_type: str,
    outcome_hash: str | None,
    current_outcome_evidence_hash: str | None,
    attestation_payload_hash: str | None,
    attestation_signature_hash: str | None,
    signature_verification_result: str | None,
    reconciliation_phase: str | None,
    failure_class: str | None,
) -> bool:
    try:
        evidence = json.loads(evidence_json)
        ledger.canonical_json_bytes(evidence)
    except Exception:
        return True
    if not isinstance(evidence, Mapping):
        return True
    expected_values = {
        "execution_lifecycle_schema_version": "usbay.execution_lifecycle.v1",
        "execution_lifecycle_state": state,
        "execution_lifecycle_reason_code": TERMINAL_RECORDED,
        "execution_lifecycle_store_type": store_type,
        "execution_lifecycle_binding_hash": binding_hash,
        "execution_authorization_hash": binding.get("execution_authorization_hash"),
        "authorization_id": binding.get("authorization_id"),
        "consumed_decision_evidence_hash": binding.get("consumed_decision_evidence_hash"),
        "decision_evidence_hash": binding.get("decision_evidence_hash"),
        "decision_consumption_evidence_hash": binding.get("decision_consumption_evidence_hash"),
        "decision_replay_evidence_hash": binding.get("decision_replay_evidence_hash"),
        "policy_id": binding.get("policy_id"),
        "policy_version": binding.get("policy_version"),
        "policy_hash": binding.get("policy_hash"),
        "request_hash": binding.get("request_hash"),
        "command_hash": binding.get("command_hash"),
        "execution_contract_hash": binding.get("execution_contract_hash"),
        "outcome_hash": outcome_hash,
        "current_outcome_evidence_hash": current_outcome_evidence_hash,
        "attestation_payload_hash": attestation_payload_hash,
        "attestation_signature_hash": attestation_signature_hash,
        "signature_verification_result": signature_verification_result,
        "reconciliation_phase": reconciliation_phase,
        "failure_class": failure_class,
    }
    if not _valid_reconciliation(reconciliation_phase, failure_class, state=state):
        return True
    if not isinstance(evidence.get("execution_lifecycle_timestamp"), str) or not evidence.get("execution_lifecycle_timestamp"):
        return True
    stored_evidence_hash = evidence.get("execution_lifecycle_evidence_hash")
    if not is_sha256_reference(stored_evidence_hash):
        return True
    if state == PARTIAL_UNKNOWN:
        if not is_sha256_reference(evidence.get("reconciliation_evidence_hash")):
            return True
        if evidence.get("reconciliation_evidence_hash") != _reconciliation_hash(evidence):
            return True
    elif evidence.get("reconciliation_evidence_hash") is not None:
        return True
    for field, expected in expected_values.items():
        if evidence.get(field) != expected:
            return True
    hash_payload = dict(evidence)
    hash_payload.pop("execution_lifecycle_evidence_hash", None)
    return _evidence_hash(hash_payload) != stored_evidence_hash


def _result(
    binding: Mapping[str, Any],
    *,
    result: str,
    reason_code: str,
    state: str,
    store_type: str,
    timestamp: str | None = None,
    outcome_hash: str = ZERO_SHA256_REFERENCE,
    current_outcome_evidence_hash: str = ZERO_SHA256_REFERENCE,
    attestation_payload_hash: str = ZERO_SHA256_REFERENCE,
    attestation_signature_hash: str = ZERO_SHA256_REFERENCE,
    signature_verification_result: str = "UNVERIFIED",
    reconciliation_phase: str | None = None,
    failure_class: str | None = None,
) -> LifecycleResult:
    return LifecycleResult(
        result,
        reason_code,
        state,
        store_type,
        _record_evidence(
            binding,
            state=state,
            reason_code=reason_code,
            store_type=store_type,
            timestamp=timestamp or utc_now_iso(),
            outcome_hash=outcome_hash,
            current_outcome_evidence_hash=current_outcome_evidence_hash,
            attestation_payload_hash=attestation_payload_hash,
            attestation_signature_hash=attestation_signature_hash,
            signature_verification_result=signature_verification_result,
            reconciliation_phase=reconciliation_phase,
            failure_class=failure_class,
        )
        if validate_lifecycle_binding(binding)
        else {},
    )


class SQLiteExecutionLifecycleStore:
    """Durable executor lifecycle store using transactional primary-key transitions."""

    store_type = "sqlite"

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = Path(db_path or DEFAULT_SQLITE_PATH)

    def _connect(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS execution_lifecycle (
                execution_authorization_hash TEXT PRIMARY KEY,
                binding_hash TEXT NOT NULL,
                state TEXT NOT NULL,
                started_at TEXT NOT NULL,
                terminal_at TEXT,
                outcome_hash TEXT,
                current_outcome_evidence_hash TEXT,
                attestation_payload_hash TEXT,
                attestation_signature_hash TEXT,
                signature_verification_result TEXT,
                reconciliation_phase TEXT,
                failure_class TEXT,
                evidence_json TEXT NOT NULL
            )
            """
        )
        for column, definition in (
            ("attestation_payload_hash", "TEXT"),
            ("attestation_signature_hash", "TEXT"),
            ("signature_verification_result", "TEXT"),
            ("reconciliation_phase", "TEXT"),
            ("failure_class", "TEXT"),
        ):
            existing = {row[1] for row in conn.execute("PRAGMA table_info(execution_lifecycle)").fetchall()}
            if column not in existing:
                conn.execute(f"ALTER TABLE execution_lifecycle ADD COLUMN {column} {definition}")
        return conn

    def acquire_execution_start(self, binding: Mapping[str, Any], *, started_at: str) -> LifecycleResult:
        if not validate_lifecycle_binding(binding):
            return _result(binding or {}, result=LIFECYCLE_BINDING_INVALID, reason_code=LIFECYCLE_BINDING_INVALID, state=BLOCKED, store_type=self.store_type, timestamp=started_at)
        binding_hash = _binding_hash(binding)
        start_evidence = _record_evidence(binding, state=EXECUTION_STARTED, reason_code=START_ACQUIRED, store_type=self.store_type, timestamp=started_at)
        try:
            conn = self._connect()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO execution_lifecycle (
                            execution_authorization_hash,
                            binding_hash,
                            state,
                            started_at,
                            evidence_json
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            binding["execution_authorization_hash"],
                            binding_hash,
                            EXECUTION_STARTED,
                            started_at,
                            ledger.canonical_json_bytes(start_evidence).decode("utf-8"),
                        ),
                    )
                return LifecycleResult(START_ACQUIRED, START_ACQUIRED, EXECUTION_STARTED, self.store_type, start_evidence)
            finally:
                conn.close()
        except sqlite3.IntegrityError:
            return self.recover(binding)
        except sqlite3.OperationalError as exc:
            reason = LIFECYCLE_STORAGE_TIMEOUT if "locked" in str(exc).lower() or "timeout" in str(exc).lower() else LIFECYCLE_STORAGE_UNAVAILABLE
            recovered = self.recover(binding)
            if recovered.result not in {LIFECYCLE_STORAGE_TIMEOUT, LIFECYCLE_STORAGE_UNAVAILABLE}:
                return recovered
            return _result(binding, result=reason, reason_code=reason, state=BLOCKED, store_type=self.store_type, timestamp=started_at)
        except Exception:
            return _result(binding, result=LIFECYCLE_STORAGE_UNAVAILABLE, reason_code=LIFECYCLE_STORAGE_UNAVAILABLE, state=BLOCKED, store_type=self.store_type, timestamp=started_at)

    def record_terminal_outcome(
        self,
        binding: Mapping[str, Any],
        *,
        outcome_state: str,
        outcome_hash: str,
        current_evidence_hash: str,
        attestation_payload_hash: str = ZERO_SHA256_REFERENCE,
        attestation_signature_hash: str = ZERO_SHA256_REFERENCE,
        signature_verification_result: str = "UNVERIFIED",
        reconciliation_phase: str | None = None,
        failure_class: str | None = None,
        completed_at: str,
    ) -> LifecycleResult:
        if not validate_lifecycle_binding(binding):
            return _result(binding or {}, result=LIFECYCLE_BINDING_INVALID, reason_code=LIFECYCLE_BINDING_INVALID, state=BLOCKED, store_type=self.store_type, timestamp=completed_at)
        terminal_signature_invalid = (
            outcome_state in {COMPLETED, FAILED}
            and (
                signature_verification_result != "VERIFIED"
                or not is_sha256_reference(attestation_payload_hash)
                or not is_sha256_reference(attestation_signature_hash)
                or attestation_payload_hash == ZERO_SHA256_REFERENCE
                or attestation_signature_hash == ZERO_SHA256_REFERENCE
            )
        )
        if (
            outcome_state not in TERMINAL_STATES
            or not is_sha256_reference(outcome_hash)
            or not is_sha256_reference(current_evidence_hash)
            or terminal_signature_invalid
            or not _valid_reconciliation(reconciliation_phase, failure_class, state=outcome_state)
        ):
            return _result(binding, result=LIFECYCLE_BINDING_INVALID, reason_code=LIFECYCLE_BINDING_INVALID, state=BLOCKED, store_type=self.store_type, timestamp=completed_at)
        binding_hash = _binding_hash(binding)
        terminal_evidence = _record_evidence(
            binding,
            state=outcome_state,
            reason_code=TERMINAL_RECORDED,
            store_type=self.store_type,
            timestamp=completed_at,
            outcome_hash=outcome_hash,
            current_outcome_evidence_hash=current_evidence_hash,
            attestation_payload_hash=attestation_payload_hash,
            attestation_signature_hash=attestation_signature_hash,
            signature_verification_result=signature_verification_result,
            reconciliation_phase=reconciliation_phase,
            failure_class=failure_class,
        )
        try:
            conn = self._connect()
            try:
                with conn:
                    cursor = conn.execute(
                        """
                        UPDATE execution_lifecycle
                           SET state = ?,
                               terminal_at = ?,
                               outcome_hash = ?,
                               current_outcome_evidence_hash = ?,
                               attestation_payload_hash = ?,
                               attestation_signature_hash = ?,
                               signature_verification_result = ?,
                               reconciliation_phase = ?,
                               failure_class = ?,
                               evidence_json = ?
                         WHERE execution_authorization_hash = ?
                           AND binding_hash = ?
                           AND state = ?
                        """,
                        (
                            outcome_state,
                            completed_at,
                            outcome_hash,
                            current_evidence_hash,
                            attestation_payload_hash,
                            attestation_signature_hash,
                            signature_verification_result,
                            reconciliation_phase,
                            failure_class,
                            ledger.canonical_json_bytes(terminal_evidence).decode("utf-8"),
                            binding["execution_authorization_hash"],
                            binding_hash,
                            EXECUTION_STARTED,
                        ),
                    )
                if cursor.rowcount == 1:
                    return LifecycleResult(TERMINAL_RECORDED, TERMINAL_RECORDED, outcome_state, self.store_type, terminal_evidence)
                return self.recover(binding)
            finally:
                conn.close()
        except sqlite3.OperationalError as exc:
            reason = LIFECYCLE_STORAGE_TIMEOUT if "locked" in str(exc).lower() or "timeout" in str(exc).lower() else LIFECYCLE_STORAGE_UNAVAILABLE
            return _result(binding, result=reason, reason_code=reason, state=BLOCKED, store_type=self.store_type, timestamp=completed_at)
        except Exception:
            return _result(binding, result=LIFECYCLE_STORAGE_UNAVAILABLE, reason_code=LIFECYCLE_STORAGE_UNAVAILABLE, state=BLOCKED, store_type=self.store_type, timestamp=completed_at)

    def recover(self, binding: Mapping[str, Any]) -> LifecycleResult:
        if not validate_lifecycle_binding(binding):
            return _result(binding or {}, result=LIFECYCLE_BINDING_INVALID, reason_code=LIFECYCLE_BINDING_INVALID, state=BLOCKED, store_type=self.store_type)
        try:
            conn = self._connect()
            try:
                row = conn.execute(
                    """
                    SELECT binding_hash, state, outcome_hash, current_outcome_evidence_hash, attestation_payload_hash, attestation_signature_hash, signature_verification_result, reconciliation_phase, failure_class, evidence_json
                      FROM execution_lifecycle
                     WHERE execution_authorization_hash = ?
                    """,
                    (binding["execution_authorization_hash"],),
                ).fetchone()
            finally:
                conn.close()
        except sqlite3.OperationalError as exc:
            reason = LIFECYCLE_STORAGE_TIMEOUT if "locked" in str(exc).lower() or "timeout" in str(exc).lower() else LIFECYCLE_STORAGE_UNAVAILABLE
            return _result(binding, result=reason, reason_code=reason, state=BLOCKED, store_type=self.store_type)
        except Exception:
            return _result(binding, result=LIFECYCLE_STORAGE_UNAVAILABLE, reason_code=LIFECYCLE_STORAGE_UNAVAILABLE, state=BLOCKED, store_type=self.store_type)
        if row is None:
            return _result(binding, result=LIFECYCLE_PARTIAL_UNKNOWN, reason_code="LIFECYCLE_RECORD_MISSING", state=PARTIAL_UNKNOWN, store_type=self.store_type)
        binding_hash, state, outcome_hash, current_outcome_evidence_hash, attestation_payload_hash, attestation_signature_hash, signature_verification_result, reconciliation_phase, failure_class, evidence_json = row
        if binding_hash != _binding_hash(binding):
            return _result(binding, result=LIFECYCLE_BINDING_MISMATCH, reason_code=LIFECYCLE_BINDING_MISMATCH, state=BLOCKED, store_type=self.store_type)
        if state == EXECUTION_STARTED:
            return _result(binding, result=LIFECYCLE_PARTIAL_UNKNOWN, reason_code="EXECUTION_STARTED_WITHOUT_TERMINAL_EVIDENCE", state=PARTIAL_UNKNOWN, store_type=self.store_type)
        if state in TERMINAL_STATES:
            if _terminal_evidence_corrupted(
                evidence_json,
                binding,
                binding_hash=binding_hash,
                state=state,
                store_type=self.store_type,
                outcome_hash=outcome_hash,
                current_outcome_evidence_hash=current_outcome_evidence_hash,
                attestation_payload_hash=attestation_payload_hash,
                attestation_signature_hash=attestation_signature_hash,
                signature_verification_result=signature_verification_result,
                reconciliation_phase=reconciliation_phase,
                failure_class=failure_class,
            ):
                return _result(binding, result=LIFECYCLE_STATE_CORRUPTED, reason_code=LIFECYCLE_STATE_CORRUPTED, state=BLOCKED, store_type=self.store_type)
            if state in {COMPLETED, FAILED} and (
                not is_sha256_reference(outcome_hash)
                or not is_sha256_reference(current_outcome_evidence_hash)
                or not is_sha256_reference(attestation_payload_hash)
                or not is_sha256_reference(attestation_signature_hash)
                or attestation_payload_hash == ZERO_SHA256_REFERENCE
                or attestation_signature_hash == ZERO_SHA256_REFERENCE
                or signature_verification_result != "VERIFIED"
            ):
                return _result(binding, result=LIFECYCLE_STATE_CORRUPTED, reason_code=LIFECYCLE_STATE_CORRUPTED, state=BLOCKED, store_type=self.store_type)
            return _result(
                binding,
                result=ALREADY_TERMINAL,
                reason_code=ALREADY_TERMINAL,
                state=state,
                store_type=self.store_type,
                outcome_hash=outcome_hash or ZERO_SHA256_REFERENCE,
                current_outcome_evidence_hash=current_outcome_evidence_hash or ZERO_SHA256_REFERENCE,
                attestation_payload_hash=attestation_payload_hash or ZERO_SHA256_REFERENCE,
                attestation_signature_hash=attestation_signature_hash or ZERO_SHA256_REFERENCE,
                signature_verification_result=signature_verification_result or "UNVERIFIED",
                reconciliation_phase=reconciliation_phase,
                failure_class=failure_class,
            )
        return _result(binding, result=LIFECYCLE_STATE_CORRUPTED, reason_code=LIFECYCLE_STATE_CORRUPTED, state=BLOCKED, store_type=self.store_type)


class UnsupportedExecutionLifecycleStore:
    store_type = "unsupported"

    def acquire_execution_start(self, binding: Mapping[str, Any], *, started_at: str) -> LifecycleResult:
        return _result(binding or {}, result=UNSUPPORTED_LIFECYCLE_STORE, reason_code=UNSUPPORTED_LIFECYCLE_STORE, state=BLOCKED, store_type=self.store_type, timestamp=started_at)

    def record_terminal_outcome(
        self,
        binding: Mapping[str, Any],
        *,
        outcome_state: str,
        outcome_hash: str,
        current_evidence_hash: str,
        attestation_payload_hash: str = ZERO_SHA256_REFERENCE,
        attestation_signature_hash: str = ZERO_SHA256_REFERENCE,
        signature_verification_result: str = "UNVERIFIED",
        reconciliation_phase: str | None = None,
        failure_class: str | None = None,
        completed_at: str,
    ) -> LifecycleResult:
        return _result(binding or {}, result=UNSUPPORTED_LIFECYCLE_STORE, reason_code=UNSUPPORTED_LIFECYCLE_STORE, state=BLOCKED, store_type=self.store_type, timestamp=completed_at)

    def recover(self, binding: Mapping[str, Any]) -> LifecycleResult:
        return _result(binding or {}, result=UNSUPPORTED_LIFECYCLE_STORE, reason_code=UNSUPPORTED_LIFECYCLE_STORE, state=BLOCKED, store_type=self.store_type)


def default_lifecycle_store() -> ExecutionLifecycleStore:
    backend = os.getenv("USBAY_EXECUTION_LIFECYCLE_STORE", "unsupported").strip().lower()
    if backend == "sqlite":
        return SQLiteExecutionLifecycleStore(os.getenv("USBAY_EXECUTION_LIFECYCLE_SQLITE_PATH") or DEFAULT_SQLITE_PATH)
    return UnsupportedExecutionLifecycleStore()
