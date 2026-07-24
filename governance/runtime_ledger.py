from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from governance.audit_evidence import ZERO_AUDIT_CHAIN_HASH, canonical_audit_json, sha256_audit_hash


GOVERNANCE_RUNTIME_LEDGER_SCHEMA = "usbay.governance.runtime_ledger.v1"
GOVERNANCE_RUNTIME_LEDGER_ENTRY_SCHEMA = GOVERNANCE_RUNTIME_LEDGER_SCHEMA + ".entry"
GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH = ZERO_AUDIT_CHAIN_HASH
GOVERNANCE_RUNTIME_LEDGER_DECISIONS = (
    "ALLOWED",
    "BLOCKED",
    "REVIEW_REQUIRED",
    "FAIL_CLOSED",
)
GOVERNANCE_RUNTIME_LEDGER_ERRORS = (
    "RUNTIME_LEDGER_ENTRY_MALFORMED",
    "RUNTIME_LEDGER_SCHEMA_INVALID",
    "RUNTIME_LEDGER_CONTEXT_MISSING",
    "RUNTIME_LEDGER_DECISION_INVALID",
    "RUNTIME_LEDGER_HASH_INVALID",
    "RUNTIME_LEDGER_POSITION_INVALID",
    "RUNTIME_LEDGER_PREVIOUS_HASH_MISMATCH",
    "RUNTIME_LEDGER_ENTRY_HASH_MISMATCH",
    "RUNTIME_LEDGER_ID_MISMATCH",
    "RUNTIME_LEDGER_DUPLICATE_ENTRY",
    "RUNTIME_LEDGER_TENANT_CROSSOVER",
    "RUNTIME_LEDGER_POLICY_VERSION_CROSSOVER",
    "RUNTIME_LEDGER_RAW_DATA_FORBIDDEN",
)
_RAW_MARKERS = (
    "raw_payload",
    "raw_evidence",
    "raw_approval",
    "payload_body",
    "secret",
    "token",
    "credential",
    "credentials",
    "private_key",
    "certificate",
)


class GovernanceRuntimeLedgerError(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimeLedgerDecisionContext:
    timestamp: str
    tenant: str
    policy_version: str
    validator: str
    decision: str
    failure_code: str
    evidence_id: str
    audit_hash: str
    correlation_id: str


def runtime_ledger_schema() -> dict[str, Any]:
    return {
        "schema": GOVERNANCE_RUNTIME_LEDGER_SCHEMA,
        "entry_schema": GOVERNANCE_RUNTIME_LEDGER_ENTRY_SCHEMA,
        "decisions": list(GOVERNANCE_RUNTIME_LEDGER_DECISIONS),
        "errors": list(GOVERNANCE_RUNTIME_LEDGER_ERRORS),
        "payload_policy": "hash-only",
        "storage_model": "append-only-reference-ledger",
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
    }


def build_runtime_ledger_entry(
    context: RuntimeLedgerDecisionContext | dict[str, Any],
    *,
    previous_hash: str = GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH,
    position: int = 0,
) -> dict[str, Any]:
    payload = _context_payload(context)
    _validate_context(payload)
    if not _is_sha256_reference(previous_hash):
        raise GovernanceRuntimeLedgerError("RUNTIME_LEDGER_PREVIOUS_HASH_MISMATCH")
    if not isinstance(position, int) or position < 0:
        raise GovernanceRuntimeLedgerError("RUNTIME_LEDGER_POSITION_INVALID")
    entry_seed = {
        "timestamp": payload["timestamp"],
        "tenant": payload["tenant"],
        "policy_version": payload["policy_version"],
        "validator": payload["validator"],
        "decision": payload["decision"],
        "failure_code": payload["failure_code"],
        "evidence_id": payload["evidence_id"],
        "audit_hash": payload["audit_hash"],
        "correlation_id": payload["correlation_id"],
    }
    ledger_id = sha256_audit_hash({"schema": GOVERNANCE_RUNTIME_LEDGER_ENTRY_SCHEMA, **entry_seed})
    entry_payload = {
        "schema": GOVERNANCE_RUNTIME_LEDGER_ENTRY_SCHEMA,
        "ledger_id": ledger_id,
        "position": position,
        "timestamp": payload["timestamp"],
        "tenant": payload["tenant"],
        "policy_version": payload["policy_version"],
        "validator": payload["validator"],
        "decision": payload["decision"],
        "failure_code": payload["failure_code"],
        "evidence_id": payload["evidence_id"],
        "audit_hash": payload["audit_hash"],
        "previous_hash": previous_hash,
        "correlation_id": payload["correlation_id"],
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
    }
    entry = {**entry_payload, "entry_hash": sha256_audit_hash(entry_payload)}
    _assert_no_raw_markers(entry)
    return entry


def append_runtime_ledger_entry(
    records: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    context: RuntimeLedgerDecisionContext | dict[str, Any],
) -> tuple[dict[str, Any], ...]:
    current_records = tuple(records)
    errors = verify_runtime_ledger(current_records)
    if errors:
        raise GovernanceRuntimeLedgerError(errors[0])
    previous_hash = current_records[-1]["entry_hash"] if current_records else GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH
    entry = build_runtime_ledger_entry(context, previous_hash=previous_hash, position=len(current_records))
    duplicate_errors = verify_runtime_ledger((*current_records, entry))
    if duplicate_errors:
        raise GovernanceRuntimeLedgerError(duplicate_errors[0])
    return (*current_records, entry)


def verify_runtime_ledger(records: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> tuple[str, ...]:
    if not isinstance(records, (tuple, list)):
        return ("RUNTIME_LEDGER_ENTRY_MALFORMED",)
    previous_hash = GOVERNANCE_RUNTIME_LEDGER_GENESIS_HASH
    seen_entry_hashes: set[str] = set()
    seen_ledger_ids: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for expected_position, entry in enumerate(records):
        if not isinstance(entry, dict):
            errors.append("RUNTIME_LEDGER_ENTRY_MALFORMED")
            continue
        try:
            _assert_no_raw_markers(entry)
        except GovernanceRuntimeLedgerError:
            errors.append("RUNTIME_LEDGER_RAW_DATA_FORBIDDEN")
        if entry.get("schema") != GOVERNANCE_RUNTIME_LEDGER_ENTRY_SCHEMA:
            errors.append("RUNTIME_LEDGER_SCHEMA_INVALID")
        if entry.get("position") != expected_position:
            errors.append("RUNTIME_LEDGER_POSITION_INVALID")
        if entry.get("previous_hash") != previous_hash:
            errors.append("RUNTIME_LEDGER_PREVIOUS_HASH_MISMATCH")
        for field in ("ledger_id", "audit_hash", "previous_hash", "correlation_id", "entry_hash"):
            if not _is_sha256_reference(entry.get(field)):
                errors.append("RUNTIME_LEDGER_HASH_INVALID")
        if entry.get("decision") not in GOVERNANCE_RUNTIME_LEDGER_DECISIONS:
            errors.append("RUNTIME_LEDGER_DECISION_INVALID")
        if entry.get("execution_allowed") is not False or entry.get("provider_execution") is not False or entry.get("production_activation") is not False:
            errors.append("RUNTIME_LEDGER_ENTRY_MALFORMED")
        if _missing_required(entry):
            errors.append("RUNTIME_LEDGER_CONTEXT_MISSING")
        expected_ledger_id = sha256_audit_hash(
            {
                "schema": GOVERNANCE_RUNTIME_LEDGER_ENTRY_SCHEMA,
                "timestamp": str(entry.get("timestamp", "")),
                "tenant": str(entry.get("tenant", "")),
                "policy_version": str(entry.get("policy_version", "")),
                "validator": str(entry.get("validator", "")),
                "decision": str(entry.get("decision", "")),
                "failure_code": str(entry.get("failure_code", "")),
                "evidence_id": str(entry.get("evidence_id", "")),
                "audit_hash": str(entry.get("audit_hash", "")),
                "correlation_id": str(entry.get("correlation_id", "")),
            }
        )
        if entry.get("ledger_id") != expected_ledger_id:
            errors.append("RUNTIME_LEDGER_ID_MISMATCH")
        expected_entry_hash = sha256_audit_hash({key: value for key, value in entry.items() if key != "entry_hash"})
        if entry.get("entry_hash") != expected_entry_hash:
            errors.append("RUNTIME_LEDGER_ENTRY_HASH_MISMATCH")
        ledger_id = str(entry.get("ledger_id", ""))
        if ledger_id in seen_ledger_ids:
            prior = seen_ledger_ids[ledger_id]
            if prior.get("tenant") != entry.get("tenant"):
                errors.append("RUNTIME_LEDGER_TENANT_CROSSOVER")
            elif prior.get("policy_version") != entry.get("policy_version"):
                errors.append("RUNTIME_LEDGER_POLICY_VERSION_CROSSOVER")
            else:
                errors.append("RUNTIME_LEDGER_DUPLICATE_ENTRY")
        seen_ledger_ids[ledger_id] = dict(entry)
        entry_hash = str(entry.get("entry_hash", ""))
        if entry_hash in seen_entry_hashes:
            errors.append("RUNTIME_LEDGER_DUPLICATE_ENTRY")
        seen_entry_hashes.add(entry_hash)
        previous_hash = entry_hash
    return _ordered_unique_errors(errors)


def serialize_runtime_ledger_entry(entry: dict[str, Any]) -> str:
    errors = verify_runtime_ledger((entry,))
    if errors:
        raise GovernanceRuntimeLedgerError(errors[0])
    return canonical_audit_json(entry)


def _context_payload(context: RuntimeLedgerDecisionContext | dict[str, Any]) -> dict[str, Any]:
    if isinstance(context, RuntimeLedgerDecisionContext):
        return {
            "timestamp": context.timestamp,
            "tenant": context.tenant,
            "policy_version": context.policy_version,
            "validator": context.validator,
            "decision": context.decision,
            "failure_code": context.failure_code,
            "evidence_id": context.evidence_id,
            "audit_hash": context.audit_hash,
            "correlation_id": context.correlation_id,
        }
    return dict(context)


def _validate_context(payload: dict[str, Any]) -> None:
    required = (
        "timestamp",
        "tenant",
        "policy_version",
        "validator",
        "decision",
        "failure_code",
        "evidence_id",
        "audit_hash",
        "correlation_id",
    )
    for field in required:
        if not isinstance(payload.get(field), str) or not str(payload.get(field, "")).strip():
            if field == "failure_code" and payload.get("decision") == "ALLOWED":
                continue
            raise GovernanceRuntimeLedgerError("RUNTIME_LEDGER_CONTEXT_MISSING")
    if payload.get("decision") not in GOVERNANCE_RUNTIME_LEDGER_DECISIONS:
        raise GovernanceRuntimeLedgerError("RUNTIME_LEDGER_DECISION_INVALID")
    for field in ("audit_hash", "correlation_id"):
        if not _is_sha256_reference(payload.get(field)):
            raise GovernanceRuntimeLedgerError("RUNTIME_LEDGER_HASH_INVALID")
    _assert_no_raw_markers(payload)


def _missing_required(entry: dict[str, Any]) -> bool:
    required = (
        "ledger_id",
        "timestamp",
        "tenant",
        "policy_version",
        "validator",
        "decision",
        "evidence_id",
        "audit_hash",
        "previous_hash",
        "correlation_id",
        "entry_hash",
    )
    return any(entry.get(field) in ("", None) for field in required)


def _ordered_unique_errors(errors: list[str]) -> tuple[str, ...]:
    return tuple(code for code in GOVERNANCE_RUNTIME_LEDGER_ERRORS if code in errors)


def _is_sha256_reference(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def _assert_no_raw_markers(payload: Any) -> None:
    serialized = canonical_audit_json(payload)
    lowered = serialized.lower()
    if any(marker in lowered for marker in _RAW_MARKERS):
        raise GovernanceRuntimeLedgerError("RUNTIME_LEDGER_RAW_DATA_FORBIDDEN")
