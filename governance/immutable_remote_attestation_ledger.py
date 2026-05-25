from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from governance.deployment_runtime_health import canonical_json, sha256_text


LEDGER_SCHEMA = "usbay.immutable_remote_attestation_ledger.v1"
LEDGER_ENTRY_SCHEMA = "usbay.immutable_remote_attestation_ledger_entry.v1"
LEDGER_GENESIS_HASH = "0" * 64
LEDGER_APPEND_SUCCEEDED = "LEDGER_APPEND_SUCCEEDED"
LEDGER_APPEND_BLOCKED = "LEDGER_APPEND_BLOCKED"
LEDGER_HASH_CHAIN_VERIFIED = "LEDGER_HASH_CHAIN_VERIFIED"
LEDGER_HASH_CHAIN_BROKEN = "LEDGER_HASH_CHAIN_BROKEN"
LEDGER_REMOTE_UNAVAILABLE = "LEDGER_REMOTE_UNAVAILABLE"
LEDGER_POLICY_MISMATCH = "LEDGER_POLICY_MISMATCH"
REQUIRED_REASON_CODES = (
    LEDGER_APPEND_SUCCEEDED,
    LEDGER_APPEND_BLOCKED,
    LEDGER_HASH_CHAIN_VERIFIED,
    LEDGER_HASH_CHAIN_BROKEN,
    LEDGER_REMOTE_UNAVAILABLE,
    LEDGER_POLICY_MISMATCH,
)
FORBIDDEN_DIAGNOSTIC_TERMS = (
    "PRIVATE " + "KEY",
    "approval_" + "contents",
    "raw_" + "payload",
    "private_key",
    "secret",
    "token",
    "stack_trace",
    "traceback",
)


class ImmutableAttestationLedgerError(RuntimeError):
    pass


@dataclass(frozen=True)
class LedgerVerificationResult:
    valid: bool
    reason_codes: tuple[str, ...]
    entry_count: int
    head_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "reason_codes": list(self.reason_codes),
            "entry_count": self.entry_count,
            "head_hash": self.head_hash,
        }


def build_attestation_ledger_evidence(
    *,
    runtime_attestation: dict[str, Any],
    deployment_health: dict[str, Any],
    startup_verification: dict[str, Any],
    policy_version: str,
    policy_hash: str,
    audit_chain_hash: str,
    post_merge_branch_hygiene: dict[str, Any] | None = None,
    cleanup_denial_event: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence = {
        "runtime_attestation_hash": _evidence_hash(runtime_attestation),
        "deployment_health_hash": _evidence_hash(deployment_health),
        "startup_verification_hash": _evidence_hash(startup_verification),
        "post_merge_branch_hygiene_hash": _optional_evidence_hash(post_merge_branch_hygiene),
        "cleanup_denial_event_hash": _optional_evidence_hash(cleanup_denial_event),
        "policy_version_hash": sha256_text(str(policy_version)),
        "policy_hash": str(policy_hash),
        "audit_chain_hash": str(audit_chain_hash),
        "runtime_attestation_status": str(runtime_attestation.get("attestation_status", "")),
        "deployment_health_status": str(deployment_health.get("status", "")),
        "startup_reason_codes_hash": sha256_text(canonical_json(startup_verification.get("reason_codes", []))),
        "branch_hygiene_reason_codes_hash": sha256_text(
            canonical_json((post_merge_branch_hygiene or {}).get("reason_codes", []))
        ),
        "cleanup_denial_reason_codes_hash": sha256_text(
            canonical_json((cleanup_denial_event or {}).get("reason_codes", []))
        ),
    }
    _assert_safe(evidence)
    return evidence


def create_ledger_entry(
    *,
    evidence: dict[str, Any],
    previous_hash: str,
    sequence: int,
    timestamp_utc: str,
    expected_policy_hash: str = "",
    remote_anchor_hash: str = "",
    require_remote_anchor: bool = False,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    if not _is_sha256(previous_hash) or sequence < 1:
        reason_codes.append(LEDGER_APPEND_BLOCKED)
    if expected_policy_hash and evidence.get("policy_hash") != expected_policy_hash:
        reason_codes.append(LEDGER_POLICY_MISMATCH)
        reason_codes.append(LEDGER_APPEND_BLOCKED)
    if not remote_anchor_hash:
        reason_codes.append(LEDGER_REMOTE_UNAVAILABLE)
        if require_remote_anchor:
            reason_codes.append(LEDGER_APPEND_BLOCKED)
    if not reason_codes or reason_codes == [LEDGER_REMOTE_UNAVAILABLE]:
        reason_codes.insert(0, LEDGER_APPEND_SUCCEEDED)

    entry = {
        "schema_version": LEDGER_ENTRY_SCHEMA,
        "sequence": sequence,
        "previous_hash": previous_hash,
        "timestamp_utc": str(timestamp_utc),
        "remote_anchor_hash": str(remote_anchor_hash),
        "remote_anchor_status": "ANCHORED" if remote_anchor_hash else "UNAVAILABLE",
        "evidence": _bounded_evidence(evidence),
        "reason_codes": tuple(dict.fromkeys(reason_codes)),
    }
    entry["evidence_hash"] = sha256_text(canonical_json(entry["evidence"]))
    entry["entry_hash"] = _entry_hash(entry)
    _assert_safe(entry)
    return entry


def append_ledger_entry(
    ledger_path: Path,
    *,
    evidence: dict[str, Any],
    timestamp_utc: str,
    expected_policy_hash: str = "",
    remote_anchor_hash: str = "",
    require_remote_anchor: bool = False,
) -> dict[str, Any]:
    verification = verify_ledger(ledger_path)
    if not verification.valid:
        return _blocked_entry(
            evidence=evidence,
            reason_codes=(LEDGER_APPEND_BLOCKED, LEDGER_HASH_CHAIN_BROKEN),
            previous_hash=verification.head_hash,
            sequence=verification.entry_count + 1,
            timestamp_utc=timestamp_utc,
        )
    entry = create_ledger_entry(
        evidence=evidence,
        previous_hash=verification.head_hash,
        sequence=verification.entry_count + 1,
        timestamp_utc=timestamp_utc,
        expected_policy_hash=expected_policy_hash,
        remote_anchor_hash=remote_anchor_hash,
        require_remote_anchor=require_remote_anchor,
    )
    if LEDGER_APPEND_BLOCKED in entry["reason_codes"]:
        return entry
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with ledger_path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(entry) + "\n")
    return entry


def verify_ledger(ledger_path: Path) -> LedgerVerificationResult:
    if not ledger_path.exists():
        return LedgerVerificationResult(
            valid=True,
            reason_codes=(LEDGER_HASH_CHAIN_VERIFIED,),
            entry_count=0,
            head_hash=LEDGER_GENESIS_HASH,
        )
    previous_hash = LEDGER_GENESIS_HASH
    entry_count = 0
    try:
        lines = [line for line in ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        for raw in lines:
            entry = json.loads(raw)
            _assert_safe(entry)
            entry_count += 1
            if entry.get("schema_version") != LEDGER_ENTRY_SCHEMA:
                return _broken(entry_count, previous_hash)
            if entry.get("sequence") != entry_count:
                return _broken(entry_count, previous_hash)
            if entry.get("previous_hash") != previous_hash:
                return _broken(entry_count, previous_hash)
            if entry.get("evidence_hash") != sha256_text(canonical_json(entry.get("evidence", {}))):
                return _broken(entry_count, previous_hash)
            if entry.get("entry_hash") != _entry_hash(entry):
                return _broken(entry_count, previous_hash)
            previous_hash = str(entry["entry_hash"])
    except Exception:
        return _broken(entry_count, previous_hash)
    return LedgerVerificationResult(
        valid=True,
        reason_codes=(LEDGER_HASH_CHAIN_VERIFIED,),
        entry_count=entry_count,
        head_hash=previous_hash,
    )


def ledger_summary(ledger_path: Path) -> dict[str, Any]:
    verification = verify_ledger(ledger_path)
    payload = {
        "schema_version": LEDGER_SCHEMA,
        "ledger_path_hash": sha256_text(str(ledger_path)),
        **verification.to_dict(),
    }
    payload["summary_hash"] = sha256_text(canonical_json(payload))
    _assert_safe(payload)
    return payload


def _entry_hash(entry: dict[str, Any]) -> str:
    payload = dict(entry)
    payload.pop("entry_hash", None)
    return sha256_text(canonical_json(payload))


def _blocked_entry(
    *,
    evidence: dict[str, Any],
    reason_codes: tuple[str, ...],
    previous_hash: str,
    sequence: int,
    timestamp_utc: str,
) -> dict[str, Any]:
    entry = {
        "schema_version": LEDGER_ENTRY_SCHEMA,
        "sequence": sequence,
        "previous_hash": previous_hash if _is_sha256(previous_hash) else LEDGER_GENESIS_HASH,
        "timestamp_utc": timestamp_utc,
        "remote_anchor_hash": "",
        "remote_anchor_status": "UNAVAILABLE",
        "evidence": _bounded_evidence(evidence),
        "reason_codes": tuple(dict.fromkeys(reason_codes)),
    }
    entry["evidence_hash"] = sha256_text(canonical_json(entry["evidence"]))
    entry["entry_hash"] = _entry_hash(entry)
    _assert_safe(entry)
    return entry


def _broken(entry_count: int, head_hash: str) -> LedgerVerificationResult:
    return LedgerVerificationResult(
        valid=False,
        reason_codes=(LEDGER_HASH_CHAIN_BROKEN,),
        entry_count=entry_count,
        head_hash=head_hash if _is_sha256(head_hash) else LEDGER_GENESIS_HASH,
    )


def _bounded_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        raise ImmutableAttestationLedgerError(LEDGER_APPEND_BLOCKED)
    bounded = dict(evidence)
    for key, value in bounded.items():
        key_text = str(key).lower()
        if key_text.endswith("_hash") or key_text in {
            "policy_hash",
            "runtime_attestation_status",
            "deployment_health_status",
        }:
            continue
        if isinstance(value, str) and value in {"SIGNED", "BLOCKED", "READY", "VERIFIED", "INVALID"}:
            continue
        raise ImmutableAttestationLedgerError(LEDGER_APPEND_BLOCKED)
    _assert_safe(bounded)
    return bounded


def _evidence_hash(value: dict[str, Any]) -> str:
    if not isinstance(value, dict) or not value:
        raise ImmutableAttestationLedgerError(LEDGER_APPEND_BLOCKED)
    _assert_safe(value)
    return sha256_text(canonical_json(value))


def _optional_evidence_hash(value: dict[str, Any] | None) -> str:
    if not value:
        return ""
    return _evidence_hash(value)


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _assert_safe(value: Any) -> None:
    text = canonical_json(value)
    if any(term.lower() in text.lower() for term in FORBIDDEN_DIAGNOSTIC_TERMS):
        raise ImmutableAttestationLedgerError(LEDGER_APPEND_BLOCKED)
