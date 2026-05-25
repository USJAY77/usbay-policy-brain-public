from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from governance.deployment_runtime_health import canonical_json, sha256_text
from governance.immutable_remote_attestation_ledger import LEDGER_HASH_CHAIN_VERIFIED, verify_ledger


FEDERATION_SCHEMA = "usbay.external_verifier_federation.v1"
TRUSTED_ANCHOR_SCHEMA = "usbay.trusted_anchor_authority.v1"
TSA_TIMESTAMP_SCHEMA = "usbay.rfc3161_style_timestamp_verification.v1"
VERIFIER_QUORUM_REACHED = "VERIFIER_QUORUM_REACHED"
VERIFIER_QUORUM_FAILED = "VERIFIER_QUORUM_FAILED"
VERIFIER_NODE_UNAVAILABLE = "VERIFIER_NODE_UNAVAILABLE"
VERIFIER_CONTRADICTION_DETECTED = "VERIFIER_CONTRADICTION_DETECTED"
TRUSTED_ANCHOR_VERIFIED = "TRUSTED_ANCHOR_VERIFIED"
TRUSTED_ANCHOR_UNAVAILABLE = "TRUSTED_ANCHOR_UNAVAILABLE"
TSA_TIMESTAMP_VERIFIED = "TSA_TIMESTAMP_VERIFIED"
TSA_TIMESTAMP_INVALID = "TSA_TIMESTAMP_INVALID"
REQUIRED_REASON_CODES = (
    VERIFIER_QUORUM_REACHED,
    VERIFIER_QUORUM_FAILED,
    VERIFIER_NODE_UNAVAILABLE,
    VERIFIER_CONTRADICTION_DETECTED,
    TRUSTED_ANCHOR_VERIFIED,
    TRUSTED_ANCHOR_UNAVAILABLE,
    TSA_TIMESTAMP_VERIFIED,
    TSA_TIMESTAMP_INVALID,
)
FORBIDDEN_DIAGNOSTIC_TERMS = (
    "PRIVATE " + "KEY",
    "approval_" + "contents",
    "raw_" + "payload",
    "credential",
    "secret",
    "bearer ",
    "access_token",
    "stack_trace",
    "traceback",
)


class ExternalVerifierFederationError(RuntimeError):
    pass


@dataclass(frozen=True)
class VerifierNode:
    verifier_id: str
    verifier_type: str
    available: bool
    ledger_head_hash: str
    ledger_valid: bool
    trusted_anchor_hash: str = ""
    timestamp_hash: str = ""
    reason_codes: tuple[str, ...] = ()


def local_verifier_from_ledger(verifier_id: str, ledger_path: Path) -> VerifierNode:
    result = verify_ledger(ledger_path)
    return VerifierNode(
        verifier_id=verifier_id,
        verifier_type="LOCAL",
        available=True,
        ledger_head_hash=result.head_hash,
        ledger_valid=result.valid,
        reason_codes=tuple(result.reason_codes),
    )


def verifier_from_cache(record: dict[str, Any]) -> VerifierNode:
    _assert_safe(record)
    return VerifierNode(
        verifier_id=str(record.get("verifier_id", "")),
        verifier_type=str(record.get("verifier_type", "OFFLINE_CACHE")),
        available=bool(record.get("available")),
        ledger_head_hash=str(record.get("ledger_head_hash", "")),
        ledger_valid=bool(record.get("ledger_valid")),
        trusted_anchor_hash=str(record.get("trusted_anchor_hash", "")),
        timestamp_hash=str(record.get("timestamp_hash", "")),
        reason_codes=tuple(str(code) for code in record.get("reason_codes", []) if isinstance(code, str)),
    )


def verify_trusted_anchor(
    *,
    ledger_head_hash: str,
    anchor_record: dict[str, Any] | None,
) -> dict[str, Any]:
    if not anchor_record:
        return _anchor_result(False, ledger_head_hash, "", [TRUSTED_ANCHOR_UNAVAILABLE])
    try:
        _assert_safe(anchor_record)
        anchor_hash = str(anchor_record.get("anchor_hash", ""))
        anchored_head = str(anchor_record.get("ledger_head_hash", ""))
        if not _is_sha256(anchor_hash) or anchored_head != ledger_head_hash:
            return _anchor_result(False, ledger_head_hash, anchor_hash, [TRUSTED_ANCHOR_UNAVAILABLE])
        return _anchor_result(True, ledger_head_hash, anchor_hash, [TRUSTED_ANCHOR_VERIFIED])
    except ExternalVerifierFederationError:
        return _anchor_result(False, ledger_head_hash, "", [TRUSTED_ANCHOR_UNAVAILABLE])


def verify_tsa_timestamp(
    *,
    evidence_hash: str,
    timestamp_record: dict[str, Any] | None,
) -> dict[str, Any]:
    if not timestamp_record:
        return _timestamp_result(False, evidence_hash, "", [TSA_TIMESTAMP_INVALID])
    try:
        _assert_safe(timestamp_record)
        imprint = str(timestamp_record.get("message_imprint_hash", ""))
        token_hash = str(timestamp_record.get("timestamp_token_hash", ""))
        policy_id = str(timestamp_record.get("tsa_policy_id", ""))
        gen_time = str(timestamp_record.get("tsa_gen_time_utc", ""))
        if imprint != evidence_hash or not _is_sha256(token_hash) or not policy_id or not gen_time.endswith("Z"):
            return _timestamp_result(False, evidence_hash, token_hash, [TSA_TIMESTAMP_INVALID])
        return _timestamp_result(True, evidence_hash, token_hash, [TSA_TIMESTAMP_VERIFIED])
    except ExternalVerifierFederationError:
        return _timestamp_result(False, evidence_hash, "", [TSA_TIMESTAMP_INVALID])


def verify_federation_quorum(
    *,
    verifiers: list[VerifierNode],
    expected_ledger_head_hash: str,
    trusted_anchor: dict[str, Any] | None = None,
    timestamp_record: dict[str, Any] | None = None,
    quorum: int = 2,
) -> dict[str, Any]:
    if quorum != 2 or len(verifiers) != 3:
        raise ExternalVerifierFederationError(VERIFIER_QUORUM_FAILED)
    _assert_safe([node.__dict__ for node in verifiers])
    available = [node for node in verifiers if node.available]
    unavailable_count = len(verifiers) - len(available)
    valid_matches = [
        node for node in available
        if node.ledger_valid and node.ledger_head_hash == expected_ledger_head_hash
    ]
    contradictory = [
        node for node in available
        if node.ledger_valid and node.ledger_head_hash and node.ledger_head_hash != expected_ledger_head_hash
    ]

    reason_codes: list[str] = []
    if unavailable_count:
        reason_codes.append(VERIFIER_NODE_UNAVAILABLE)
    if contradictory:
        reason_codes.append(VERIFIER_CONTRADICTION_DETECTED)
    if len(valid_matches) >= quorum and not contradictory:
        reason_codes.append(VERIFIER_QUORUM_REACHED)
    else:
        reason_codes.append(VERIFIER_QUORUM_FAILED)

    anchor = verify_trusted_anchor(ledger_head_hash=expected_ledger_head_hash, anchor_record=trusted_anchor)
    timestamp = verify_tsa_timestamp(evidence_hash=expected_ledger_head_hash, timestamp_record=timestamp_record)
    reason_codes.extend(anchor["reason_codes"])
    reason_codes.extend(timestamp["reason_codes"])
    valid = (
        VERIFIER_QUORUM_REACHED in reason_codes
        and VERIFIER_CONTRADICTION_DETECTED not in reason_codes
        and anchor["valid"] is True
        and timestamp["valid"] is True
    )
    payload = {
        "schema_version": FEDERATION_SCHEMA,
        "federation_status": "VERIFIED" if valid else "BLOCKED",
        "quorum_policy": "2-of-3",
        "quorum_required": quorum,
        "verifier_count": len(verifiers),
        "available_verifier_count": len(available),
        "matching_verifier_count": len(valid_matches),
        "expected_ledger_head_hash": expected_ledger_head_hash,
        "verifier_evidence_hash": sha256_text(canonical_json([
            {
                "verifier_id_hash": sha256_text(node.verifier_id),
                "verifier_type": node.verifier_type,
                "available": node.available,
                "ledger_head_hash": node.ledger_head_hash,
                "ledger_valid": node.ledger_valid,
                "reason_codes": list(node.reason_codes),
            }
            for node in verifiers
        ])),
        "trusted_anchor": anchor,
        "tsa_timestamp": timestamp,
        "reason_codes": tuple(dict.fromkeys(reason_codes)),
        "fail_closed": not valid,
    }
    payload["federation_hash"] = sha256_text(canonical_json(payload))
    _assert_safe(payload)
    return payload


def _anchor_result(valid: bool, ledger_head_hash: str, anchor_hash: str, reason_codes: list[str]) -> dict[str, Any]:
    payload = {
        "schema_version": TRUSTED_ANCHOR_SCHEMA,
        "valid": valid,
        "ledger_head_hash": ledger_head_hash,
        "anchor_hash": anchor_hash,
        "reason_codes": tuple(dict.fromkeys(reason_codes)),
    }
    payload["anchor_verification_hash"] = sha256_text(canonical_json(payload))
    _assert_safe(payload)
    return payload


def _timestamp_result(valid: bool, evidence_hash: str, token_hash: str, reason_codes: list[str]) -> dict[str, Any]:
    payload = {
        "schema_version": TSA_TIMESTAMP_SCHEMA,
        "valid": valid,
        "message_imprint_hash": evidence_hash,
        "timestamp_token_hash": token_hash,
        "reason_codes": tuple(dict.fromkeys(reason_codes)),
    }
    payload["timestamp_verification_hash"] = sha256_text(canonical_json(payload))
    _assert_safe(payload)
    return payload


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _assert_safe(value: Any) -> None:
    text = canonical_json(value)
    if any(term.lower() in text.lower() for term in FORBIDDEN_DIAGNOSTIC_TERMS):
        raise ExternalVerifierFederationError(VERIFIER_QUORUM_FAILED)
