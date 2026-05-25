from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from governance.deployment_runtime_health import canonical_json, sha256_text
from governance.device_identity_lifecycle import public_key_fingerprint


SCHEMA_VERSION = "usbay.verifier_continuity.v1"

VERIFIER_CONTINUITY_NOT_STARTED = "VERIFIER_CONTINUITY_NOT_STARTED"
VERIFIER_CONTINUITY_ACTIVE = "VERIFIER_CONTINUITY_ACTIVE"
VERIFIER_CONTINUITY_DEGRADED = "VERIFIER_CONTINUITY_DEGRADED"
VERIFIER_CONTINUITY_FAILED = "VERIFIER_CONTINUITY_FAILED"
VERIFIER_NODE_UNAVAILABLE = "VERIFIER_NODE_UNAVAILABLE"
VERIFIER_QUORUM_REACHED = "VERIFIER_QUORUM_REACHED"
VERIFIER_QUORUM_FAILED = "VERIFIER_QUORUM_FAILED"
VERIFIER_FAILOVER_ACTIVE = "VERIFIER_FAILOVER_ACTIVE"
VERIFIER_CONTRADICTION_DETECTED = "VERIFIER_CONTRADICTION_DETECTED"

VERIFIER_PACKET_MALFORMED = "VERIFIER_PACKET_MALFORMED"
VERIFIER_POLICY_MISMATCH = "VERIFIER_POLICY_MISMATCH"
VERIFIER_EPOCH_REPLAY_BLOCKED = "VERIFIER_EPOCH_REPLAY_BLOCKED"
VERIFIER_SIGNATURE_INVALID = "VERIFIER_SIGNATURE_INVALID"
VERIFIER_PUBLIC_KEY_UNTRUSTED = "VERIFIER_PUBLIC_KEY_UNTRUSTED"
VERIFIER_CONTINUITY_STALE = "VERIFIER_CONTINUITY_STALE"
VERIFIER_CONTINUITY_BLOCKED = "VERIFIER_CONTINUITY_BLOCKED"

ALLOWED_STATES = {
    VERIFIER_CONTINUITY_NOT_STARTED,
    VERIFIER_CONTINUITY_ACTIVE,
    VERIFIER_CONTINUITY_DEGRADED,
    VERIFIER_CONTINUITY_FAILED,
    VERIFIER_NODE_UNAVAILABLE,
    VERIFIER_QUORUM_REACHED,
    VERIFIER_QUORUM_FAILED,
    VERIFIER_FAILOVER_ACTIVE,
    VERIFIER_CONTRADICTION_DETECTED,
}

REQUIRED_NODE_FIELDS = (
    "verifier_node_id",
    "verifier_role",
    "verifier_hash",
    "quorum_group",
    "consensus_epoch",
    "continuity_window",
    "last_verified_at",
    "policy_hash",
    "signature_status",
    "continuity_state",
    "signature",
)

FORBIDDEN_DIAGNOSTIC_TERMS = (
    "PRIVATE " + "KEY",
    "approval_" + "contents",
    "raw_" + "payload",
    "secret",
    "token",
    "credential",
)
BLOCKING_REASON_CODES = {
    VERIFIER_PACKET_MALFORMED,
    VERIFIER_POLICY_MISMATCH,
    VERIFIER_EPOCH_REPLAY_BLOCKED,
    VERIFIER_SIGNATURE_INVALID,
    VERIFIER_PUBLIC_KEY_UNTRUSTED,
    VERIFIER_CONTRADICTION_DETECTED,
}


class VerifierContinuityError(RuntimeError):
    pass


@dataclass(frozen=True)
class VerifierContinuityResult:
    verified: bool
    continuity_state: str
    reason_code: str
    reason_codes: tuple[str, ...]
    audit_evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "verified": self.verified,
            "continuity_state": self.continuity_state,
            "reason_code": self.reason_code,
            "reason_codes": list(self.reason_codes),
            "audit_evidence": self.audit_evidence,
        }


def signed_verifier_payload(node: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(node)
    payload.pop("signature", None)
    payload.pop("verification", None)
    payload.pop("audit_evidence", None)
    return payload


def signable_verifier_message(node: Mapping[str, Any]) -> bytes:
    return canonical_json(signed_verifier_payload(node)).encode("utf-8")


def missing_verifier_continuity_result(*, policy_hash: str, timestamp_utc: str | None = None) -> VerifierContinuityResult:
    timestamp = timestamp_utc or _utc_now()
    evidence = _audit_evidence(
        continuity_state=VERIFIER_CONTINUITY_NOT_STARTED,
        reason_code=VERIFIER_QUORUM_FAILED,
        verifier_nodes=[],
        matching_nodes=[],
        unavailable_nodes=[],
        contradictory_nodes=[],
        failover_nodes=[],
        consensus_epochs=[],
        policy_hash=policy_hash,
        timestamp_utc=timestamp,
    )
    return VerifierContinuityResult(
        verified=False,
        continuity_state=VERIFIER_CONTINUITY_NOT_STARTED,
        reason_code=VERIFIER_QUORUM_FAILED,
        reason_codes=(VERIFIER_QUORUM_FAILED, VERIFIER_CONTINUITY_BLOCKED),
        audit_evidence=evidence,
    )


def validate_verifier_continuity(
    verifier_nodes: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...] | None,
    *,
    trusted_public_keys: Mapping[str, str],
    expected_policy_hash: str,
    quorum_required: int = 2,
    used_consensus_epochs: set[str] | frozenset[str] | tuple[str, ...] = (),
    now_utc: str | None = None,
) -> VerifierContinuityResult:
    timestamp = now_utc or _utc_now()
    if not verifier_nodes:
        return missing_verifier_continuity_result(policy_hash=expected_policy_hash, timestamp_utc=timestamp)

    reason_codes: list[str] = []
    valid_nodes: list[Mapping[str, Any]] = []
    unavailable_nodes: list[Mapping[str, Any]] = []
    contradictory_nodes: list[Mapping[str, Any]] = []
    failover_nodes: list[Mapping[str, Any]] = []
    epochs: list[str] = []

    expected_group = ""
    expected_epoch = ""

    for node in verifier_nodes:
        state = str(node.get("continuity_state", VERIFIER_CONTINUITY_FAILED))
        verifier_hash = str(node.get("verifier_hash", ""))
        quorum_group = str(node.get("quorum_group", ""))
        epoch = str(node.get("consensus_epoch", ""))
        role = str(node.get("verifier_role", ""))

        if not _node_shape_valid(node):
            reason_codes.append(VERIFIER_PACKET_MALFORMED)
            contradictory_nodes.append(node)
            continue
        if state not in ALLOWED_STATES:
            reason_codes.append(VERIFIER_PACKET_MALFORMED)
            contradictory_nodes.append(node)
            continue
        if str(node.get("policy_hash", "")) != expected_policy_hash:
            reason_codes.append(VERIFIER_POLICY_MISMATCH)
            contradictory_nodes.append(node)
        if epoch in set(used_consensus_epochs):
            reason_codes.append(VERIFIER_EPOCH_REPLAY_BLOCKED)
            contradictory_nodes.append(node)
        if not _is_fresh(str(node.get("last_verified_at", "")), str(node.get("continuity_window", "")), timestamp):
            reason_codes.append(VERIFIER_CONTINUITY_STALE)
            unavailable_nodes.append(node)
        if state == VERIFIER_NODE_UNAVAILABLE:
            reason_codes.append(VERIFIER_NODE_UNAVAILABLE)
            unavailable_nodes.append(node)
        if state == VERIFIER_FAILOVER_ACTIVE:
            reason_codes.append(VERIFIER_FAILOVER_ACTIVE)
            failover_nodes.append(node)
        if state == VERIFIER_CONTRADICTION_DETECTED:
            reason_codes.append(VERIFIER_CONTRADICTION_DETECTED)
            contradictory_nodes.append(node)

        public_key_pem = trusted_public_keys.get(verifier_hash)
        if not public_key_pem:
            reason_codes.append(VERIFIER_PUBLIC_KEY_UNTRUSTED)
            contradictory_nodes.append(node)
        else:
            try:
                trusted_fingerprint = public_key_fingerprint(public_key_pem)
            except Exception:
                trusted_fingerprint = ""
            if trusted_fingerprint != verifier_hash:
                reason_codes.append(VERIFIER_PUBLIC_KEY_UNTRUSTED)
                contradictory_nodes.append(node)
            elif node.get("signature_status") != "SIGNED" or not _verify_signature(node, public_key_pem):
                reason_codes.append(VERIFIER_SIGNATURE_INVALID)
                contradictory_nodes.append(node)

        if not expected_group:
            expected_group = quorum_group
        if not expected_epoch:
            expected_epoch = epoch
        if quorum_group != expected_group or epoch != expected_epoch:
            reason_codes.append(VERIFIER_CONTRADICTION_DETECTED)
            contradictory_nodes.append(node)

        if not any(item is node for item in contradictory_nodes + unavailable_nodes):
            valid_nodes.append(node)
        epochs.append(epoch)

    matching_nodes = [
        node for node in valid_nodes
        if str(node.get("continuity_state")) in {
            VERIFIER_CONTINUITY_ACTIVE,
            VERIFIER_QUORUM_REACHED,
            VERIFIER_FAILOVER_ACTIVE,
        }
    ]
    blocking_detected = any(code in reason_codes for code in BLOCKING_REASON_CODES)
    quorum_reached = len(matching_nodes) >= quorum_required and not blocking_detected
    failover_without_quorum = bool(failover_nodes) and not quorum_reached
    if failover_without_quorum:
        reason_codes.append(VERIFIER_QUORUM_FAILED)
    if quorum_reached:
        reason_codes.append(VERIFIER_QUORUM_REACHED)
    else:
        reason_codes.append(VERIFIER_QUORUM_FAILED)

    if VERIFIER_CONTRADICTION_DETECTED in reason_codes:
        state = VERIFIER_CONTRADICTION_DETECTED
    elif blocking_detected:
        state = VERIFIER_CONTINUITY_FAILED
    elif quorum_reached:
        state = VERIFIER_FAILOVER_ACTIVE if failover_nodes else VERIFIER_CONTINUITY_ACTIVE
    elif unavailable_nodes:
        state = VERIFIER_CONTINUITY_DEGRADED
    else:
        state = VERIFIER_CONTINUITY_FAILED

    verified = quorum_reached and state in {VERIFIER_CONTINUITY_ACTIVE, VERIFIER_FAILOVER_ACTIVE}
    if not verified:
        reason_codes.append(VERIFIER_CONTINUITY_BLOCKED)

    ordered_reasons = tuple(dict.fromkeys(reason_codes))
    reason_code = ordered_reasons[0] if ordered_reasons else VERIFIER_CONTINUITY_BLOCKED
    evidence = _audit_evidence(
        continuity_state=state,
        reason_code=reason_code,
        verifier_nodes=list(verifier_nodes),
        matching_nodes=matching_nodes,
        unavailable_nodes=unavailable_nodes,
        contradictory_nodes=contradictory_nodes,
        failover_nodes=failover_nodes,
        consensus_epochs=epochs,
        policy_hash=expected_policy_hash,
        timestamp_utc=timestamp,
    )
    return VerifierContinuityResult(
        verified=verified,
        continuity_state=state,
        reason_code=reason_code,
        reason_codes=ordered_reasons,
        audit_evidence=evidence,
    )


def _node_shape_valid(node: Mapping[str, Any]) -> bool:
    if any(field not in node for field in REQUIRED_NODE_FIELDS):
        return False
    if any(not isinstance(node.get(field), str) or not str(node.get(field)).strip() for field in REQUIRED_NODE_FIELDS):
        return False
    if not _is_sha256(str(node.get("verifier_hash", ""))):
        return False
    if not _is_sha256(str(node.get("policy_hash", ""))):
        return False
    try:
        return int(str(node.get("continuity_window", ""))) > 0
    except ValueError:
        return False


def _is_fresh(last_verified_at: str, continuity_window: str, now_utc: str) -> bool:
    try:
        last_verified = _parse_utc(last_verified_at)
        now = _parse_utc(now_utc)
        window_seconds = int(continuity_window)
    except (VerifierContinuityError, ValueError):
        return False
    return 0 <= (now - last_verified).total_seconds() <= window_seconds


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise VerifierContinuityError(VERIFIER_PACKET_MALFORMED) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_public_key(public_key_pem: str) -> Ed25519PublicKey:
    try:
        normalized = public_key_pem.strip().replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r\n", "\n").replace("\r", "\n")
        key = serialization.load_pem_public_key(normalized.encode("utf-8"))
    except Exception as exc:
        raise VerifierContinuityError(VERIFIER_SIGNATURE_INVALID) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise VerifierContinuityError(VERIFIER_SIGNATURE_INVALID)
    return key


def _verify_signature(node: Mapping[str, Any], public_key_pem: str) -> bool:
    try:
        signature = base64.b64decode(str(node.get("signature", "")).encode("ascii"), validate=True)
        _load_public_key(public_key_pem).verify(signature, signable_verifier_message(node))
        return True
    except (InvalidSignature, ValueError, TypeError, VerifierContinuityError):
        return False


def _audit_evidence(
    *,
    continuity_state: str,
    reason_code: str,
    verifier_nodes: list[Mapping[str, Any]],
    matching_nodes: list[Mapping[str, Any]],
    unavailable_nodes: list[Mapping[str, Any]],
    contradictory_nodes: list[Mapping[str, Any]],
    failover_nodes: list[Mapping[str, Any]],
    consensus_epochs: list[str],
    policy_hash: str,
    timestamp_utc: str,
) -> dict[str, Any]:
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "continuity_state": continuity_state,
        "reason_code": reason_code,
        "verifier_node_hashes": [_node_evidence_hash(node) for node in verifier_nodes],
        "quorum_evidence": {
            "required": 2,
            "matching": len(matching_nodes),
            "matching_hash": sha256_text(canonical_json([_node_evidence_hash(node) for node in matching_nodes])),
        },
        "continuity_epoch_hash": sha256_text(canonical_json(sorted(set(consensus_epochs)))),
        "failover_evidence": {
            "active": bool(failover_nodes),
            "failover_hash": sha256_text(canonical_json([_node_evidence_hash(node) for node in failover_nodes])),
        },
        "contradiction_evidence": {
            "detected": bool(contradictory_nodes),
            "contradiction_hash": sha256_text(canonical_json([_node_evidence_hash(node) for node in contradictory_nodes])),
        },
        "unavailable_verifier_hash": sha256_text(canonical_json([_node_evidence_hash(node) for node in unavailable_nodes])),
        "policy_hash": policy_hash,
        "timestamp": timestamp_utc,
    }
    evidence["verifier_continuity_audit_hash"] = sha256_text(canonical_json(evidence))
    _assert_safe(evidence)
    return evidence


def _node_evidence_hash(node: Mapping[str, Any]) -> str:
    bounded = {
        "verifier_node_id_hash": sha256_text(str(node.get("verifier_node_id", ""))),
        "verifier_role": str(node.get("verifier_role", "")),
        "verifier_hash": str(node.get("verifier_hash", "")),
        "quorum_group_hash": sha256_text(str(node.get("quorum_group", ""))),
        "consensus_epoch_hash": sha256_text(str(node.get("consensus_epoch", ""))),
        "last_verified_at": str(node.get("last_verified_at", "")),
        "policy_hash": str(node.get("policy_hash", "")),
        "signature_status": str(node.get("signature_status", "")),
        "continuity_state": str(node.get("continuity_state", "")),
    }
    return sha256_text(canonical_json(bounded))


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _assert_safe(value: Any) -> None:
    text = canonical_json(value)
    if any(term.lower() in text.lower() for term in FORBIDDEN_DIAGNOSTIC_TERMS):
        raise VerifierContinuityError(VERIFIER_CONTINUITY_BLOCKED)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
