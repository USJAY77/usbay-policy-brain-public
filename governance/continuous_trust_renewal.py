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


SCHEMA_VERSION = "usbay.continuous_trust_renewal.v1"

TRUST_RENEWAL_NOT_STARTED = "TRUST_RENEWAL_NOT_STARTED"
TRUST_RENEWAL_PENDING = "TRUST_RENEWAL_PENDING"
TRUST_RENEWAL_ACTIVE = "TRUST_RENEWAL_ACTIVE"
TRUST_RENEWAL_EXPIRED = "TRUST_RENEWAL_EXPIRED"
TRUST_RENEWAL_FAILED = "TRUST_RENEWAL_FAILED"
TRUST_RENEWAL_REVOKED = "TRUST_RENEWAL_REVOKED"
TRUST_RENEWAL_REPLAY_BLOCKED = "TRUST_RENEWAL_REPLAY_BLOCKED"

TRUST_RENEWAL_MISSING = "TRUST_RENEWAL_MISSING"
TRUST_RENEWAL_PACKET_MALFORMED = "TRUST_RENEWAL_PACKET_MALFORMED"
TRUST_RENEWAL_POLICY_MISMATCH = "TRUST_RENEWAL_POLICY_MISMATCH"
TRUST_RENEWAL_DEVICE_MISMATCH = "TRUST_RENEWAL_DEVICE_MISMATCH"
TRUST_RENEWAL_SIGNATURE_INVALID = "TRUST_RENEWAL_SIGNATURE_INVALID"
TRUST_RENEWAL_PUBLIC_KEY_UNTRUSTED = "TRUST_RENEWAL_PUBLIC_KEY_UNTRUSTED"
TRUST_RENEWAL_CHALLENGE_CHAIN_STALE = "TRUST_RENEWAL_CHALLENGE_CHAIN_STALE"
TRUST_RENEWAL_BLOCKED = "TRUST_RENEWAL_BLOCKED"

ALLOWED_STATES = {
    TRUST_RENEWAL_NOT_STARTED,
    TRUST_RENEWAL_PENDING,
    TRUST_RENEWAL_ACTIVE,
    TRUST_RENEWAL_EXPIRED,
    TRUST_RENEWAL_FAILED,
    TRUST_RENEWAL_REVOKED,
    TRUST_RENEWAL_REPLAY_BLOCKED,
}

REQUIRED_PACKET_FIELDS = (
    "renewal_id",
    "previous_challenge_hash",
    "new_challenge_id",
    "nonce_hash",
    "device_identity_fingerprint",
    "policy_hash",
    "issued_at",
    "expires_at",
    "renewal_window_seconds",
    "signature_status",
    "renewal_state",
    "signature",
)

FORBIDDEN_PACKET_FIELDS = ("device_id", "raw_device_id", "device_identifier", "nonce")
FORBIDDEN_DIAGNOSTIC_TERMS = (
    "PRIVATE " + "KEY",
    "approval_" + "contents",
    "raw_" + "payload",
    "secret",
    "token",
)


class ContinuousTrustRenewalError(RuntimeError):
    pass


@dataclass(frozen=True)
class TrustRenewalResult:
    verified: bool
    renewal_state: str
    reason_code: str
    reason_codes: tuple[str, ...]
    audit_evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "verified": self.verified,
            "renewal_state": self.renewal_state,
            "reason_code": self.reason_code,
            "reason_codes": list(self.reason_codes),
            "audit_evidence": self.audit_evidence,
        }


def signed_renewal_payload(packet: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(packet)
    payload.pop("signature", None)
    payload.pop("verification", None)
    payload.pop("audit_evidence", None)
    return payload


def signable_renewal_message(packet: Mapping[str, Any]) -> bytes:
    return canonical_json(signed_renewal_payload(packet)).encode("utf-8")


def missing_renewal_result(*, policy_hash: str, timestamp_utc: str | None = None) -> TrustRenewalResult:
    timestamp = timestamp_utc or _utc_now()
    evidence = _audit_evidence(
        renewal_state=TRUST_RENEWAL_NOT_STARTED,
        reason_code=TRUST_RENEWAL_MISSING,
        renewal_id="",
        previous_challenge_hash="",
        new_challenge_id="",
        nonce_hash="",
        policy_hash=policy_hash,
        timestamp_utc=timestamp,
    )
    return TrustRenewalResult(
        verified=False,
        renewal_state=TRUST_RENEWAL_NOT_STARTED,
        reason_code=TRUST_RENEWAL_MISSING,
        reason_codes=(TRUST_RENEWAL_MISSING, TRUST_RENEWAL_BLOCKED),
        audit_evidence=evidence,
    )


def validate_trust_renewal(
    packet: Mapping[str, Any] | None,
    *,
    trusted_public_keys: Mapping[str, str],
    expected_device_identity_fingerprint: str,
    expected_policy_hash: str,
    expected_previous_challenge_hash: str,
    used_nonce_hashes: set[str] | frozenset[str] | tuple[str, ...] = (),
    revoked_device_fingerprints: set[str] | frozenset[str] | tuple[str, ...] = (),
    now_utc: str | None = None,
) -> TrustRenewalResult:
    timestamp = now_utc or _utc_now()
    if not packet:
        return missing_renewal_result(policy_hash=expected_policy_hash, timestamp_utc=timestamp)

    reason_codes: list[str] = []
    state = str(packet.get("renewal_state", TRUST_RENEWAL_FAILED))
    renewal_id = str(packet.get("renewal_id", ""))
    previous_challenge_hash = str(packet.get("previous_challenge_hash", ""))
    new_challenge_id = str(packet.get("new_challenge_id", ""))
    nonce_hash = str(packet.get("nonce_hash", ""))
    device_fingerprint = str(packet.get("device_identity_fingerprint", ""))
    policy_hash = str(packet.get("policy_hash", ""))

    if not _packet_shape_valid(packet):
        reason_codes.append(TRUST_RENEWAL_PACKET_MALFORMED)
        state = TRUST_RENEWAL_FAILED
    if state not in ALLOWED_STATES:
        reason_codes.append(TRUST_RENEWAL_PACKET_MALFORMED)
        state = TRUST_RENEWAL_FAILED
    if not _is_current(
        str(packet.get("issued_at", "")),
        str(packet.get("expires_at", "")),
        str(packet.get("renewal_window_seconds", "")),
        timestamp,
    ):
        reason_codes.append(TRUST_RENEWAL_EXPIRED)
        state = TRUST_RENEWAL_EXPIRED
    if nonce_hash in set(used_nonce_hashes):
        reason_codes.append(TRUST_RENEWAL_REPLAY_BLOCKED)
        state = TRUST_RENEWAL_REPLAY_BLOCKED
    if device_fingerprint in set(revoked_device_fingerprints):
        reason_codes.append(TRUST_RENEWAL_REVOKED)
        state = TRUST_RENEWAL_REVOKED
    if device_fingerprint != expected_device_identity_fingerprint:
        reason_codes.append(TRUST_RENEWAL_DEVICE_MISMATCH)
    if policy_hash != expected_policy_hash:
        reason_codes.append(TRUST_RENEWAL_POLICY_MISMATCH)
    if previous_challenge_hash != expected_previous_challenge_hash:
        reason_codes.append(TRUST_RENEWAL_CHALLENGE_CHAIN_STALE)

    public_key_pem = trusted_public_keys.get(device_fingerprint)
    if not public_key_pem:
        reason_codes.append(TRUST_RENEWAL_PUBLIC_KEY_UNTRUSTED)
    elif packet.get("signature_status") != "SIGNED":
        reason_codes.append(TRUST_RENEWAL_SIGNATURE_INVALID)
        state = TRUST_RENEWAL_FAILED
    elif not _verify_signature(packet, public_key_pem):
        reason_codes.append(TRUST_RENEWAL_SIGNATURE_INVALID)
        state = TRUST_RENEWAL_FAILED

    verified = not reason_codes and state == TRUST_RENEWAL_ACTIVE
    if verified:
        reason_codes.append(TRUST_RENEWAL_ACTIVE)
    else:
        reason_codes.append(TRUST_RENEWAL_BLOCKED)

    ordered_reasons = tuple(dict.fromkeys(reason_codes))
    reason_code = ordered_reasons[0] if ordered_reasons else TRUST_RENEWAL_BLOCKED
    evidence = _audit_evidence(
        renewal_state=state,
        reason_code=reason_code,
        renewal_id=renewal_id,
        previous_challenge_hash=previous_challenge_hash,
        new_challenge_id=new_challenge_id,
        nonce_hash=nonce_hash,
        policy_hash=expected_policy_hash,
        timestamp_utc=timestamp,
    )
    return TrustRenewalResult(
        verified=verified,
        renewal_state=state,
        reason_code=reason_code,
        reason_codes=ordered_reasons,
        audit_evidence=evidence,
    )


def _packet_shape_valid(packet: Mapping[str, Any]) -> bool:
    if any(field in packet for field in FORBIDDEN_PACKET_FIELDS):
        return False
    if any(field not in packet for field in REQUIRED_PACKET_FIELDS):
        return False
    if any(not isinstance(packet.get(field), str) or not str(packet.get(field)).strip() for field in REQUIRED_PACKET_FIELDS):
        return False
    for field in ("previous_challenge_hash", "nonce_hash", "device_identity_fingerprint", "policy_hash"):
        if not _is_sha256_fingerprint(str(packet.get(field, ""))):
            return False
    try:
        return int(str(packet.get("renewal_window_seconds", ""))) > 0
    except ValueError:
        return False


def _is_sha256_fingerprint(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _is_current(issued_at: str, expires_at: str, renewal_window_seconds: str, now_utc: str) -> bool:
    try:
        issued = _parse_utc(issued_at)
        expires = _parse_utc(expires_at)
        now = _parse_utc(now_utc)
        window_seconds = int(renewal_window_seconds)
    except (ContinuousTrustRenewalError, ValueError):
        return False
    if window_seconds <= 0:
        return False
    if (expires - issued).total_seconds() > window_seconds:
        return False
    return issued <= now < expires


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise ContinuousTrustRenewalError(TRUST_RENEWAL_PACKET_MALFORMED) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_public_key(public_key_pem: str) -> Ed25519PublicKey:
    try:
        normalized = public_key_pem.strip().replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r\n", "\n").replace("\r", "\n")
        key = serialization.load_pem_public_key(normalized.encode("utf-8"))
    except Exception as exc:
        raise ContinuousTrustRenewalError(TRUST_RENEWAL_SIGNATURE_INVALID) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ContinuousTrustRenewalError(TRUST_RENEWAL_SIGNATURE_INVALID)
    return key


def _verify_signature(packet: Mapping[str, Any], public_key_pem: str) -> bool:
    try:
        public_key_fingerprint(public_key_pem)
        signature = base64.b64decode(str(packet.get("signature", "")).encode("ascii"), validate=True)
        _load_public_key(public_key_pem).verify(signature, signable_renewal_message(packet))
        return True
    except (InvalidSignature, ValueError, TypeError, ContinuousTrustRenewalError):
        return False


def _audit_evidence(
    *,
    renewal_state: str,
    reason_code: str,
    renewal_id: str,
    previous_challenge_hash: str,
    new_challenge_id: str,
    nonce_hash: str,
    policy_hash: str,
    timestamp_utc: str,
) -> dict[str, Any]:
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "renewal_state": renewal_state,
        "reason_code": reason_code,
        "renewal_id_hash": sha256_text(renewal_id),
        "previous_challenge_hash": previous_challenge_hash,
        "new_challenge_hash": sha256_text(new_challenge_id),
        "nonce_hash": nonce_hash,
        "policy_hash": policy_hash,
        "timestamp": timestamp_utc,
    }
    evidence["renewal_audit_hash"] = sha256_text(canonical_json(evidence))
    _assert_safe(evidence)
    return evidence


def _assert_safe(value: Any) -> None:
    text = canonical_json(value)
    if any(term.lower() in text.lower() for term in FORBIDDEN_DIAGNOSTIC_TERMS):
        raise ContinuousTrustRenewalError(TRUST_RENEWAL_PACKET_MALFORMED)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
