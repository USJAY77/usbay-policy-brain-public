from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from governance.deployment_runtime_health import canonical_json, sha256_text


SCHEMA_VERSION = "usbay.device_identity_lifecycle.v1"
SIGNATURE_ALGORITHM = "Ed25519"

IDENTITY_UNENROLLED = "IDENTITY_UNENROLLED"
IDENTITY_ENROLLMENT_PENDING = "IDENTITY_ENROLLMENT_PENDING"
IDENTITY_ENROLLED = "IDENTITY_ENROLLED"
IDENTITY_CHALLENGE_REQUIRED = "IDENTITY_CHALLENGE_REQUIRED"
IDENTITY_VERIFIED = "IDENTITY_VERIFIED"
IDENTITY_EXPIRED = "IDENTITY_EXPIRED"
IDENTITY_REVOKED = "IDENTITY_REVOKED"
IDENTITY_SIGNATURE_INVALID = "IDENTITY_SIGNATURE_INVALID"

IDENTITY_VALIDATION_PASSED = "IDENTITY_VALIDATION_PASSED"
IDENTITY_MISSING = "IDENTITY_MISSING"
IDENTITY_PACKET_MALFORMED = "IDENTITY_PACKET_MALFORMED"
IDENTITY_POLICY_MISMATCH = "IDENTITY_POLICY_MISMATCH"
IDENTITY_NONCE_STALE = "IDENTITY_NONCE_STALE"
IDENTITY_CHALLENGE_STALE = "IDENTITY_CHALLENGE_STALE"
IDENTITY_PUBLIC_KEY_UNTRUSTED = "IDENTITY_PUBLIC_KEY_UNTRUSTED"
IDENTITY_PUBLIC_KEY_MISMATCH = "IDENTITY_PUBLIC_KEY_MISMATCH"
IDENTITY_BLOCKED = "IDENTITY_BLOCKED"

ALLOWED_STATES = {
    IDENTITY_UNENROLLED,
    IDENTITY_ENROLLMENT_PENDING,
    IDENTITY_ENROLLED,
    IDENTITY_CHALLENGE_REQUIRED,
    IDENTITY_VERIFIED,
    IDENTITY_EXPIRED,
    IDENTITY_REVOKED,
    IDENTITY_SIGNATURE_INVALID,
}

REQUIRED_PACKET_FIELDS = (
    "device_id_fingerprint",
    "policy_version",
    "issued_at",
    "expires_at",
    "nonce",
    "challenge_id",
    "public_key_fingerprint",
    "signature_status",
    "identity_state",
    "signature",
)
FORBIDDEN_PACKET_FIELDS = ("device_id", "raw_device_id", "device_identifier")

FORBIDDEN_DIAGNOSTIC_TERMS = (
    "PRIVATE " + "KEY",
    "approval_" + "contents",
    "raw_" + "payload",
    "secret",
    "token",
)


class DeviceIdentityLifecycleError(RuntimeError):
    pass


@dataclass(frozen=True)
class IdentityLifecycleResult:
    verified: bool
    identity_state: str
    reason_code: str
    reason_codes: tuple[str, ...]
    audit_evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "verified": self.verified,
            "identity_state": self.identity_state,
            "reason_code": self.reason_code,
            "reason_codes": list(self.reason_codes),
            "audit_evidence": self.audit_evidence,
        }


def signed_identity_payload(packet: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(packet)
    payload.pop("signature", None)
    payload.pop("verification", None)
    payload.pop("audit_evidence", None)
    return payload


def signable_identity_message(packet: Mapping[str, Any]) -> bytes:
    return canonical_json(signed_identity_payload(packet)).encode("utf-8")


def public_key_fingerprint(public_key_pem: str) -> str:
    public_key = _load_public_key(public_key_pem)
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def missing_identity_result(
    *,
    expected_policy_hash: str,
    timestamp_utc: str | None = None,
) -> IdentityLifecycleResult:
    timestamp = timestamp_utc or _utc_now()
    evidence = _audit_evidence(
        identity_state=IDENTITY_UNENROLLED,
        reason_code=IDENTITY_MISSING,
        policy_hash=expected_policy_hash,
        public_key_fingerprint="",
        challenge_id="",
        nonce="",
        timestamp_utc=timestamp,
        device_id_fingerprint="",
    )
    return IdentityLifecycleResult(
        verified=False,
        identity_state=IDENTITY_UNENROLLED,
        reason_code=IDENTITY_MISSING,
        reason_codes=(IDENTITY_MISSING, IDENTITY_BLOCKED),
        audit_evidence=evidence,
    )


def validate_identity_packet(
    packet: Mapping[str, Any] | None,
    *,
    trusted_public_keys: Mapping[str, str],
    expected_policy_version: str,
    expected_policy_hash: str,
    active_challenges: set[str] | frozenset[str] | tuple[str, ...] = (),
    used_nonces: set[str] | frozenset[str] | tuple[str, ...] = (),
    revoked_device_fingerprints: set[str] | frozenset[str] | tuple[str, ...] = (),
    revoked_public_key_fingerprints: set[str] | frozenset[str] | tuple[str, ...] = (),
    now_utc: str | None = None,
) -> IdentityLifecycleResult:
    timestamp = now_utc or _utc_now()
    if not packet:
        return missing_identity_result(expected_policy_hash=expected_policy_hash, timestamp_utc=timestamp)

    reason_codes: list[str] = []
    state = str(packet.get("identity_state", IDENTITY_SIGNATURE_INVALID))
    device_fingerprint = str(packet.get("device_id_fingerprint", ""))
    key_fingerprint = str(packet.get("public_key_fingerprint", ""))
    nonce = str(packet.get("nonce", ""))
    challenge_id = str(packet.get("challenge_id", ""))

    if not _packet_shape_valid(packet):
        reason_codes.append(IDENTITY_PACKET_MALFORMED)
        state = IDENTITY_SIGNATURE_INVALID
    if state not in ALLOWED_STATES:
        reason_codes.append(IDENTITY_PACKET_MALFORMED)
        state = IDENTITY_SIGNATURE_INVALID
    if str(packet.get("policy_version", "")) != expected_policy_version:
        reason_codes.append(IDENTITY_POLICY_MISMATCH)
    if not _is_current(str(packet.get("issued_at", "")), str(packet.get("expires_at", "")), timestamp):
        reason_codes.append(IDENTITY_EXPIRED)
        state = IDENTITY_EXPIRED
    if device_fingerprint in set(revoked_device_fingerprints) or key_fingerprint in set(revoked_public_key_fingerprints):
        reason_codes.append(IDENTITY_REVOKED)
        state = IDENTITY_REVOKED
    if nonce in set(used_nonces):
        reason_codes.append(IDENTITY_NONCE_STALE)
    if challenge_id not in set(active_challenges):
        reason_codes.append(IDENTITY_CHALLENGE_STALE)
        if state == IDENTITY_ENROLLED:
            state = IDENTITY_CHALLENGE_REQUIRED

    public_key_pem = trusted_public_keys.get(key_fingerprint)
    if not public_key_pem:
        reason_codes.append(IDENTITY_PUBLIC_KEY_UNTRUSTED)
    else:
        try:
            trusted_fingerprint = public_key_fingerprint(public_key_pem)
        except DeviceIdentityLifecycleError:
            trusted_fingerprint = ""
        if trusted_fingerprint != key_fingerprint:
            reason_codes.append(IDENTITY_PUBLIC_KEY_MISMATCH)
        elif packet.get("signature_status") != "SIGNED":
            reason_codes.append(IDENTITY_SIGNATURE_INVALID)
            state = IDENTITY_SIGNATURE_INVALID
        elif not _verify_signature(packet, public_key_pem):
            reason_codes.append(IDENTITY_SIGNATURE_INVALID)
            state = IDENTITY_SIGNATURE_INVALID

    if state in {
        IDENTITY_UNENROLLED,
        IDENTITY_ENROLLMENT_PENDING,
        IDENTITY_ENROLLED,
        IDENTITY_CHALLENGE_REQUIRED,
    }:
        reason_codes.append(state)

    verified = not reason_codes and state == IDENTITY_VERIFIED
    if verified:
        reason_codes.append(IDENTITY_VALIDATION_PASSED)
    else:
        reason_codes.append(IDENTITY_BLOCKED)

    ordered_reasons = tuple(dict.fromkeys(reason_codes))
    reason_code = ordered_reasons[0] if ordered_reasons else IDENTITY_BLOCKED
    evidence = _audit_evidence(
        identity_state=state,
        reason_code=reason_code,
        policy_hash=expected_policy_hash,
        public_key_fingerprint=key_fingerprint,
        challenge_id=challenge_id,
        nonce=nonce,
        timestamp_utc=timestamp,
        device_id_fingerprint=device_fingerprint,
    )
    return IdentityLifecycleResult(
        verified=verified,
        identity_state=state,
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
    if not _is_sha256_fingerprint(str(packet.get("device_id_fingerprint", ""))):
        return False
    if not _is_sha256_fingerprint(str(packet.get("public_key_fingerprint", ""))):
        return False
    return True


def _is_sha256_fingerprint(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _is_current(issued_at: str, expires_at: str, now_utc: str) -> bool:
    try:
        issued = _parse_utc(issued_at)
        expires = _parse_utc(expires_at)
        now = _parse_utc(now_utc)
    except DeviceIdentityLifecycleError:
        return False
    return issued <= now < expires


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise DeviceIdentityLifecycleError(IDENTITY_PACKET_MALFORMED) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_public_key(public_key_pem: str) -> Ed25519PublicKey:
    try:
        normalized = public_key_pem.strip().replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r\n", "\n").replace("\r", "\n")
        key = serialization.load_pem_public_key(normalized.encode("utf-8"))
    except Exception as exc:
        raise DeviceIdentityLifecycleError(IDENTITY_SIGNATURE_INVALID) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise DeviceIdentityLifecycleError(IDENTITY_SIGNATURE_INVALID)
    return key


def _verify_signature(packet: Mapping[str, Any], public_key_pem: str) -> bool:
    try:
        signature = base64.b64decode(str(packet.get("signature", "")).encode("ascii"), validate=True)
        _load_public_key(public_key_pem).verify(signature, signable_identity_message(packet))
        return True
    except (InvalidSignature, ValueError, TypeError, DeviceIdentityLifecycleError):
        return False


def _audit_evidence(
    *,
    identity_state: str,
    reason_code: str,
    policy_hash: str,
    public_key_fingerprint: str,
    challenge_id: str,
    nonce: str,
    timestamp_utc: str,
    device_id_fingerprint: str,
) -> dict[str, Any]:
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "identity_state": identity_state,
        "reason_code": reason_code,
        "policy_hash": policy_hash,
        "public_key_fingerprint": public_key_fingerprint,
        "challenge_id_hash": sha256_text(challenge_id),
        "nonce_hash": sha256_text(nonce),
        "timestamp": timestamp_utc,
        "device_id_fingerprint": device_id_fingerprint,
    }
    evidence["identity_audit_hash"] = sha256_text(canonical_json(evidence))
    _assert_safe(evidence)
    return evidence


def _assert_safe(value: Any) -> None:
    text = canonical_json(value)
    if any(term.lower() in text.lower() for term in FORBIDDEN_DIAGNOSTIC_TERMS):
        raise DeviceIdentityLifecycleError(IDENTITY_PACKET_MALFORMED)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
