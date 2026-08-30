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


SCHEMA_VERSION = "usbay.remote_challenge_response.v1"

CHALLENGE_NOT_ISSUED = "CHALLENGE_NOT_ISSUED"
CHALLENGE_ISSUED = "CHALLENGE_ISSUED"
CHALLENGE_RESPONSE_VALID = "CHALLENGE_RESPONSE_VALID"
CHALLENGE_RESPONSE_INVALID = "CHALLENGE_RESPONSE_INVALID"
CHALLENGE_EXPIRED = "CHALLENGE_EXPIRED"
CHALLENGE_REPLAY_DETECTED = "CHALLENGE_REPLAY_DETECTED"

CHALLENGE_MISSING = "CHALLENGE_MISSING"
CHALLENGE_PACKET_MALFORMED = "CHALLENGE_PACKET_MALFORMED"
CHALLENGE_DEVICE_MISMATCH = "CHALLENGE_DEVICE_MISMATCH"
CHALLENGE_POLICY_MISMATCH = "CHALLENGE_POLICY_MISMATCH"
CHALLENGE_SIGNATURE_INVALID = "CHALLENGE_SIGNATURE_INVALID"
CHALLENGE_PUBLIC_KEY_UNTRUSTED = "CHALLENGE_PUBLIC_KEY_UNTRUSTED"
CHALLENGE_BLOCKED = "CHALLENGE_BLOCKED"

ALLOWED_STATES = {
    CHALLENGE_NOT_ISSUED,
    CHALLENGE_ISSUED,
    CHALLENGE_RESPONSE_VALID,
    CHALLENGE_RESPONSE_INVALID,
    CHALLENGE_EXPIRED,
    CHALLENGE_REPLAY_DETECTED,
}

REQUIRED_PACKET_FIELDS = (
    "challenge_id",
    "nonce",
    "issued_at",
    "expires_at",
    "device_identity_fingerprint",
    "policy_hash",
    "response_signature_status",
    "challenge_state",
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


class RemoteChallengeResponseError(RuntimeError):
    pass


@dataclass(frozen=True)
class ChallengeResponseResult:
    verified: bool
    challenge_state: str
    reason_code: str
    reason_codes: tuple[str, ...]
    audit_evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "verified": self.verified,
            "challenge_state": self.challenge_state,
            "reason_code": self.reason_code,
            "reason_codes": list(self.reason_codes),
            "audit_evidence": self.audit_evidence,
        }


def signed_challenge_payload(packet: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(packet)
    payload.pop("signature", None)
    payload.pop("verification", None)
    payload.pop("audit_evidence", None)
    return payload


def signable_challenge_message(packet: Mapping[str, Any]) -> bytes:
    return canonical_json(signed_challenge_payload(packet)).encode("utf-8")


def missing_challenge_result(*, policy_hash: str, timestamp_utc: str | None = None) -> ChallengeResponseResult:
    timestamp = timestamp_utc or _utc_now()
    evidence = _audit_evidence(
        challenge_state=CHALLENGE_NOT_ISSUED,
        reason_code=CHALLENGE_MISSING,
        challenge_id="",
        nonce="",
        device_identity_fingerprint="",
        policy_hash=policy_hash,
        timestamp_utc=timestamp,
    )
    return ChallengeResponseResult(
        verified=False,
        challenge_state=CHALLENGE_NOT_ISSUED,
        reason_code=CHALLENGE_MISSING,
        reason_codes=(CHALLENGE_MISSING, CHALLENGE_BLOCKED),
        audit_evidence=evidence,
    )


def validate_challenge_response(
    packet: Mapping[str, Any] | None,
    *,
    trusted_public_keys: Mapping[str, str],
    expected_device_identity_fingerprint: str,
    expected_policy_hash: str,
    issued_challenges: set[str] | frozenset[str] | tuple[str, ...] = (),
    used_nonces: set[str] | frozenset[str] | tuple[str, ...] = (),
    now_utc: str | None = None,
) -> ChallengeResponseResult:
    timestamp = now_utc or _utc_now()
    if not packet:
        return missing_challenge_result(policy_hash=expected_policy_hash, timestamp_utc=timestamp)

    reason_codes: list[str] = []
    state = str(packet.get("challenge_state", CHALLENGE_RESPONSE_INVALID))
    challenge_id = str(packet.get("challenge_id", ""))
    nonce = str(packet.get("nonce", ""))
    device_fingerprint = str(packet.get("device_identity_fingerprint", ""))
    policy_hash = str(packet.get("policy_hash", ""))

    if not _packet_shape_valid(packet):
        reason_codes.append(CHALLENGE_PACKET_MALFORMED)
        state = CHALLENGE_RESPONSE_INVALID
    if state not in ALLOWED_STATES:
        reason_codes.append(CHALLENGE_PACKET_MALFORMED)
        state = CHALLENGE_RESPONSE_INVALID
    if challenge_id not in set(issued_challenges):
        reason_codes.append(CHALLENGE_MISSING)
        if state == CHALLENGE_ISSUED:
            state = CHALLENGE_NOT_ISSUED
    if nonce in set(used_nonces):
        reason_codes.append(CHALLENGE_REPLAY_DETECTED)
        state = CHALLENGE_REPLAY_DETECTED
    if device_fingerprint != expected_device_identity_fingerprint:
        reason_codes.append(CHALLENGE_DEVICE_MISMATCH)
    if policy_hash != expected_policy_hash:
        reason_codes.append(CHALLENGE_POLICY_MISMATCH)
    if not _is_current(str(packet.get("issued_at", "")), str(packet.get("expires_at", "")), timestamp):
        reason_codes.append(CHALLENGE_EXPIRED)
        state = CHALLENGE_EXPIRED

    public_key_pem = trusted_public_keys.get(device_fingerprint)
    if not public_key_pem:
        reason_codes.append(CHALLENGE_PUBLIC_KEY_UNTRUSTED)
    elif packet.get("response_signature_status") != "SIGNED":
        reason_codes.append(CHALLENGE_SIGNATURE_INVALID)
        state = CHALLENGE_RESPONSE_INVALID
    elif not _verify_signature(packet, public_key_pem):
        reason_codes.append(CHALLENGE_SIGNATURE_INVALID)
        state = CHALLENGE_RESPONSE_INVALID

    verified = not reason_codes and state == CHALLENGE_RESPONSE_VALID
    if verified:
        reason_codes.append(CHALLENGE_RESPONSE_VALID)
    else:
        reason_codes.append(CHALLENGE_BLOCKED)

    ordered_reasons = tuple(dict.fromkeys(reason_codes))
    reason_code = ordered_reasons[0] if ordered_reasons else CHALLENGE_BLOCKED
    evidence = _audit_evidence(
        challenge_state=state,
        reason_code=reason_code,
        challenge_id=challenge_id,
        nonce=nonce,
        device_identity_fingerprint=device_fingerprint,
        policy_hash=expected_policy_hash,
        timestamp_utc=timestamp,
    )
    return ChallengeResponseResult(
        verified=verified,
        challenge_state=state,
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
    if not _is_sha256_fingerprint(str(packet.get("device_identity_fingerprint", ""))):
        return False
    if not _is_sha256_fingerprint(str(packet.get("policy_hash", ""))):
        return False
    return True


def _is_sha256_fingerprint(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _is_current(issued_at: str, expires_at: str, now_utc: str) -> bool:
    try:
        issued = _parse_utc(issued_at)
        expires = _parse_utc(expires_at)
        now = _parse_utc(now_utc)
    except RemoteChallengeResponseError:
        return False
    return issued <= now < expires


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise RemoteChallengeResponseError(CHALLENGE_PACKET_MALFORMED) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_public_key(public_key_pem: str) -> Ed25519PublicKey:
    try:
        normalized = public_key_pem.strip().replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r\n", "\n").replace("\r", "\n")
        key = serialization.load_pem_public_key(normalized.encode("utf-8"))
    except Exception as exc:
        raise RemoteChallengeResponseError(CHALLENGE_SIGNATURE_INVALID) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise RemoteChallengeResponseError(CHALLENGE_SIGNATURE_INVALID)
    return key


def _verify_signature(packet: Mapping[str, Any], public_key_pem: str) -> bool:
    try:
        public_key_fingerprint(public_key_pem)
        signature = base64.b64decode(str(packet.get("signature", "")).encode("ascii"), validate=True)
        _load_public_key(public_key_pem).verify(signature, signable_challenge_message(packet))
        return True
    except (InvalidSignature, ValueError, TypeError, RemoteChallengeResponseError):
        return False


def _audit_evidence(
    *,
    challenge_state: str,
    reason_code: str,
    challenge_id: str,
    nonce: str,
    device_identity_fingerprint: str,
    policy_hash: str,
    timestamp_utc: str,
) -> dict[str, Any]:
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "challenge_state": challenge_state,
        "reason_code": reason_code,
        "challenge_id_hash": sha256_text(challenge_id),
        "nonce_hash": sha256_text(nonce),
        "device_identity_fingerprint": device_identity_fingerprint,
        "policy_hash": policy_hash,
        "timestamp": timestamp_utc,
    }
    evidence["challenge_audit_hash"] = sha256_text(canonical_json(evidence))
    _assert_safe(evidence)
    return evidence


def _assert_safe(value: Any) -> None:
    text = canonical_json(value)
    if any(term.lower() in text.lower() for term in FORBIDDEN_DIAGNOSTIC_TERMS):
        raise RemoteChallengeResponseError(CHALLENGE_PACKET_MALFORMED)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
