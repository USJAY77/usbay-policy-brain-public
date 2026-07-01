"""Offline Suricata external signing authority proof validation.

This module models external signing authority evidence only. It does not call
certificate authorities, KMS, HSM, or network services, and it never stores raw
public keys or certificate bodies.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from publication.models import hash_payload, is_sha256_ref


POLICY_VERSION = "USBAY-SURICATA-014"


@dataclass(frozen=True)
class SuricataExternalSigningAuthorityResult:
    approved: bool
    authority_id: str
    authority_fingerprint: str
    policy_version: str
    human_approved: bool
    issued_at: str
    expires_at: str
    evidence_hash: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "authority_id": self.authority_id,
            "authority_fingerprint": self.authority_fingerprint,
            "policy_version": self.policy_version,
            "human_approved": self.human_approved,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "evidence_hash": self.evidence_hash,
            "reason": self.reason,
        }


def suricata_signing_authority_hash(
    *,
    authority_id: str,
    authority_fingerprint: str,
    policy_version: str,
    approved: bool,
    human_approved: bool,
    issued_at: str,
    expires_at: str,
) -> str:
    return hash_payload(
        _authority_payload(
            authority_id=authority_id,
            authority_fingerprint=authority_fingerprint,
            policy_version=policy_version,
            approved=approved,
            human_approved=human_approved,
            issued_at=issued_at,
            expires_at=expires_at,
        )
    )


def validate_suricata_external_signing_authority(
    payload: dict[str, Any] | SuricataExternalSigningAuthorityResult | None,
    *,
    expected_fingerprint: str,
    policy_version: str,
    now: datetime | None = None,
) -> SuricataExternalSigningAuthorityResult:
    if payload is None:
        return _blocked("SURICATA_SIGNING_AUTHORITY_MISSING", "", "", policy_version, "", "")
    if isinstance(payload, SuricataExternalSigningAuthorityResult):
        if not payload.approved:
            return payload
        payload = payload.to_dict()
    if not isinstance(payload, dict):
        return _blocked("SURICATA_SIGNING_AUTHORITY_MALFORMED", "", "", policy_version, "", "")

    authority_id = str(payload.get("authority_id") or "")
    authority_fingerprint = str(payload.get("authority_fingerprint") or "")
    payload_policy_version = str(payload.get("policy_version") or "")
    approved = payload.get("approved") is True
    human_approved = payload.get("human_approved") is True
    issued_at = str(payload.get("issued_at") or "")
    expires_at = str(payload.get("expires_at") or "")
    evidence_hash = str(payload.get("evidence_hash") or "")

    if not authority_id or not issued_at or not expires_at:
        return _blocked("SURICATA_SIGNING_AUTHORITY_MALFORMED", authority_id, authority_fingerprint, payload_policy_version, issued_at, expires_at)
    if not is_sha256_ref(authority_fingerprint):
        return _blocked("SURICATA_SIGNING_AUTHORITY_MALFORMED", authority_id, authority_fingerprint, payload_policy_version, issued_at, expires_at)
    if not is_sha256_ref(evidence_hash):
        return _blocked("SURICATA_SIGNING_AUTHORITY_EVIDENCE_MISSING", authority_id, authority_fingerprint, payload_policy_version, issued_at, expires_at)
    if evidence_hash != suricata_signing_authority_hash(
        authority_id=authority_id,
        authority_fingerprint=authority_fingerprint,
        policy_version=payload_policy_version,
        approved=approved,
        human_approved=human_approved,
        issued_at=issued_at,
        expires_at=expires_at,
    ):
        return _blocked("SURICATA_SIGNING_AUTHORITY_HASH_MISMATCH", authority_id, authority_fingerprint, payload_policy_version, issued_at, expires_at)
    if not approved:
        return _blocked("SURICATA_SIGNING_AUTHORITY_REVOKED", authority_id, authority_fingerprint, payload_policy_version, issued_at, expires_at)
    if not human_approved:
        return _blocked("SURICATA_SIGNING_AUTHORITY_HUMAN_APPROVAL_MISSING", authority_id, authority_fingerprint, payload_policy_version, issued_at, expires_at)
    if authority_fingerprint != expected_fingerprint:
        return _blocked("SURICATA_SIGNING_AUTHORITY_FINGERPRINT_MISMATCH", authority_id, authority_fingerprint, payload_policy_version, issued_at, expires_at)
    if payload_policy_version != policy_version:
        return _blocked("SURICATA_SIGNING_AUTHORITY_POLICY_MISMATCH", authority_id, authority_fingerprint, payload_policy_version, issued_at, expires_at)

    now_value = now or datetime.now(timezone.utc)
    try:
        issued = _parse_time(issued_at)
        expires = _parse_time(expires_at)
    except ValueError:
        return _blocked("SURICATA_SIGNING_AUTHORITY_MALFORMED", authority_id, authority_fingerprint, payload_policy_version, issued_at, expires_at)
    if issued > now_value or expires <= now_value:
        return _blocked("SURICATA_SIGNING_AUTHORITY_EXPIRED", authority_id, authority_fingerprint, payload_policy_version, issued_at, expires_at)

    return SuricataExternalSigningAuthorityResult(
        approved=True,
        authority_id=authority_id,
        authority_fingerprint=authority_fingerprint,
        policy_version=payload_policy_version,
        human_approved=True,
        issued_at=issued_at,
        expires_at=expires_at,
        evidence_hash=evidence_hash,
        reason="SURICATA_SIGNING_AUTHORITY_APPROVED",
    )


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _blocked(
    reason: str,
    authority_id: str,
    authority_fingerprint: str,
    policy_version: str,
    issued_at: str,
    expires_at: str,
) -> SuricataExternalSigningAuthorityResult:
    payload = {
        **_authority_payload(
            authority_id=authority_id,
            authority_fingerprint=authority_fingerprint,
            policy_version=policy_version,
            approved=False,
            human_approved=False,
            issued_at=issued_at,
            expires_at=expires_at,
        ),
        "reason": reason,
        "validator_policy_version": POLICY_VERSION,
    }
    return SuricataExternalSigningAuthorityResult(
        approved=False,
        authority_id=authority_id,
        authority_fingerprint=authority_fingerprint,
        policy_version=policy_version or POLICY_VERSION,
        human_approved=False,
        issued_at=issued_at,
        expires_at=expires_at,
        evidence_hash=hash_payload(payload),
        reason=reason,
    )


def _authority_payload(
    *,
    authority_id: str,
    authority_fingerprint: str,
    policy_version: str,
    approved: bool,
    human_approved: bool,
    issued_at: str,
    expires_at: str,
) -> dict[str, Any]:
    return {
        "authority_id": authority_id,
        "authority_fingerprint": authority_fingerprint,
        "policy_version": policy_version,
        "approved": approved,
        "human_approved": human_approved,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "validator_policy_version": POLICY_VERSION,
    }
