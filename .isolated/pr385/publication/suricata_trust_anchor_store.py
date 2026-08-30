"""Local Suricata production trust-anchor store.

This module validates offline trust-anchor records only. It does not store raw
public keys, fetch external authorities, or call network services.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from publication.models import hash_payload, is_sha256_ref


POLICY_VERSION = "USBAY-SURICATA-008"
FINALIZER_POLICY_VERSION = "USBAY-SURICATA-009"
APPROVED_STATUS = "approved"
REVOKED_STATUS = "revoked"


@dataclass(frozen=True)
class SuricataTrustAnchorRecord:
    anchor_id: str
    issuer: str
    public_key_fingerprint: str
    status: str
    approved_by_human: bool
    policy_version: str
    created_at: str
    evidence_hash: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SuricataTrustAnchorRecord":
        return cls(
            anchor_id=str(payload.get("anchor_id") or ""),
            issuer=str(payload.get("issuer") or ""),
            public_key_fingerprint=str(payload.get("public_key_fingerprint") or ""),
            status=str(payload.get("status") or ""),
            approved_by_human=payload.get("approved_by_human") is True,
            policy_version=str(payload.get("policy_version") or ""),
            created_at=str(payload.get("created_at") or ""),
            evidence_hash=str(payload.get("evidence_hash") or ""),
        )

    def to_hash_payload(self) -> dict[str, Any]:
        return {
            "anchor_id": self.anchor_id,
            "issuer": self.issuer,
            "public_key_fingerprint": self.public_key_fingerprint,
            "status": self.status,
            "approved_by_human": self.approved_by_human,
            "policy_version": self.policy_version,
            "created_at": self.created_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.to_hash_payload(),
            "evidence_hash": self.evidence_hash,
        }


@dataclass(frozen=True)
class SuricataTrustAnchorResult:
    approved: bool
    anchor_id: str
    issuer: str
    public_key_fingerprint: str
    policy_version: str
    evidence_hash: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "anchor_id": self.anchor_id,
            "issuer": self.issuer,
            "public_key_fingerprint": self.public_key_fingerprint,
            "policy_version": self.policy_version,
            "evidence_hash": self.evidence_hash,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class SuricataTrustAnchorFinalizerResult:
    approved: bool
    trust_anchor_id: str
    policy_version: str
    fingerprint_hash: str
    approval_hash: str
    trust_anchor_evidence_hash: str
    finalizer_decision: str
    finalizer_reason: str
    evidence_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "trust_anchor_id": self.trust_anchor_id,
            "policy_version": self.policy_version,
            "fingerprint_hash": self.fingerprint_hash,
            "approval_hash": self.approval_hash,
            "trust_anchor_evidence_hash": self.trust_anchor_evidence_hash,
            "finalizer_decision": self.finalizer_decision,
            "finalizer_reason": self.finalizer_reason,
            "evidence_hash": self.evidence_hash,
        }


class SuricataTrustAnchorStore:
    def __init__(self, records: list[dict[str, Any] | SuricataTrustAnchorRecord] | tuple[dict[str, Any] | SuricataTrustAnchorRecord, ...]):
        self.records = tuple(record if isinstance(record, SuricataTrustAnchorRecord) else SuricataTrustAnchorRecord.from_dict(record) for record in records)

    @property
    def store_hash(self) -> str:
        return hash_payload({"suricata_trust_anchor_store": tuple(record.to_dict() for record in self.records)})

    def validate_anchor(
        self,
        *,
        anchor_id: str,
        expected_fingerprint: str,
        policy_version: str,
    ) -> SuricataTrustAnchorResult:
        if not self.records:
            return self._blocked("SURICATA_TRUST_ANCHOR_MISSING", anchor_id, "", "", policy_version)

        matches = tuple(record for record in self.records if record.anchor_id == anchor_id)
        if not matches:
            return self._blocked("SURICATA_TRUST_ANCHOR_MISSING", anchor_id, "", "", policy_version)
        if len(matches) > 1:
            return self._blocked("SURICATA_TRUST_ANCHOR_MALFORMED", anchor_id, "", "", policy_version)

        record = matches[0]
        malformed_reason = _malformed_reason(record)
        if malformed_reason:
            return self._blocked(malformed_reason, record.anchor_id, record.issuer, record.public_key_fingerprint, record.policy_version)
        if record.status == REVOKED_STATUS:
            return self._blocked("SURICATA_TRUST_ANCHOR_REVOKED", record.anchor_id, record.issuer, record.public_key_fingerprint, record.policy_version)
        if not record.approved_by_human:
            return self._blocked("SURICATA_TRUST_ANCHOR_HUMAN_APPROVAL_MISSING", record.anchor_id, record.issuer, record.public_key_fingerprint, record.policy_version)
        if record.public_key_fingerprint != expected_fingerprint:
            return self._blocked("SURICATA_TRUST_ANCHOR_FINGERPRINT_MISMATCH", record.anchor_id, record.issuer, record.public_key_fingerprint, record.policy_version)
        if record.policy_version != policy_version:
            return self._blocked("SURICATA_TRUST_ANCHOR_POLICY_MISMATCH", record.anchor_id, record.issuer, record.public_key_fingerprint, record.policy_version)

        payload = _result_payload(
            approved=True,
            anchor_id=record.anchor_id,
            issuer=record.issuer,
            public_key_fingerprint=record.public_key_fingerprint,
            policy_version=record.policy_version,
            store_hash=self.store_hash,
            record_evidence_hash=record.evidence_hash,
            reason="SURICATA_TRUST_ANCHOR_APPROVED",
        )
        return SuricataTrustAnchorResult(
            approved=True,
            anchor_id=record.anchor_id,
            issuer=record.issuer,
            public_key_fingerprint=record.public_key_fingerprint,
            policy_version=record.policy_version,
            evidence_hash=hash_payload(payload),
            reason="SURICATA_TRUST_ANCHOR_APPROVED",
        )

    def _blocked(self, reason: str, anchor_id: str, issuer: str, fingerprint: str, policy_version: str) -> SuricataTrustAnchorResult:
        payload = _result_payload(
            approved=False,
            anchor_id=anchor_id,
            issuer=issuer,
            public_key_fingerprint=fingerprint,
            policy_version=policy_version,
            store_hash=self.store_hash,
            record_evidence_hash="",
            reason=reason,
        )
        return SuricataTrustAnchorResult(
            approved=False,
            anchor_id=anchor_id,
            issuer=issuer,
            public_key_fingerprint=fingerprint,
            policy_version=policy_version,
            evidence_hash=hash_payload(payload),
            reason=reason,
        )


def finalize_suricata_trust_anchor(
    trust_anchor_result: SuricataTrustAnchorResult | None,
) -> SuricataTrustAnchorFinalizerResult:
    if trust_anchor_result is None:
        return _finalizer_blocked("SURICATA_TRUST_ANCHOR_FINALIZER_MISSING", "", "", "", "")
    if not is_sha256_ref(trust_anchor_result.evidence_hash):
        return _finalizer_blocked(
            "SURICATA_TRUST_ANCHOR_FINALIZER_EVIDENCE_MISSING",
            trust_anchor_result.anchor_id,
            trust_anchor_result.policy_version,
            "",
            trust_anchor_result.evidence_hash,
        )
    if not trust_anchor_result.approved:
        return _finalizer_blocked(
            trust_anchor_result.reason,
            trust_anchor_result.anchor_id,
            trust_anchor_result.policy_version,
            "",
            trust_anchor_result.evidence_hash,
        )
    if not is_sha256_ref(trust_anchor_result.public_key_fingerprint):
        return _finalizer_blocked(
            "SURICATA_TRUST_ANCHOR_FINALIZER_FINGERPRINT_MALFORMED",
            trust_anchor_result.anchor_id,
            trust_anchor_result.policy_version,
            "",
            trust_anchor_result.evidence_hash,
        )

    fingerprint_hash = hash_payload({"public_key_fingerprint": trust_anchor_result.public_key_fingerprint})
    approval_hash = hash_payload(
        {
            "trust_anchor_id": trust_anchor_result.anchor_id,
            "policy_version": trust_anchor_result.policy_version,
            "trust_anchor_evidence_hash": trust_anchor_result.evidence_hash,
            "human_approval_required": True,
        }
    )
    payload = _finalizer_payload(
        approved=True,
        trust_anchor_id=trust_anchor_result.anchor_id,
        policy_version=trust_anchor_result.policy_version,
        fingerprint_hash=fingerprint_hash,
        approval_hash=approval_hash,
        trust_anchor_evidence_hash=trust_anchor_result.evidence_hash,
        finalizer_decision="ALLOW",
        finalizer_reason="SURICATA_TRUST_ANCHOR_FINALIZER_APPROVED",
    )
    return SuricataTrustAnchorFinalizerResult(
        approved=True,
        trust_anchor_id=trust_anchor_result.anchor_id,
        policy_version=trust_anchor_result.policy_version,
        fingerprint_hash=fingerprint_hash,
        approval_hash=approval_hash,
        trust_anchor_evidence_hash=trust_anchor_result.evidence_hash,
        finalizer_decision="ALLOW",
        finalizer_reason="SURICATA_TRUST_ANCHOR_FINALIZER_APPROVED",
        evidence_hash=hash_payload(payload),
    )


def suricata_trust_anchor_record_hash(
    *,
    anchor_id: str,
    issuer: str,
    public_key_fingerprint: str,
    status: str,
    approved_by_human: bool,
    policy_version: str,
    created_at: str,
) -> str:
    return hash_payload(
        {
            "anchor_id": anchor_id,
            "issuer": issuer,
            "public_key_fingerprint": public_key_fingerprint,
            "status": status,
            "approved_by_human": approved_by_human,
            "policy_version": policy_version,
            "created_at": created_at,
        }
    )


def _malformed_reason(record: SuricataTrustAnchorRecord) -> str:
    if not record.anchor_id or not record.issuer or not record.policy_version or not record.created_at:
        return "SURICATA_TRUST_ANCHOR_MALFORMED"
    if record.status not in {APPROVED_STATUS, REVOKED_STATUS}:
        return "SURICATA_TRUST_ANCHOR_MALFORMED"
    if not is_sha256_ref(record.public_key_fingerprint):
        return "SURICATA_TRUST_ANCHOR_MALFORMED"
    if not record.evidence_hash:
        return "SURICATA_TRUST_ANCHOR_EVIDENCE_MISSING"
    if not is_sha256_ref(record.evidence_hash):
        return "SURICATA_TRUST_ANCHOR_EVIDENCE_MISSING"
    if record.evidence_hash != suricata_trust_anchor_record_hash(**record.to_hash_payload()):
        return "SURICATA_TRUST_ANCHOR_EVIDENCE_MISMATCH"
    if _parse_timestamp(record.created_at) is None:
        return "SURICATA_TRUST_ANCHOR_MALFORMED"
    return ""


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _result_payload(
    *,
    approved: bool,
    anchor_id: str,
    issuer: str,
    public_key_fingerprint: str,
    policy_version: str,
    store_hash: str,
    record_evidence_hash: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "approved": approved,
        "anchor_id": anchor_id,
        "issuer": issuer,
        "public_key_fingerprint": public_key_fingerprint,
        "policy_version": policy_version,
        "store_hash": store_hash,
        "record_evidence_hash": record_evidence_hash,
        "reason": reason,
    }


def _finalizer_blocked(
    reason: str,
    trust_anchor_id: str,
    policy_version: str,
    fingerprint_hash: str,
    trust_anchor_evidence_hash: str,
) -> SuricataTrustAnchorFinalizerResult:
    approval_hash = hash_payload(
        {
            "trust_anchor_id": trust_anchor_id,
            "policy_version": policy_version,
            "trust_anchor_evidence_hash": trust_anchor_evidence_hash,
            "human_approval_required": True,
            "approved": False,
        }
    )
    payload = _finalizer_payload(
        approved=False,
        trust_anchor_id=trust_anchor_id,
        policy_version=policy_version,
        fingerprint_hash=fingerprint_hash,
        approval_hash=approval_hash,
        trust_anchor_evidence_hash=trust_anchor_evidence_hash,
        finalizer_decision="BLOCK",
        finalizer_reason=reason,
    )
    return SuricataTrustAnchorFinalizerResult(
        approved=False,
        trust_anchor_id=trust_anchor_id,
        policy_version=policy_version,
        fingerprint_hash=fingerprint_hash,
        approval_hash=approval_hash,
        trust_anchor_evidence_hash=trust_anchor_evidence_hash,
        finalizer_decision="BLOCK",
        finalizer_reason=reason,
        evidence_hash=hash_payload(payload),
    )


def _finalizer_payload(
    *,
    approved: bool,
    trust_anchor_id: str,
    policy_version: str,
    fingerprint_hash: str,
    approval_hash: str,
    trust_anchor_evidence_hash: str,
    finalizer_decision: str,
    finalizer_reason: str,
) -> dict[str, Any]:
    return {
        "approved": approved,
        "trust_anchor_id": trust_anchor_id,
        "policy_version": policy_version,
        "fingerprint_hash": fingerprint_hash,
        "approval_hash": approval_hash,
        "trust_anchor_evidence_hash": trust_anchor_evidence_hash,
        "finalizer_decision": finalizer_decision,
        "finalizer_reason": finalizer_reason,
        "finalizer_policy_version": FINALIZER_POLICY_VERSION,
    }
