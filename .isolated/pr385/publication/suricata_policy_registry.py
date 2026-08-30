"""Governed local Suricata policy registry validation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from publication.models import hash_payload, is_sha256_ref
from publication.suricata_policy_manifest import suricata_policy_evidence_hash, suricata_registry_hash


POLICY_VERSION = "USBAY-SURICATA-003"
MAX_APPROVAL_AGE_DAYS = 365


@dataclass(frozen=True)
class SuricataPolicyRegistryRecord:
    policy_id: str
    policy_version: str
    signature_hash: str
    evidence_hash: str
    rule_count: int
    created_at: str
    approved_by: str
    approval_timestamp: str
    active: bool
    revoked: bool

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SuricataPolicyRegistryRecord":
        return cls(
            policy_id=str(payload.get("policy_id") or ""),
            policy_version=str(payload.get("policy_version") or ""),
            signature_hash=str(payload.get("signature_hash") or ""),
            evidence_hash=str(payload.get("evidence_hash") or ""),
            rule_count=payload.get("rule_count") if isinstance(payload.get("rule_count"), int) else -1,
            created_at=str(payload.get("created_at") or ""),
            approved_by=str(payload.get("approved_by") or ""),
            approval_timestamp=str(payload.get("approval_timestamp") or ""),
            active=payload.get("active") is True,
            revoked=payload.get("revoked") is True,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "signature_hash": self.signature_hash,
            "evidence_hash": self.evidence_hash,
            "rule_count": self.rule_count,
            "created_at": self.created_at,
            "approved_by": self.approved_by,
            "approval_timestamp": self.approval_timestamp,
            "active": self.active,
            "revoked": self.revoked,
        }


@dataclass(frozen=True)
class SuricataPolicyRegistryResult:
    approved: bool
    policy_id: str
    policy_version: str
    registry_hash: str
    evidence_hash: str
    reason: str
    policy_registry_version: str = POLICY_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "registry_hash": self.registry_hash,
            "evidence_hash": self.evidence_hash,
            "reason": self.reason,
            "policy_registry_version": self.policy_registry_version,
        }


class SuricataPolicyRegistry:
    def __init__(self, records: tuple[SuricataPolicyRegistryRecord, ...] | list[SuricataPolicyRegistryRecord | dict[str, Any]]):
        self.records = tuple(record if isinstance(record, SuricataPolicyRegistryRecord) else SuricataPolicyRegistryRecord.from_dict(record) for record in records)

    @classmethod
    def from_dicts(cls, records: list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> "SuricataPolicyRegistry":
        return cls(list(records))

    @property
    def registry_hash(self) -> str:
        return suricata_registry_hash(tuple(record.to_dict() for record in self.records))

    def validate(
        self,
        *,
        policy_id: str,
        policy_version: str,
        now: datetime | None = None,
        max_age_days: int = MAX_APPROVAL_AGE_DAYS,
    ) -> SuricataPolicyRegistryResult:
        if not self.records:
            return self._blocked("SURICATA_POLICY_REGISTRY_MALFORMED", policy_id, policy_version)

        versions: set[tuple[str, str]] = set()
        for record in self.records:
            key = (record.policy_id, record.policy_version)
            if key in versions:
                return self._blocked("SURICATA_POLICY_DUPLICATE_VERSION", record.policy_id, record.policy_version)
            versions.add(key)

        matches = tuple(record for record in self.records if record.policy_id == policy_id and record.policy_version == policy_version)
        if not matches:
            return self._blocked("SURICATA_POLICY_UNKNOWN", policy_id, policy_version)
        record = matches[0]

        malformed_reason = _malformed_reason(record)
        if malformed_reason:
            return self._blocked(malformed_reason, record.policy_id, record.policy_version, record.evidence_hash)

        expected_hash = suricata_policy_evidence_hash(
            policy_id=record.policy_id,
            policy_version=record.policy_version,
            signature_hash=record.signature_hash,
            rule_count=record.rule_count,
        )
        if record.evidence_hash != expected_hash:
            return self._blocked("SURICATA_POLICY_HASH_MISMATCH", record.policy_id, record.policy_version, record.evidence_hash)

        if record.revoked or not record.active:
            return self._blocked("SURICATA_POLICY_REVOKED", record.policy_id, record.policy_version, record.evidence_hash)

        if not record.approved_by or not record.approval_timestamp:
            return self._blocked("SURICATA_POLICY_APPROVAL_MISSING", record.policy_id, record.policy_version, record.evidence_hash)

        if _is_stale(record, now=now, max_age_days=max_age_days):
            return self._blocked("SURICATA_POLICY_STALE_TIMESTAMP", record.policy_id, record.policy_version, record.evidence_hash)

        result_payload = {
            "approved": True,
            "policy_id": record.policy_id,
            "policy_version": record.policy_version,
            "registry_hash": self.registry_hash,
            "record_evidence_hash": record.evidence_hash,
            "reason": "SURICATA_POLICY_REGISTRY_APPROVED",
        }
        return SuricataPolicyRegistryResult(
            approved=True,
            policy_id=record.policy_id,
            policy_version=record.policy_version,
            registry_hash=self.registry_hash,
            evidence_hash=hash_payload(result_payload),
            reason="SURICATA_POLICY_REGISTRY_APPROVED",
        )

    def _blocked(
        self,
        reason: str,
        policy_id: str,
        policy_version: str,
        evidence_hash: str = "",
    ) -> SuricataPolicyRegistryResult:
        payload = {
            "approved": False,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "registry_hash": self.registry_hash,
            "record_evidence_hash": evidence_hash,
            "reason": reason,
        }
        return SuricataPolicyRegistryResult(
            approved=False,
            policy_id=policy_id,
            policy_version=policy_version,
            registry_hash=self.registry_hash,
            evidence_hash=hash_payload(payload),
            reason=reason,
        )


def _malformed_reason(record: SuricataPolicyRegistryRecord) -> str:
    if not record.policy_id or not record.policy_version:
        return "SURICATA_POLICY_REGISTRY_MALFORMED"
    if record.rule_count <= 0:
        return "SURICATA_POLICY_REGISTRY_MALFORMED"
    if not is_sha256_ref(record.signature_hash):
        return "SURICATA_POLICY_UNSIGNED"
    if not is_sha256_ref(record.evidence_hash):
        return "SURICATA_POLICY_HASH_INVALID"
    if not _parse_timestamp(record.created_at):
        return "SURICATA_POLICY_REGISTRY_MALFORMED"
    if record.approval_timestamp and not _parse_timestamp(record.approval_timestamp):
        return "SURICATA_POLICY_REGISTRY_MALFORMED"
    return ""


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_stale(record: SuricataPolicyRegistryRecord, *, now: datetime | None, max_age_days: int) -> bool:
    approval = _parse_timestamp(record.approval_timestamp)
    created = _parse_timestamp(record.created_at)
    if approval is None or created is None:
        return True
    if approval < created:
        return True
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if approval > current:
        return True
    return (current - approval).days > max_age_days
