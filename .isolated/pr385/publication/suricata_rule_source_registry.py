"""Local Suricata rule source registry.

This module validates source allowlist metadata only. It does not fetch rule
sets, open network connections, or store raw source URIs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from publication.models import hash_payload, is_sha256_ref


POLICY_VERSION = "USBAY-SURICATA-005"


@dataclass(frozen=True)
class SuricataRuleSourceRecord:
    approved_source_id: str
    source_name: str
    source_uri_hash: str
    approved_public_key_hash: str
    approved_policy_version: str
    max_age_seconds: int
    revoked: bool
    human_approval_id: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SuricataRuleSourceRecord":
        return cls(
            approved_source_id=str(payload.get("approved_source_id") or ""),
            source_name=str(payload.get("source_name") or ""),
            source_uri_hash=str(payload.get("source_uri_hash") or ""),
            approved_public_key_hash=str(payload.get("approved_public_key_hash") or ""),
            approved_policy_version=str(payload.get("approved_policy_version") or ""),
            max_age_seconds=payload.get("max_age_seconds") if isinstance(payload.get("max_age_seconds"), int) else -1,
            revoked=payload.get("revoked") is True,
            human_approval_id=str(payload.get("human_approval_id") or ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved_source_id": self.approved_source_id,
            "source_name": self.source_name,
            "source_uri_hash": self.source_uri_hash,
            "approved_public_key_hash": self.approved_public_key_hash,
            "approved_policy_version": self.approved_policy_version,
            "max_age_seconds": self.max_age_seconds,
            "revoked": self.revoked,
            "human_approval_id": self.human_approval_id,
        }


@dataclass(frozen=True)
class SuricataRuleSourceRegistryResult:
    approved: bool
    approved_source_id: str
    approved_policy_version: str
    registry_hash: str
    evidence_hash: str
    reason: str
    policy_version: str = POLICY_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "approved_source_id": self.approved_source_id,
            "approved_policy_version": self.approved_policy_version,
            "registry_hash": self.registry_hash,
            "evidence_hash": self.evidence_hash,
            "reason": self.reason,
            "policy_version": self.policy_version,
        }


class SuricataRuleSourceRegistry:
    def __init__(self, records: list[dict[str, Any] | SuricataRuleSourceRecord] | tuple[dict[str, Any] | SuricataRuleSourceRecord, ...]):
        self.records = tuple(record if isinstance(record, SuricataRuleSourceRecord) else SuricataRuleSourceRecord.from_dict(record) for record in records)

    @property
    def registry_hash(self) -> str:
        return hash_payload({"suricata_rule_source_registry": tuple(record.to_dict() for record in self.records)})

    def validate_source(self, *, approved_source_id: str, policy_version: str) -> SuricataRuleSourceRegistryResult:
        if not self.records:
            return self._blocked("SURICATA_RULE_SOURCE_REGISTRY_MALFORMED", approved_source_id, policy_version)

        seen: set[str] = set()
        for record in self.records:
            if record.approved_source_id in seen:
                return self._blocked("SURICATA_RULE_SOURCE_DUPLICATE", record.approved_source_id, record.approved_policy_version)
            seen.add(record.approved_source_id)

        matches = tuple(record for record in self.records if record.approved_source_id == approved_source_id)
        if not matches:
            return self._blocked("SURICATA_RULE_SOURCE_UNKNOWN", approved_source_id, policy_version)
        record = matches[0]

        malformed_reason = _malformed_reason(record)
        if malformed_reason:
            return self._blocked(malformed_reason, record.approved_source_id, record.approved_policy_version)
        if record.revoked:
            return self._blocked("SURICATA_RULE_SOURCE_REVOKED", record.approved_source_id, record.approved_policy_version)
        if record.approved_policy_version != policy_version:
            return self._blocked("SURICATA_RULE_SOURCE_POLICY_MISMATCH", record.approved_source_id, record.approved_policy_version)

        evidence_hash = hash_payload(
            {
                "approved": True,
                "approved_source_id": record.approved_source_id,
                "approved_policy_version": record.approved_policy_version,
                "registry_hash": self.registry_hash,
                "reason": "SURICATA_RULE_SOURCE_APPROVED",
            }
        )
        return SuricataRuleSourceRegistryResult(
            approved=True,
            approved_source_id=record.approved_source_id,
            approved_policy_version=record.approved_policy_version,
            registry_hash=self.registry_hash,
            evidence_hash=evidence_hash,
            reason="SURICATA_RULE_SOURCE_APPROVED",
        )

    def _blocked(self, reason: str, approved_source_id: str, policy_version: str) -> SuricataRuleSourceRegistryResult:
        evidence_hash = hash_payload(
            {
                "approved": False,
                "approved_source_id": approved_source_id,
                "approved_policy_version": policy_version,
                "registry_hash": self.registry_hash,
                "reason": reason,
            }
        )
        return SuricataRuleSourceRegistryResult(
            approved=False,
            approved_source_id=approved_source_id,
            approved_policy_version=policy_version,
            registry_hash=self.registry_hash,
            evidence_hash=evidence_hash,
            reason=reason,
        )


def _malformed_reason(record: SuricataRuleSourceRecord) -> str:
    if not record.approved_source_id or not record.source_name or not record.approved_policy_version:
        return "SURICATA_RULE_SOURCE_REGISTRY_MALFORMED"
    if not is_sha256_ref(record.source_uri_hash) or not is_sha256_ref(record.approved_public_key_hash):
        return "SURICATA_RULE_SOURCE_REGISTRY_MALFORMED"
    if record.max_age_seconds <= 0:
        return "SURICATA_RULE_SOURCE_REGISTRY_MALFORMED"
    if not record.human_approval_id:
        return "SURICATA_RULE_SOURCE_APPROVAL_MISSING"
    return ""
