"""Local Suricata rule bundle signature metadata verification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from publication.models import hash_payload, is_sha256_ref
from publication.suricata_rule_source_registry import SuricataRuleSourceRecord, SuricataRuleSourceRegistryResult


POLICY_VERSION = "USBAY-SURICATA-005"


@dataclass(frozen=True)
class SuricataRuleBundleMetadata:
    approved_source_id: str
    policy_version: str
    rule_bundle_hash: str
    public_key_hash: str
    signature_hash: str
    generated_at: str
    rule_count: int

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SuricataRuleBundleMetadata":
        return cls(
            approved_source_id=str(payload.get("approved_source_id") or ""),
            policy_version=str(payload.get("policy_version") or ""),
            rule_bundle_hash=str(payload.get("rule_bundle_hash") or ""),
            public_key_hash=str(payload.get("public_key_hash") or ""),
            signature_hash=str(payload.get("signature_hash") or ""),
            generated_at=str(payload.get("generated_at") or ""),
            rule_count=payload.get("rule_count") if isinstance(payload.get("rule_count"), int) else -1,
        )

    def to_redacted_dict(self) -> dict[str, Any]:
        return {
            "approved_source_id": self.approved_source_id,
            "policy_version": self.policy_version,
            "rule_bundle_hash": self.rule_bundle_hash,
            "public_key_hash": self.public_key_hash,
            "signature_hash": self.signature_hash,
            "generated_at": self.generated_at,
            "rule_count": self.rule_count,
            "raw_rule_payload_stored": False,
        }


@dataclass(frozen=True)
class SuricataRuleSignatureResult:
    approved: bool
    approved_source_id: str
    policy_version: str
    evidence_hash: str
    rule_bundle_hash: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "approved_source_id": self.approved_source_id,
            "policy_version": self.policy_version,
            "evidence_hash": self.evidence_hash,
            "rule_bundle_hash": self.rule_bundle_hash,
            "reason": self.reason,
        }


def expected_rule_signature_hash(*, rule_bundle_hash: str, public_key_hash: str, policy_version: str) -> str:
    return hash_payload(
        {
            "rule_bundle_hash": rule_bundle_hash,
            "public_key_hash": public_key_hash,
            "policy_version": policy_version,
        }
    )


def verify_suricata_rule_signature(
    *,
    metadata: SuricataRuleBundleMetadata | dict[str, Any] | None,
    source_record: SuricataRuleSourceRecord | None,
    source_registry_result: SuricataRuleSourceRegistryResult | None,
    now: datetime | None = None,
) -> SuricataRuleSignatureResult:
    if metadata is None:
        return _blocked("SURICATA_RULE_SIGNATURE_METADATA_MISSING", "", "", "")
    resolved_metadata = metadata if isinstance(metadata, SuricataRuleBundleMetadata) else SuricataRuleBundleMetadata.from_dict(metadata)

    if source_record is None or source_registry_result is None or not source_registry_result.approved:
        return _blocked(
            "SURICATA_RULE_SOURCE_NOT_APPROVED",
            resolved_metadata.approved_source_id,
            resolved_metadata.policy_version,
            resolved_metadata.rule_bundle_hash,
        )

    malformed_reason = _metadata_malformed_reason(resolved_metadata)
    if malformed_reason:
        return _blocked(malformed_reason, resolved_metadata.approved_source_id, resolved_metadata.policy_version, resolved_metadata.rule_bundle_hash)

    if resolved_metadata.approved_source_id != source_record.approved_source_id:
        return _blocked("SURICATA_RULE_SOURCE_UNKNOWN", resolved_metadata.approved_source_id, resolved_metadata.policy_version, resolved_metadata.rule_bundle_hash)
    if resolved_metadata.policy_version != source_record.approved_policy_version:
        return _blocked("SURICATA_RULE_SOURCE_POLICY_MISMATCH", resolved_metadata.approved_source_id, resolved_metadata.policy_version, resolved_metadata.rule_bundle_hash)
    if resolved_metadata.public_key_hash != source_record.approved_public_key_hash:
        return _blocked("SURICATA_RULE_SIGNATURE_KEY_MISMATCH", resolved_metadata.approved_source_id, resolved_metadata.policy_version, resolved_metadata.rule_bundle_hash)
    if _is_stale(resolved_metadata, source_record=source_record, now=now):
        return _blocked("SURICATA_RULE_SOURCE_STALE", resolved_metadata.approved_source_id, resolved_metadata.policy_version, resolved_metadata.rule_bundle_hash)

    expected_signature = expected_rule_signature_hash(
        rule_bundle_hash=resolved_metadata.rule_bundle_hash,
        public_key_hash=resolved_metadata.public_key_hash,
        policy_version=resolved_metadata.policy_version,
    )
    if resolved_metadata.signature_hash != expected_signature:
        return _blocked("SURICATA_RULE_SIGNATURE_MISMATCH", resolved_metadata.approved_source_id, resolved_metadata.policy_version, resolved_metadata.rule_bundle_hash)

    payload = {
        "approved": True,
        "metadata": resolved_metadata.to_redacted_dict(),
        "source_registry_evidence_hash": source_registry_result.evidence_hash,
        "reason": "SURICATA_RULE_SIGNATURE_APPROVED",
    }
    return SuricataRuleSignatureResult(
        approved=True,
        approved_source_id=resolved_metadata.approved_source_id,
        policy_version=resolved_metadata.policy_version,
        evidence_hash=hash_payload(payload),
        rule_bundle_hash=resolved_metadata.rule_bundle_hash,
        reason="SURICATA_RULE_SIGNATURE_APPROVED",
    )


def _metadata_malformed_reason(metadata: SuricataRuleBundleMetadata) -> str:
    if not metadata.approved_source_id or not metadata.policy_version:
        return "SURICATA_RULE_SIGNATURE_METADATA_MALFORMED"
    if metadata.rule_count <= 0:
        return "SURICATA_RULE_SIGNATURE_METADATA_MALFORMED"
    if not is_sha256_ref(metadata.rule_bundle_hash):
        return "SURICATA_RULE_SIGNATURE_METADATA_MALFORMED"
    if not is_sha256_ref(metadata.public_key_hash) or not is_sha256_ref(metadata.signature_hash):
        return "SURICATA_RULE_SIGNATURE_MISSING"
    if _parse_timestamp(metadata.generated_at) is None:
        return "SURICATA_RULE_SIGNATURE_METADATA_MALFORMED"
    return ""


def _is_stale(metadata: SuricataRuleBundleMetadata, *, source_record: SuricataRuleSourceRecord, now: datetime | None) -> bool:
    generated_at = _parse_timestamp(metadata.generated_at)
    if generated_at is None:
        return True
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if generated_at > current:
        return True
    return (current - generated_at).total_seconds() > source_record.max_age_seconds


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _blocked(reason: str, source_id: str, policy_version: str, rule_bundle_hash: str) -> SuricataRuleSignatureResult:
    payload = {
        "approved": False,
        "approved_source_id": source_id,
        "policy_version": policy_version,
        "rule_bundle_hash": rule_bundle_hash,
        "reason": reason,
    }
    return SuricataRuleSignatureResult(
        approved=False,
        approved_source_id=source_id,
        policy_version=policy_version,
        evidence_hash=hash_payload(payload),
        rule_bundle_hash=rule_bundle_hash,
        reason=reason,
    )
