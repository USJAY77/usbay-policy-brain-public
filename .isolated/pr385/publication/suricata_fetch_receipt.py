"""Governed local Suricata fetch receipt validation.

The receipt model is metadata-only. It does not fetch network resources and
never stores raw Suricata rule bundle contents.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from publication.models import hash_payload, is_sha256_ref


POLICY_VERSION = "USBAY-SURICATA-011"


@dataclass(frozen=True)
class SuricataFetchReceipt:
    source_id: str
    source_registry_hash: str
    rule_bundle_hash: str
    trust_anchor_hash: str
    fetched_at: str
    freshness_window_seconds: int
    human_approval_id: str
    fetch_receipt_hash: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SuricataFetchReceipt":
        return cls(
            source_id=str(payload.get("source_id") or ""),
            source_registry_hash=str(payload.get("source_registry_hash") or ""),
            rule_bundle_hash=str(payload.get("rule_bundle_hash") or ""),
            trust_anchor_hash=str(payload.get("trust_anchor_hash") or ""),
            fetched_at=str(payload.get("fetched_at") or ""),
            freshness_window_seconds=payload.get("freshness_window_seconds")
            if isinstance(payload.get("freshness_window_seconds"), int)
            else -1,
            human_approval_id=str(payload.get("human_approval_id") or ""),
            fetch_receipt_hash=str(payload.get("fetch_receipt_hash") or ""),
        )

    def to_hash_payload(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_registry_hash": self.source_registry_hash,
            "rule_bundle_hash": self.rule_bundle_hash,
            "trust_anchor_hash": self.trust_anchor_hash,
            "fetched_at": self.fetched_at,
            "freshness_window_seconds": self.freshness_window_seconds,
            "human_approval_id": self.human_approval_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.to_hash_payload(),
            "fetch_receipt_hash": self.fetch_receipt_hash,
        }


@dataclass(frozen=True)
class SuricataFetchReceiptResult:
    approved: bool
    blocked: bool
    reason: str
    source_id: str
    source_registry_hash: str
    rule_bundle_hash: str
    trust_anchor_hash: str
    fetch_receipt_hash: str
    policy_version: str
    evidence_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "blocked": self.blocked,
            "reason": self.reason,
            "source_id": self.source_id,
            "source_registry_hash": self.source_registry_hash,
            "rule_bundle_hash": self.rule_bundle_hash,
            "trust_anchor_hash": self.trust_anchor_hash,
            "fetch_receipt_hash": self.fetch_receipt_hash,
            "policy_version": self.policy_version,
            "evidence_hash": self.evidence_hash,
        }


def suricata_fetch_receipt_hash(
    *,
    source_id: str,
    source_registry_hash: str,
    rule_bundle_hash: str,
    trust_anchor_hash: str,
    fetched_at: str,
    freshness_window_seconds: int,
    human_approval_id: str,
) -> str:
    return hash_payload(
        {
            "source_id": source_id,
            "source_registry_hash": source_registry_hash,
            "rule_bundle_hash": rule_bundle_hash,
            "trust_anchor_hash": trust_anchor_hash,
            "fetched_at": fetched_at,
            "freshness_window_seconds": freshness_window_seconds,
            "human_approval_id": human_approval_id,
        }
    )


def validate_suricata_fetch_receipt(
    receipt: SuricataFetchReceipt | dict[str, Any] | None,
    *,
    now: datetime | None = None,
) -> SuricataFetchReceiptResult:
    if receipt is None:
        return _blocked("SURICATA_FETCH_RECEIPT_MISSING", "", "", "", "")
    resolved = receipt if isinstance(receipt, SuricataFetchReceipt) else SuricataFetchReceipt.from_dict(receipt)

    malformed_reason = _malformed_reason(resolved)
    if malformed_reason:
        return _blocked(
            malformed_reason,
            resolved.source_id,
            resolved.source_registry_hash,
            resolved.rule_bundle_hash,
            resolved.trust_anchor_hash,
            resolved.fetch_receipt_hash,
        )

    fetched_at = _parse_timestamp(resolved.fetched_at)
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if fetched_at is None:
        return _blocked(
            "SURICATA_FETCH_RECEIPT_MALFORMED",
            resolved.source_id,
            resolved.source_registry_hash,
            resolved.rule_bundle_hash,
            resolved.trust_anchor_hash,
            resolved.fetch_receipt_hash,
        )
    if fetched_at > current or (current - fetched_at).total_seconds() > resolved.freshness_window_seconds:
        return _blocked(
            "SURICATA_FETCH_RECEIPT_STALE",
            resolved.source_id,
            resolved.source_registry_hash,
            resolved.rule_bundle_hash,
            resolved.trust_anchor_hash,
            resolved.fetch_receipt_hash,
        )

    expected_hash = suricata_fetch_receipt_hash(**resolved.to_hash_payload())
    if resolved.fetch_receipt_hash != expected_hash:
        return _blocked(
            "SURICATA_FETCH_RECEIPT_HASH_MISMATCH",
            resolved.source_id,
            resolved.source_registry_hash,
            resolved.rule_bundle_hash,
            resolved.trust_anchor_hash,
            resolved.fetch_receipt_hash,
        )

    payload = _result_payload(
        approved=True,
        blocked=False,
        reason="SURICATA_FETCH_RECEIPT_APPROVED",
        source_id=resolved.source_id,
        source_registry_hash=resolved.source_registry_hash,
        rule_bundle_hash=resolved.rule_bundle_hash,
        trust_anchor_hash=resolved.trust_anchor_hash,
        fetch_receipt_hash=resolved.fetch_receipt_hash,
    )
    return SuricataFetchReceiptResult(
        approved=True,
        blocked=False,
        reason="SURICATA_FETCH_RECEIPT_APPROVED",
        source_id=resolved.source_id,
        source_registry_hash=resolved.source_registry_hash,
        rule_bundle_hash=resolved.rule_bundle_hash,
        trust_anchor_hash=resolved.trust_anchor_hash,
        fetch_receipt_hash=resolved.fetch_receipt_hash,
        policy_version=POLICY_VERSION,
        evidence_hash=hash_payload(payload),
    )


def _malformed_reason(receipt: SuricataFetchReceipt) -> str:
    if not receipt.source_id:
        return "SURICATA_FETCH_RECEIPT_SOURCE_MISSING"
    if not is_sha256_ref(receipt.source_registry_hash):
        return "SURICATA_FETCH_RECEIPT_REGISTRY_HASH_INVALID"
    if not is_sha256_ref(receipt.rule_bundle_hash):
        return "SURICATA_FETCH_RECEIPT_BUNDLE_HASH_INVALID"
    if not is_sha256_ref(receipt.trust_anchor_hash):
        return "SURICATA_FETCH_RECEIPT_TRUST_ANCHOR_HASH_INVALID"
    if not receipt.fetched_at or _parse_timestamp(receipt.fetched_at) is None:
        return "SURICATA_FETCH_RECEIPT_MALFORMED"
    if receipt.freshness_window_seconds <= 0:
        return "SURICATA_FETCH_RECEIPT_MALFORMED"
    if not receipt.human_approval_id:
        return "SURICATA_FETCH_RECEIPT_HUMAN_APPROVAL_MISSING"
    if not is_sha256_ref(receipt.fetch_receipt_hash):
        return "SURICATA_FETCH_RECEIPT_HASH_MISSING"
    return ""


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _blocked(reason: str, source_id: str, source_registry_hash: str, rule_bundle_hash: str, trust_anchor_hash: str, fetch_receipt_hash: str = "") -> SuricataFetchReceiptResult:
    payload = _result_payload(
        approved=False,
        blocked=True,
        reason=reason,
        source_id=source_id,
        source_registry_hash=source_registry_hash,
        rule_bundle_hash=rule_bundle_hash,
        trust_anchor_hash=trust_anchor_hash,
        fetch_receipt_hash=fetch_receipt_hash,
    )
    return SuricataFetchReceiptResult(
        approved=False,
        blocked=True,
        reason=reason,
        source_id=source_id,
        source_registry_hash=source_registry_hash,
        rule_bundle_hash=rule_bundle_hash,
        trust_anchor_hash=trust_anchor_hash,
        fetch_receipt_hash=fetch_receipt_hash,
        policy_version=POLICY_VERSION,
        evidence_hash=hash_payload(payload),
    )


def _result_payload(
    *,
    approved: bool,
    blocked: bool,
    reason: str,
    source_id: str,
    source_registry_hash: str,
    rule_bundle_hash: str,
    trust_anchor_hash: str,
    fetch_receipt_hash: str,
) -> dict[str, Any]:
    return {
        "approved": approved,
        "blocked": blocked,
        "reason": reason,
        "source_id": source_id,
        "source_registry_hash": source_registry_hash,
        "rule_bundle_hash": rule_bundle_hash,
        "trust_anchor_hash": trust_anchor_hash,
        "fetch_receipt_hash": fetch_receipt_hash,
        "policy_version": POLICY_VERSION,
    }
