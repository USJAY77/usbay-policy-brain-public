"""Final hash-only Suricata fetch receipt proof.

The finalizer binds local fetch receipt evidence to rule-source registry,
signature, trust-anchor, and local rule bundle evidence. It does not fetch
network resources or expose raw Suricata content.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from publication.models import hash_payload, is_sha256_ref
from publication.suricata_fetch_receipt import SuricataFetchReceiptResult
from publication.suricata_rule_signature import SuricataRuleSignatureResult
from publication.suricata_rule_source_fetcher import LocalRuleSourceFetchResult
from publication.suricata_rule_source_registry import SuricataRuleSourceRegistryResult
from publication.suricata_trust_anchor_store import SuricataTrustAnchorFinalizerResult, SuricataTrustAnchorResult


POLICY_VERSION = "USBAY-SURICATA-012"


@dataclass(frozen=True)
class SuricataFetchReceiptFinalizerResult:
    approved: bool
    decision: str
    reason: str
    source_id: str
    policy_version: str
    rule_bundle_hash: str
    source_registry_hash: str
    signature_evidence_hash: str
    trust_anchor_hash: str
    fetch_receipt_hash: str
    local_fetch_hash: str
    final_suricata_fetch_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "decision": self.decision,
            "reason": self.reason,
            "source_id": self.source_id,
            "policy_version": self.policy_version,
            "rule_bundle_hash": self.rule_bundle_hash,
            "source_registry_hash": self.source_registry_hash,
            "signature_evidence_hash": self.signature_evidence_hash,
            "trust_anchor_hash": self.trust_anchor_hash,
            "fetch_receipt_hash": self.fetch_receipt_hash,
            "local_fetch_hash": self.local_fetch_hash,
            "final_suricata_fetch_hash": self.final_suricata_fetch_hash,
        }


def finalize_suricata_fetch_receipt(
    *,
    source_registry: SuricataRuleSourceRegistryResult | None,
    source_signature: SuricataRuleSignatureResult | None,
    trust_anchor: SuricataTrustAnchorResult | None,
    trust_anchor_finalizer: SuricataTrustAnchorFinalizerResult | None,
    fetch_receipt: SuricataFetchReceiptResult | None,
    local_fetch: LocalRuleSourceFetchResult | None,
) -> SuricataFetchReceiptFinalizerResult:
    missing_reason = _missing_or_rejected_reason(
        source_registry=source_registry,
        source_signature=source_signature,
        trust_anchor=trust_anchor,
        trust_anchor_finalizer=trust_anchor_finalizer,
        fetch_receipt=fetch_receipt,
        local_fetch=local_fetch,
    )
    if missing_reason:
        return _blocked(missing_reason)

    assert source_registry is not None
    assert source_signature is not None
    assert trust_anchor is not None
    assert trust_anchor_finalizer is not None
    assert fetch_receipt is not None
    assert local_fetch is not None

    if not _all_hashes_valid(
        source_registry.evidence_hash,
        source_signature.evidence_hash,
        trust_anchor.evidence_hash,
        trust_anchor_finalizer.evidence_hash,
        fetch_receipt.evidence_hash,
        local_fetch.evidence_hash,
        fetch_receipt.rule_bundle_hash,
        source_signature.rule_bundle_hash,
        local_fetch.rule_bundle_hash,
    ):
        return _blocked("SURICATA_FETCH_FINALIZER_MALFORMED")

    if source_registry.approved_policy_version != source_signature.policy_version:
        return _blocked("SURICATA_FETCH_FINALIZER_POLICY_MISMATCH")
    if source_registry.approved_policy_version != trust_anchor.policy_version:
        return _blocked("SURICATA_FETCH_FINALIZER_POLICY_MISMATCH")
    if source_registry.approved_policy_version != fetch_receipt.policy_version and fetch_receipt.policy_version != "USBAY-SURICATA-011":
        return _blocked("SURICATA_FETCH_FINALIZER_POLICY_MISMATCH")
    if source_registry.approved_source_id != source_signature.approved_source_id:
        return _blocked("SURICATA_FETCH_FINALIZER_SOURCE_MISMATCH")
    if source_registry.approved_source_id != fetch_receipt.source_id or source_registry.approved_source_id != local_fetch.source_id:
        return _blocked("SURICATA_FETCH_FINALIZER_SOURCE_MISMATCH")

    if source_signature.rule_bundle_hash != local_fetch.rule_bundle_hash:
        return _blocked("SURICATA_FETCH_FINALIZER_BUNDLE_HASH_MISMATCH")
    if source_signature.rule_bundle_hash != fetch_receipt.rule_bundle_hash:
        return _blocked("SURICATA_FETCH_FINALIZER_BUNDLE_HASH_MISMATCH")
    if fetch_receipt.source_registry_hash != source_registry.evidence_hash:
        return _blocked("SURICATA_FETCH_FINALIZER_REGISTRY_HASH_MISMATCH")
    if fetch_receipt.trust_anchor_hash != trust_anchor_finalizer.evidence_hash:
        return _blocked("SURICATA_FETCH_FINALIZER_TRUST_ANCHOR_HASH_MISMATCH")
    if local_fetch.registry_evidence_hash != source_registry.evidence_hash:
        return _blocked("SURICATA_FETCH_FINALIZER_REGISTRY_HASH_MISMATCH")
    if local_fetch.signature_evidence_hash != source_signature.evidence_hash:
        return _blocked("SURICATA_FETCH_FINALIZER_SIGNATURE_HASH_MISMATCH")

    payload = _payload(
        approved=True,
        decision="ALLOW",
        reason="SURICATA_FETCH_FINALIZER_APPROVED",
        source_id=source_registry.approved_source_id,
        policy_version=source_registry.approved_policy_version,
        rule_bundle_hash=source_signature.rule_bundle_hash,
        source_registry_hash=source_registry.evidence_hash,
        signature_evidence_hash=source_signature.evidence_hash,
        trust_anchor_hash=trust_anchor_finalizer.evidence_hash,
        fetch_receipt_hash=fetch_receipt.evidence_hash,
        local_fetch_hash=local_fetch.evidence_hash,
    )
    final_hash = hash_payload(payload)
    return SuricataFetchReceiptFinalizerResult(
        approved=True,
        decision="ALLOW",
        reason="SURICATA_FETCH_FINALIZER_APPROVED",
        source_id=source_registry.approved_source_id,
        policy_version=source_registry.approved_policy_version,
        rule_bundle_hash=source_signature.rule_bundle_hash,
        source_registry_hash=source_registry.evidence_hash,
        signature_evidence_hash=source_signature.evidence_hash,
        trust_anchor_hash=trust_anchor_finalizer.evidence_hash,
        fetch_receipt_hash=fetch_receipt.evidence_hash,
        local_fetch_hash=local_fetch.evidence_hash,
        final_suricata_fetch_hash=final_hash,
    )


def _missing_or_rejected_reason(
    *,
    source_registry: SuricataRuleSourceRegistryResult | None,
    source_signature: SuricataRuleSignatureResult | None,
    trust_anchor: SuricataTrustAnchorResult | None,
    trust_anchor_finalizer: SuricataTrustAnchorFinalizerResult | None,
    fetch_receipt: SuricataFetchReceiptResult | None,
    local_fetch: LocalRuleSourceFetchResult | None,
) -> str:
    if source_registry is None:
        return "SURICATA_FETCH_FINALIZER_REGISTRY_MISSING"
    if not source_registry.approved:
        return source_registry.reason
    if source_signature is None:
        return "SURICATA_FETCH_FINALIZER_SIGNATURE_MISSING"
    if not source_signature.approved:
        return source_signature.reason
    if trust_anchor is None:
        return "SURICATA_FETCH_FINALIZER_TRUST_ANCHOR_MISSING"
    if not trust_anchor.approved:
        return trust_anchor.reason
    if trust_anchor_finalizer is None:
        return "SURICATA_FETCH_FINALIZER_TRUST_ANCHOR_FINALIZER_MISSING"
    if not trust_anchor_finalizer.approved:
        return trust_anchor_finalizer.finalizer_reason
    if fetch_receipt is None:
        return "SURICATA_FETCH_FINALIZER_RECEIPT_MISSING"
    if not fetch_receipt.approved:
        return fetch_receipt.reason
    if local_fetch is None:
        return "SURICATA_FETCH_FINALIZER_LOCAL_FETCH_MISSING"
    if not local_fetch.approved:
        return local_fetch.reason
    return ""


def _all_hashes_valid(*values: str) -> bool:
    return all(is_sha256_ref(value) for value in values)


def _blocked(reason: str) -> SuricataFetchReceiptFinalizerResult:
    payload = _payload(
        approved=False,
        decision="BLOCK",
        reason=reason,
        source_id="",
        policy_version=POLICY_VERSION,
        rule_bundle_hash="",
        source_registry_hash="",
        signature_evidence_hash="",
        trust_anchor_hash="",
        fetch_receipt_hash="",
        local_fetch_hash="",
    )
    return SuricataFetchReceiptFinalizerResult(
        approved=False,
        decision="BLOCK",
        reason=reason,
        source_id="",
        policy_version=POLICY_VERSION,
        rule_bundle_hash="",
        source_registry_hash="",
        signature_evidence_hash="",
        trust_anchor_hash="",
        fetch_receipt_hash="",
        local_fetch_hash="",
        final_suricata_fetch_hash=hash_payload(payload),
    )


def _payload(
    *,
    approved: bool,
    decision: str,
    reason: str,
    source_id: str,
    policy_version: str,
    rule_bundle_hash: str,
    source_registry_hash: str,
    signature_evidence_hash: str,
    trust_anchor_hash: str,
    fetch_receipt_hash: str,
    local_fetch_hash: str,
) -> dict[str, Any]:
    return {
        "approved": approved,
        "decision": decision,
        "reason": reason,
        "source_id": source_id,
        "policy_version": policy_version,
        "rule_bundle_hash": rule_bundle_hash,
        "source_registry_hash": source_registry_hash,
        "signature_evidence_hash": signature_evidence_hash,
        "trust_anchor_hash": trust_anchor_hash,
        "fetch_receipt_hash": fetch_receipt_hash,
        "local_fetch_hash": local_fetch_hash,
        "finalizer_policy_version": POLICY_VERSION,
    }
