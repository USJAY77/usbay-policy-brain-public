"""Governed Suricata source rollback/replacement flow.

This module validates replacement metadata only. It does not fetch network
resources and never exposes raw Suricata rule payloads or EVE JSON.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from publication.models import hash_payload, is_sha256_ref
from publication.suricata_fetch_receipt import SuricataFetchReceiptResult
from publication.suricata_fetch_receipt_finalizer import SuricataFetchReceiptFinalizerResult
from publication.suricata_rule_signature import SuricataRuleSignatureResult
from publication.suricata_rule_source_registry import SuricataRuleSourceRegistryResult
from publication.suricata_trust_anchor_store import SuricataTrustAnchorFinalizerResult, SuricataTrustAnchorResult


POLICY_VERSION = "USBAY-SURICATA-013"


@dataclass(frozen=True)
class SuricataSourceReplacementFlowResult:
    approved: bool
    decision: str
    reason: str
    source_id: str
    rule_bundle_hash: str
    previous_rule_bundle_hash: str
    policy_version: str
    rollback_plan_id: str
    human_approval_id: str
    replacement_flow_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "decision": self.decision,
            "reason": self.reason,
            "source_id": self.source_id,
            "rule_bundle_hash": self.rule_bundle_hash,
            "previous_rule_bundle_hash": self.previous_rule_bundle_hash,
            "policy_version": self.policy_version,
            "rollback_plan_id": self.rollback_plan_id,
            "human_approval_id": self.human_approval_id,
            "replacement_flow_hash": self.replacement_flow_hash,
        }


def validate_suricata_source_replacement_flow(
    *,
    current_fetch_finalizer: SuricataFetchReceiptFinalizerResult | None,
    candidate_fetch_receipt: SuricataFetchReceiptResult | None,
    candidate_source_registry: SuricataRuleSourceRegistryResult | None,
    candidate_signature: SuricataRuleSignatureResult | None,
    trust_anchor: SuricataTrustAnchorResult | None,
    trust_anchor_finalizer: SuricataTrustAnchorFinalizerResult | None,
    rollback_plan_id: str,
    human_approval_id: str,
    replacement_approved: bool,
) -> SuricataSourceReplacementFlowResult:
    missing_reason = _missing_or_rejected_reason(
        current_fetch_finalizer=current_fetch_finalizer,
        candidate_fetch_receipt=candidate_fetch_receipt,
        candidate_source_registry=candidate_source_registry,
        candidate_signature=candidate_signature,
        trust_anchor=trust_anchor,
        trust_anchor_finalizer=trust_anchor_finalizer,
    )
    if missing_reason:
        return _blocked(missing_reason, rollback_plan_id, human_approval_id)

    assert current_fetch_finalizer is not None
    assert candidate_fetch_receipt is not None
    assert candidate_source_registry is not None
    assert candidate_signature is not None
    assert trust_anchor is not None
    assert trust_anchor_finalizer is not None

    if not rollback_plan_id:
        return _blocked("SURICATA_REPLACEMENT_ROLLBACK_PLAN_MISSING", rollback_plan_id, human_approval_id)
    if not human_approval_id:
        return _blocked("SURICATA_REPLACEMENT_HUMAN_APPROVAL_MISSING", rollback_plan_id, human_approval_id)
    if not _all_hashes_valid(
        current_fetch_finalizer.final_suricata_fetch_hash,
        candidate_fetch_receipt.evidence_hash,
        candidate_source_registry.evidence_hash,
        candidate_signature.evidence_hash,
        trust_anchor.evidence_hash,
        trust_anchor_finalizer.evidence_hash,
        current_fetch_finalizer.rule_bundle_hash,
        candidate_fetch_receipt.rule_bundle_hash,
        candidate_signature.rule_bundle_hash,
    ):
        return _blocked("SURICATA_REPLACEMENT_MALFORMED", rollback_plan_id, human_approval_id)

    policy_version = current_fetch_finalizer.policy_version
    if candidate_source_registry.approved_policy_version != policy_version:
        return _blocked("SURICATA_REPLACEMENT_POLICY_MISMATCH", rollback_plan_id, human_approval_id)
    if candidate_signature.policy_version != policy_version:
        return _blocked("SURICATA_REPLACEMENT_POLICY_MISMATCH", rollback_plan_id, human_approval_id)
    if trust_anchor.policy_version != policy_version:
        return _blocked("SURICATA_REPLACEMENT_POLICY_MISMATCH", rollback_plan_id, human_approval_id)
    if candidate_fetch_receipt.rule_bundle_hash != candidate_signature.rule_bundle_hash:
        return _blocked("SURICATA_REPLACEMENT_RULE_BUNDLE_HASH_MISMATCH", rollback_plan_id, human_approval_id)
    if candidate_fetch_receipt.source_registry_hash != candidate_source_registry.evidence_hash:
        return _blocked("SURICATA_REPLACEMENT_REGISTRY_HASH_MISMATCH", rollback_plan_id, human_approval_id)
    if candidate_fetch_receipt.trust_anchor_hash != trust_anchor_finalizer.evidence_hash:
        return _blocked("SURICATA_REPLACEMENT_TRUST_ANCHOR_HASH_MISMATCH", rollback_plan_id, human_approval_id)
    if candidate_source_registry.approved_source_id != candidate_signature.approved_source_id:
        return _blocked("SURICATA_REPLACEMENT_SOURCE_MISMATCH", rollback_plan_id, human_approval_id)
    if candidate_source_registry.approved_source_id != candidate_fetch_receipt.source_id:
        return _blocked("SURICATA_REPLACEMENT_SOURCE_MISMATCH", rollback_plan_id, human_approval_id)
    if current_fetch_finalizer.rule_bundle_hash != candidate_signature.rule_bundle_hash and not replacement_approved:
        return _blocked("SURICATA_REPLACEMENT_APPROVAL_REQUIRED", rollback_plan_id, human_approval_id)

    payload = _payload(
        approved=True,
        decision="ALLOW",
        reason="SURICATA_REPLACEMENT_FLOW_APPROVED",
        source_id=candidate_source_registry.approved_source_id,
        rule_bundle_hash=candidate_signature.rule_bundle_hash,
        previous_rule_bundle_hash=current_fetch_finalizer.rule_bundle_hash,
        policy_version=policy_version,
        rollback_plan_id=rollback_plan_id,
        human_approval_id=human_approval_id,
        current_fetch_hash=current_fetch_finalizer.final_suricata_fetch_hash,
        candidate_receipt_hash=candidate_fetch_receipt.evidence_hash,
        candidate_registry_hash=candidate_source_registry.evidence_hash,
        candidate_signature_hash=candidate_signature.evidence_hash,
        trust_anchor_hash=trust_anchor_finalizer.evidence_hash,
    )
    return SuricataSourceReplacementFlowResult(
        approved=True,
        decision="ALLOW",
        reason="SURICATA_REPLACEMENT_FLOW_APPROVED",
        source_id=candidate_source_registry.approved_source_id,
        rule_bundle_hash=candidate_signature.rule_bundle_hash,
        previous_rule_bundle_hash=current_fetch_finalizer.rule_bundle_hash,
        policy_version=policy_version,
        rollback_plan_id=rollback_plan_id,
        human_approval_id=human_approval_id,
        replacement_flow_hash=hash_payload(payload),
    )


def _missing_or_rejected_reason(
    *,
    current_fetch_finalizer: SuricataFetchReceiptFinalizerResult | None,
    candidate_fetch_receipt: SuricataFetchReceiptResult | None,
    candidate_source_registry: SuricataRuleSourceRegistryResult | None,
    candidate_signature: SuricataRuleSignatureResult | None,
    trust_anchor: SuricataTrustAnchorResult | None,
    trust_anchor_finalizer: SuricataTrustAnchorFinalizerResult | None,
) -> str:
    if current_fetch_finalizer is None:
        return "SURICATA_REPLACEMENT_CURRENT_PROOF_MISSING"
    if not current_fetch_finalizer.approved:
        return current_fetch_finalizer.reason
    if candidate_fetch_receipt is None:
        return "SURICATA_REPLACEMENT_CANDIDATE_RECEIPT_MISSING"
    if not candidate_fetch_receipt.approved:
        return candidate_fetch_receipt.reason
    if candidate_source_registry is None:
        return "SURICATA_REPLACEMENT_CANDIDATE_REGISTRY_MISSING"
    if not candidate_source_registry.approved:
        return candidate_source_registry.reason
    if candidate_signature is None:
        return "SURICATA_REPLACEMENT_CANDIDATE_SIGNATURE_MISSING"
    if not candidate_signature.approved:
        return candidate_signature.reason
    if trust_anchor is None:
        return "SURICATA_REPLACEMENT_TRUST_ANCHOR_MISSING"
    if not trust_anchor.approved:
        return trust_anchor.reason
    if trust_anchor_finalizer is None:
        return "SURICATA_REPLACEMENT_TRUST_ANCHOR_FINALIZER_MISSING"
    if not trust_anchor_finalizer.approved:
        return trust_anchor_finalizer.finalizer_reason
    return ""


def _all_hashes_valid(*values: str) -> bool:
    return all(is_sha256_ref(value) for value in values)


def _blocked(reason: str, rollback_plan_id: str, human_approval_id: str) -> SuricataSourceReplacementFlowResult:
    payload = _payload(
        approved=False,
        decision="BLOCK",
        reason=reason,
        source_id="",
        rule_bundle_hash="",
        previous_rule_bundle_hash="",
        policy_version=POLICY_VERSION,
        rollback_plan_id=rollback_plan_id,
        human_approval_id=human_approval_id,
        current_fetch_hash="",
        candidate_receipt_hash="",
        candidate_registry_hash="",
        candidate_signature_hash="",
        trust_anchor_hash="",
    )
    return SuricataSourceReplacementFlowResult(
        approved=False,
        decision="BLOCK",
        reason=reason,
        source_id="",
        rule_bundle_hash="",
        previous_rule_bundle_hash="",
        policy_version=POLICY_VERSION,
        rollback_plan_id=rollback_plan_id,
        human_approval_id=human_approval_id,
        replacement_flow_hash=hash_payload(payload),
    )


def _payload(
    *,
    approved: bool,
    decision: str,
    reason: str,
    source_id: str,
    rule_bundle_hash: str,
    previous_rule_bundle_hash: str,
    policy_version: str,
    rollback_plan_id: str,
    human_approval_id: str,
    current_fetch_hash: str,
    candidate_receipt_hash: str,
    candidate_registry_hash: str,
    candidate_signature_hash: str,
    trust_anchor_hash: str,
) -> dict[str, Any]:
    return {
        "approved": approved,
        "decision": decision,
        "reason": reason,
        "source_id": source_id,
        "rule_bundle_hash": rule_bundle_hash,
        "previous_rule_bundle_hash": previous_rule_bundle_hash,
        "policy_version": policy_version,
        "rollback_plan_id": rollback_plan_id,
        "human_approval_id": human_approval_id,
        "current_fetch_hash": current_fetch_hash,
        "candidate_receipt_hash": candidate_receipt_hash,
        "candidate_registry_hash": candidate_registry_hash,
        "candidate_signature_hash": candidate_signature_hash,
        "trust_anchor_hash": trust_anchor_hash,
        "replacement_policy_version": POLICY_VERSION,
    }
