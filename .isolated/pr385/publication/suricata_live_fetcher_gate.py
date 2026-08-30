"""Fail-closed Suricata live-network-fetcher governance gate.

This module validates whether live-fetcher governance evidence is complete. It
does not perform network calls, connector calls, publication, or rule fetching.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from publication.models import hash_payload, is_sha256_ref
from publication.suricata_fetch_receipt import SuricataFetchReceiptResult
from publication.suricata_rule_source_registry import SuricataRuleSourceRegistryResult
from publication.suricata_source_replacement_flow import SuricataSourceReplacementFlowResult
from publication.suricata_trust_anchor_store import SuricataTrustAnchorFinalizerResult, SuricataTrustAnchorResult


POLICY_VERSION = "USBAY-SURICATA-014-LIVE-FETCHER-GATE"


@dataclass(frozen=True)
class SuricataLiveFetcherGateResult:
    approved: bool
    blocked: bool
    decision: str
    reason: str
    policy_version: str
    live_fetch_enabled: bool
    human_approval_id: str
    source_registry_hash: str
    trust_anchor_hash: str
    fetch_receipt_hash: str
    replacement_flow_hash: str
    evaluated_at: str
    evidence_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "blocked": self.blocked,
            "decision": self.decision,
            "reason": self.reason,
            "policy_version": self.policy_version,
            "live_fetch_enabled": self.live_fetch_enabled,
            "human_approval_id": self.human_approval_id,
            "source_registry_hash": self.source_registry_hash,
            "trust_anchor_hash": self.trust_anchor_hash,
            "fetch_receipt_hash": self.fetch_receipt_hash,
            "replacement_flow_hash": self.replacement_flow_hash,
            "evaluated_at": self.evaluated_at,
            "evidence_hash": self.evidence_hash,
        }


def validate_suricata_live_fetcher_gate(
    *,
    policy: dict[str, Any] | None,
    source_registry: SuricataRuleSourceRegistryResult | None,
    trust_anchor: SuricataTrustAnchorResult | None,
    trust_anchor_finalizer: SuricataTrustAnchorFinalizerResult | None,
    fetch_receipt: SuricataFetchReceiptResult | None,
    replacement_flow: SuricataSourceReplacementFlowResult | None,
) -> SuricataLiveFetcherGateResult:
    policy = policy or {}
    policy_version = str(policy.get("policy_version") or POLICY_VERSION)
    evaluated_at = str(policy.get("evaluated_at") or "")
    human_approval_id = str(policy.get("human_approval_id") or "")
    live_fetch_enabled = policy.get("live_fetch_enabled") is True
    explicit_policy_flag = policy.get("allow_live_network_fetcher") is True

    if not live_fetch_enabled:
        return _blocked("SURICATA_LIVE_FETCH_DISABLED", policy_version, False, human_approval_id, evaluated_at)
    if not explicit_policy_flag:
        return _blocked("SURICATA_LIVE_FETCH_POLICY_FLAG_DISABLED", policy_version, live_fetch_enabled, human_approval_id, evaluated_at)
    if not human_approval_id:
        return _blocked("SURICATA_LIVE_FETCH_HUMAN_APPROVAL_MISSING", policy_version, live_fetch_enabled, human_approval_id, evaluated_at)
    if not evaluated_at:
        return _blocked("SURICATA_LIVE_FETCH_POLICY_MALFORMED", policy_version, live_fetch_enabled, human_approval_id, evaluated_at)
    if source_registry is None:
        return _blocked("SURICATA_LIVE_FETCH_SOURCE_REGISTRY_MISSING", policy_version, live_fetch_enabled, human_approval_id, evaluated_at)
    if not source_registry.approved:
        return _blocked(source_registry.reason, policy_version, live_fetch_enabled, human_approval_id, evaluated_at)
    if trust_anchor is None or trust_anchor_finalizer is None:
        return _blocked("SURICATA_LIVE_FETCH_TRUST_ANCHOR_MISSING", policy_version, live_fetch_enabled, human_approval_id, evaluated_at)
    if not trust_anchor.approved:
        return _blocked(trust_anchor.reason, policy_version, live_fetch_enabled, human_approval_id, evaluated_at)
    if not trust_anchor_finalizer.approved:
        return _blocked(trust_anchor_finalizer.finalizer_reason, policy_version, live_fetch_enabled, human_approval_id, evaluated_at)
    if fetch_receipt is None:
        return _blocked("SURICATA_LIVE_FETCH_RECEIPT_MISSING", policy_version, live_fetch_enabled, human_approval_id, evaluated_at)
    if not fetch_receipt.approved:
        return _blocked(fetch_receipt.reason, policy_version, live_fetch_enabled, human_approval_id, evaluated_at)
    if replacement_flow is None:
        return _blocked("SURICATA_LIVE_FETCH_REPLACEMENT_FLOW_MISSING", policy_version, live_fetch_enabled, human_approval_id, evaluated_at)
    if not replacement_flow.approved:
        return _blocked(replacement_flow.reason, policy_version, live_fetch_enabled, human_approval_id, evaluated_at)

    if (
        source_registry.approved_policy_version != policy_version
        or trust_anchor.policy_version != policy_version
        or fetch_receipt.source_registry_hash != source_registry.evidence_hash
        or replacement_flow.policy_version != policy_version
    ):
        return _blocked("SURICATA_LIVE_FETCH_POLICY_MISMATCH", policy_version, live_fetch_enabled, human_approval_id, evaluated_at)
    if not _all_hashes_valid(
        source_registry.evidence_hash,
        trust_anchor.evidence_hash,
        trust_anchor_finalizer.evidence_hash,
        fetch_receipt.evidence_hash,
        replacement_flow.replacement_flow_hash,
    ):
        return _blocked("SURICATA_LIVE_FETCH_MALFORMED_EVIDENCE", policy_version, live_fetch_enabled, human_approval_id, evaluated_at)

    payload = _payload(
        approved=True,
        blocked=False,
        decision="ALLOW",
        reason="SURICATA_LIVE_FETCH_GATE_APPROVED",
        policy_version=policy_version,
        live_fetch_enabled=live_fetch_enabled,
        human_approval_id=human_approval_id,
        source_registry_hash=source_registry.evidence_hash,
        trust_anchor_hash=trust_anchor_finalizer.evidence_hash,
        fetch_receipt_hash=fetch_receipt.evidence_hash,
        replacement_flow_hash=replacement_flow.replacement_flow_hash,
        evaluated_at=evaluated_at,
    )
    return SuricataLiveFetcherGateResult(
        approved=True,
        blocked=False,
        decision="ALLOW",
        reason="SURICATA_LIVE_FETCH_GATE_APPROVED",
        policy_version=policy_version,
        live_fetch_enabled=True,
        human_approval_id=human_approval_id,
        source_registry_hash=source_registry.evidence_hash,
        trust_anchor_hash=trust_anchor_finalizer.evidence_hash,
        fetch_receipt_hash=fetch_receipt.evidence_hash,
        replacement_flow_hash=replacement_flow.replacement_flow_hash,
        evaluated_at=evaluated_at,
        evidence_hash=hash_payload(payload),
    )


def _blocked(
    reason: str,
    policy_version: str,
    live_fetch_enabled: bool,
    human_approval_id: str,
    evaluated_at: str,
) -> SuricataLiveFetcherGateResult:
    payload = _payload(
        approved=False,
        blocked=True,
        decision="BLOCK",
        reason=reason,
        policy_version=policy_version or POLICY_VERSION,
        live_fetch_enabled=live_fetch_enabled,
        human_approval_id=human_approval_id,
        source_registry_hash="",
        trust_anchor_hash="",
        fetch_receipt_hash="",
        replacement_flow_hash="",
        evaluated_at=evaluated_at,
    )
    return SuricataLiveFetcherGateResult(
        approved=False,
        blocked=True,
        decision="BLOCK",
        reason=reason,
        policy_version=policy_version or POLICY_VERSION,
        live_fetch_enabled=live_fetch_enabled,
        human_approval_id=human_approval_id,
        source_registry_hash="",
        trust_anchor_hash="",
        fetch_receipt_hash="",
        replacement_flow_hash="",
        evaluated_at=evaluated_at,
        evidence_hash=hash_payload(payload),
    )


def _all_hashes_valid(*values: str) -> bool:
    return all(is_sha256_ref(value) for value in values)


def _payload(
    *,
    approved: bool,
    blocked: bool,
    decision: str,
    reason: str,
    policy_version: str,
    live_fetch_enabled: bool,
    human_approval_id: str,
    source_registry_hash: str,
    trust_anchor_hash: str,
    fetch_receipt_hash: str,
    replacement_flow_hash: str,
    evaluated_at: str,
) -> dict[str, Any]:
    return {
        "approved": approved,
        "blocked": blocked,
        "decision": decision,
        "reason": reason,
        "policy_version": policy_version,
        "live_fetch_enabled": live_fetch_enabled,
        "human_approval_id": human_approval_id,
        "source_registry_hash": source_registry_hash,
        "trust_anchor_hash": trust_anchor_hash,
        "fetch_receipt_hash": fetch_receipt_hash,
        "replacement_flow_hash": replacement_flow_hash,
        "evaluated_at": evaluated_at,
        "validator_policy_version": POLICY_VERSION,
        "network_call_performed": False,
    }
