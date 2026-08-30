"""Fail-closed Suricata severity threshold policy gate."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from publication.models import SuricataPolicyGateResult, hash_payload, is_sha256_ref
from publication.suricata_evidence_adapter import SuricataEvidenceResult


POLICY_VERSION = "USBAY-SURICATA-002"
MAX_SURICATA_SEVERITY = 4


def evaluate_suricata_policy_gate(
    evidence: SuricataEvidenceResult | None,
    policy_config: Mapping[str, Any] | None,
) -> SuricataPolicyGateResult:
    if policy_config is None:
        return _blocked("SURICATA_POLICY_MISSING", None, -1, POLICY_VERSION)

    policy_version = str(policy_config.get("policy_version") or "")
    if not policy_version:
        return _blocked("SURICATA_POLICY_VERSION_MISSING", None, -1, POLICY_VERSION)

    threshold = policy_config.get("severity_threshold")
    if not isinstance(threshold, int) or threshold < 0 or threshold > MAX_SURICATA_SEVERITY:
        return _blocked("SURICATA_THRESHOLD_INVALID", None, -1, policy_version)

    if str(policy_config.get("action_on_threshold_exceeded") or "") != "BLOCK":
        return _blocked("SURICATA_ACTION_INVALID", None, threshold, policy_version)

    if evidence is None:
        return _blocked("SURICATA_EVIDENCE_MISSING", None, threshold, policy_version)

    if evidence.severity is None or not isinstance(evidence.severity, int):
        return _blocked("SURICATA_SEVERITY_MISSING", None, threshold, policy_version)

    if not is_sha256_ref(evidence.evidence_hash):
        return _blocked("SURICATA_EVIDENCE_HASH_MALFORMED", evidence.severity, threshold, policy_version)

    if evidence.evidence_hash != _expected_adapter_hash(evidence):
        return _blocked("SURICATA_EVIDENCE_HASH_MISMATCH", evidence.severity, threshold, policy_version)

    if not evidence.accepted:
        return _blocked("SURICATA_EVIDENCE_NOT_ACCEPTED", evidence.severity, threshold, policy_version)

    approved = evidence.severity < threshold
    reason = "SURICATA_POLICY_GATE_ALLOWED" if approved else "SURICATA_POLICY_THRESHOLD_BLOCKED"
    return SuricataPolicyGateResult(
        approved=approved,
        severity=evidence.severity,
        threshold=threshold,
        evidence_hash=_gate_hash(
            approved=approved,
            severity=evidence.severity,
            threshold=threshold,
            source_evidence_hash=evidence.evidence_hash,
            policy_version=policy_version,
            reason=reason,
        ),
        policy_version=policy_version,
        reason=reason,
    )


def _expected_adapter_hash(evidence: SuricataEvidenceResult) -> str:
    return hash_payload(
        {
            "accepted": evidence.accepted,
            "blocked": evidence.blocked,
            "severity": evidence.severity,
            "threshold": evidence.threshold,
            "redacted_event": evidence.redacted_event,
            "policy_version": evidence.policy_version,
            "reason": evidence.reason,
        }
    )


def _blocked(reason: str, severity: int | None, threshold: int, policy_version: str) -> SuricataPolicyGateResult:
    return SuricataPolicyGateResult(
        approved=False,
        severity=severity,
        threshold=threshold,
        evidence_hash=_gate_hash(
            approved=False,
            severity=severity,
            threshold=threshold,
            source_evidence_hash="",
            policy_version=policy_version or POLICY_VERSION,
            reason=reason,
        ),
        policy_version=policy_version or POLICY_VERSION,
        reason=reason,
    )


def _gate_hash(
    *,
    approved: bool,
    severity: int | None,
    threshold: int,
    source_evidence_hash: str,
    policy_version: str,
    reason: str,
) -> str:
    return hash_payload(
        {
            "approved": approved,
            "severity": severity,
            "threshold": threshold,
            "source_evidence_hash": source_evidence_hash,
            "policy_version": policy_version,
            "reason": reason,
        }
    )
