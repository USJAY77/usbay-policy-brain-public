"""Hash-only final publication decision report generation."""

from __future__ import annotations

from datetime import datetime, timezone

from publication.models import (
    BlockReason,
    FinalPublicationReport,
    PublicationDecision,
    PublicationDecisionResult,
    RegistryRecord,
    is_sha256_ref,
)


REPORT_HASH_FIELDS = {
    "evidence_chain_verification_hash": "evidence_chain_verification_hash",
    "audit_hash": "audit_hash",
    "connector_gate_hash": "connector_gate_hash",
    "human_approval_hash": "approval_validation_hash",
    "sensitive_scan_hash": "sensitive_scan_hash",
    "classification_hash": "classification_hash",
    "registry_hash": "registry_hash",
}


def generate_final_publication_report(
    *,
    record: RegistryRecord | None,
    decision_result: PublicationDecisionResult | None,
    created_at: str | None = None,
) -> FinalPublicationReport:
    timestamp = created_at or datetime.now(timezone.utc).isoformat()
    if record is None or decision_result is None:
        return _incomplete_report(
            record=record,
            policy_version=(decision_result.audit.policy_version if decision_result else "UNKNOWN"),
            created_at=timestamp,
        )

    hashes = _extract_required_hashes(decision_result)
    if hashes is None:
        return _incomplete_report(
            record=record,
            policy_version=record.policy_version,
            created_at=timestamp,
        )

    return FinalPublicationReport(
        artifact_id=record.artifact_id,
        artifact_version=record.version,
        target_channel=record.target_channel,
        final_decision=decision_result.decision,
        block_reason=decision_result.block_reason,
        policy_version=record.policy_version,
        created_at=timestamp,
        **hashes,
    )


def _extract_required_hashes(decision_result: PublicationDecisionResult) -> dict[str, str] | None:
    evidence_hashes = decision_result.audit.evidence_hashes
    extracted: dict[str, str] = {
        "audit_hash": decision_result.audit.audit_hash,
    }
    for report_field, evidence_key in REPORT_HASH_FIELDS.items():
        if report_field == "audit_hash":
            continue
        value = evidence_hashes.get(evidence_key)
        if not is_sha256_ref(value):
            return None
        extracted[report_field] = value
    if not is_sha256_ref(extracted["audit_hash"]):
        return None
    suricata_hash = evidence_hashes.get("suricata_evidence_hash", "")
    if suricata_hash:
        if not is_sha256_ref(suricata_hash):
            return None
        extracted["suricata_evidence_hash"] = suricata_hash
        extracted["suricata_policy_version"] = evidence_hashes.get("suricata_policy_version", "")
        extracted["suricata_reason"] = evidence_hashes.get("suricata_reason", "")
        extracted["suricata_threshold"] = evidence_hashes.get("suricata_threshold", "")
        extracted["suricata_decision"] = evidence_hashes.get("suricata_decision", "")
        signing_authority_hash = evidence_hashes.get("suricata_signing_authority_hash", "")
        if signing_authority_hash:
            if not is_sha256_ref(signing_authority_hash):
                return None
            extracted["suricata_signing_authority_hash"] = signing_authority_hash
            extracted["suricata_signing_authority_status"] = evidence_hashes.get("suricata_signing_authority_status", "")
        live_fetcher_gate_hash = evidence_hashes.get("suricata_live_fetcher_gate_hash", "")
        if live_fetcher_gate_hash:
            if not is_sha256_ref(live_fetcher_gate_hash):
                return None
            extracted["suricata_live_fetcher_gate_hash"] = live_fetcher_gate_hash
            extracted["suricata_live_fetcher_policy_version"] = evidence_hashes.get("suricata_live_fetcher_policy_version", "")
            extracted["suricata_live_fetcher_decision"] = evidence_hashes.get("suricata_live_fetcher_decision", "")
            extracted["suricata_live_fetcher_reason"] = evidence_hashes.get("suricata_live_fetcher_reason", "")
            extracted["suricata_live_fetcher_timestamp"] = evidence_hashes.get("suricata_live_fetcher_timestamp", "")
        live_network_fetch_hash = evidence_hashes.get("suricata_live_network_fetch_hash", "")
        if live_network_fetch_hash:
            if not is_sha256_ref(live_network_fetch_hash):
                return None
            bundle_hash = evidence_hashes.get("suricata_live_network_bundle_hash", "")
            trust_fingerprint = evidence_hashes.get("suricata_live_network_trust_fingerprint", "")
            if not is_sha256_ref(bundle_hash) or not is_sha256_ref(trust_fingerprint):
                return None
            extracted["suricata_live_network_fetch_hash"] = live_network_fetch_hash
            extracted["suricata_live_network_bundle_hash"] = bundle_hash
            extracted["suricata_live_network_timestamp"] = evidence_hashes.get("suricata_live_network_timestamp", "")
            extracted["suricata_live_network_policy_version"] = evidence_hashes.get("suricata_live_network_policy_version", "")
            extracted["suricata_live_network_trust_fingerprint"] = trust_fingerprint
            extracted["suricata_live_network_decision"] = evidence_hashes.get("suricata_live_network_decision", "")
            extracted["suricata_live_network_reason"] = evidence_hashes.get("suricata_live_network_reason", "")
        connector_hash = evidence_hashes.get("suricata_publication_connector_hash", "")
        if connector_hash:
            if not is_sha256_ref(connector_hash):
                return None
            connector_trust = evidence_hashes.get("suricata_publication_connector_trust_fingerprint", "")
            if not is_sha256_ref(connector_trust):
                return None
            extracted["suricata_publication_connector_hash"] = connector_hash
            extracted["suricata_publication_connector_policy_version"] = evidence_hashes.get("suricata_publication_connector_policy_version", "")
            extracted["suricata_publication_connector_trust_fingerprint"] = connector_trust
            extracted["suricata_publication_connector_decision"] = evidence_hashes.get("suricata_publication_connector_decision", "")
            extracted["suricata_publication_connector_reason"] = evidence_hashes.get("suricata_publication_connector_reason", "")
            extracted["suricata_publication_connector_timestamp"] = evidence_hashes.get("suricata_publication_connector_timestamp", "")
            extracted["suricata_publication_connector_nonce"] = evidence_hashes.get("suricata_publication_connector_nonce", "")
            extracted["suricata_publication_connector_version"] = evidence_hashes.get("suricata_publication_connector_version", "")
    return extracted


def _incomplete_report(
    *,
    record: RegistryRecord | None,
    policy_version: str,
    created_at: str,
) -> FinalPublicationReport:
    return FinalPublicationReport(
        artifact_id=record.artifact_id if record is not None else "UNKNOWN_ARTIFACT",
        artifact_version=record.version if record is not None else "UNKNOWN_VERSION",
        target_channel=record.target_channel if record is not None else "UNKNOWN_CHANNEL",
        final_decision=PublicationDecision.BLOCK_PUBLICATION,
        block_reason=BlockReason.REPORT_INCOMPLETE,
        policy_version=policy_version or "UNKNOWN",
        evidence_chain_verification_hash="",
        audit_hash="",
        connector_gate_hash="",
        human_approval_hash="",
        sensitive_scan_hash="",
        classification_hash="",
        registry_hash="",
        created_at=created_at,
    )
