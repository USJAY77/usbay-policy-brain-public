"""Final local runtime publication decision aggregator."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from publication.audit_persistence import LocalAuditStore, create_publication_audit_event
from publication.classification import classify_registry_record
from publication.connector_gate import evaluate_connector_gate
from publication.decision_engine import evaluate_publication_decision
from publication.evidence_consistency_gate import validate_evidence_consistency_gate
from publication.evidence_chain import verify_evidence_chain
from publication.evidence_seal import REQUIRED_SEAL_ORDER, validate_evidence_seal
from publication.final_report import generate_final_publication_report
from publication.finalization_gate import evaluate_finalization_gate
from publication.human_approval import resolve_human_approval
from publication.models import (
    ApprovalEvidence,
    ApprovalState,
    AuditPersistenceResult,
    BlockReason,
    CommitScopeResult,
    EvidenceChainEntry,
    EvidenceChainStage,
    FinalPublicationReport,
    PolicyBundleReadinessResult,
    PolicyBundleValidationResult,
    PublicationDecision,
    PublicationDecisionResult,
    RegistryRecord,
    SuricataPolicyGateResult,
    hash_payload,
    is_sha256_ref,
)
from publication.publication_lock import evaluate_publication_lock
from publication.publication_lock_release import evaluate_publication_lock_release
from publication.publication_release_blocker import validate_publication_release_blocker
from publication.release_blocker_integrity import validate_release_blocker_integrity
from publication.registry_validator import validate_registry_record
from publication.sensitive_data_scanner import scan_publication_content
from publication.suricata_evidence_adapter import SuricataEvidenceResult
from publication.suricata_external_signing_authority import SuricataExternalSigningAuthorityResult
from publication.suricata_fetch_receipt import SuricataFetchReceiptResult
from publication.suricata_fetch_receipt_finalizer import SuricataFetchReceiptFinalizerResult
from publication.suricata_live_fetcher_gate import SuricataLiveFetcherGateResult
from publication.suricata_live_network_fetcher import SuricataLiveNetworkFetchResult
from publication.suricata_policy_registry import SuricataPolicyRegistryResult
from publication.suricata_publication_connector import SuricataPublicationConnectorResult
from publication.suricata_rule_signature import SuricataRuleSignatureResult
from publication.suricata_rule_source_fetcher import LocalRuleSourceFetchResult
from publication.suricata_source_replacement_flow import SuricataSourceReplacementFlowResult
from publication.suricata_trust_anchor_store import SuricataTrustAnchorFinalizerResult, SuricataTrustAnchorResult


def aggregate_runtime_publication_decision(
    record: RegistryRecord | None,
    *,
    content: str | None,
    approvals: Iterable[ApprovalEvidence | dict[str, Any]] | None,
    registry_schema: dict[str, Any] | None = None,
    classification_policy: dict[str, Any] | None = None,
    approval_policy: dict[str, Any] | None = None,
    connector_policy: dict[str, object] | None = None,
    active_policy_version: str = "1.0",
    now: datetime | None = None,
    audit_store: LocalAuditStore | None = None,
    create_audit: bool = True,
    automatic_publication_requested: bool = False,
    scan_metadata: Mapping[str, Any] | None = None,
    commit_scope_result: CommitScopeResult | None = None,
    policy_bundle_result: PolicyBundleValidationResult | None = None,
    policy_bundle_readiness: PolicyBundleReadinessResult | None = None,
    suricata_evidence: SuricataEvidenceResult | None = None,
    suricata_policy_gate: SuricataPolicyGateResult | None = None,
    suricata_policy_registry: SuricataPolicyRegistryResult | None = None,
    suricata_rule_source: SuricataRuleSignatureResult | None = None,
    suricata_trust_anchor: SuricataTrustAnchorResult | None = None,
    suricata_trust_anchor_finalizer: SuricataTrustAnchorFinalizerResult | None = None,
    suricata_signing_authority: SuricataExternalSigningAuthorityResult | None = None,
    suricata_live_rule_source_enabled: bool = False,
    suricata_rule_source_fetcher: LocalRuleSourceFetchResult | None = None,
    suricata_fetch_receipt: SuricataFetchReceiptResult | None = None,
    suricata_fetch_finalizer: SuricataFetchReceiptFinalizerResult | None = None,
    suricata_replacement_mode_enabled: bool = False,
    suricata_replacement_flow: SuricataSourceReplacementFlowResult | None = None,
    suricata_live_fetcher_gate: SuricataLiveFetcherGateResult | None = None,
    suricata_live_network_fetch: SuricataLiveNetworkFetchResult | None = None,
    suricata_publication_connector: SuricataPublicationConnectorResult | None = None,
) -> PublicationDecisionResult:
    registry_result = validate_registry_record(
        record,
        schema=registry_schema,
        active_policy_version=active_policy_version,
    )
    if not registry_result.publish_allowed:
        return registry_result
    assert record is not None

    classification_result = classify_registry_record(record, policy=classification_policy)
    if not classification_result.publish_allowed:
        return classification_result

    scan_result = scan_publication_content(
        artifact_id=record.artifact_id,
        content=content,  # type: ignore[arg-type]
        policy_version=record.policy_version,
        metadata=scan_metadata,
    )
    if not scan_result.passed:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=scan_result.block_reason,
            decision=PublicationDecision.SENSITIVE_DATA_BLOCKED,
            policy_version=record.policy_version,
            evidence_hashes=scan_result.audit.evidence_hashes,
            details=tuple(category.value for category in scan_result.detected_categories),
        )

    approval_result = resolve_human_approval(
        record=record,
        approvals=approvals,
        policy=approval_policy,
        now=now,
    )
    if not approval_result.passed:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=approval_result.block_reason,
            decision=PublicationDecision.NEEDS_HUMAN_REVIEW,
            policy_version=record.policy_version,
            evidence_hashes=approval_result.audit.evidence_hashes,
            details=approval_result.reviewer_references,
        )

    audit_result = _create_or_block_audit(
        record=record,
        registry_result=registry_result,
        classification_result=classification_result,
        scan_hash=scan_result.audit.evidence_hashes["sensitive_scan_hash"],
        approval_hash=approval_result.audit.evidence_hashes["approval_validation_hash"],
        audit_store=audit_store,
        create_audit=create_audit,
    )
    if not audit_result.persisted:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=audit_result.block_reason,
            decision=PublicationDecision.AUDIT_EVIDENCE_MISSING,
            policy_version=record.policy_version,
            evidence_hashes=audit_result.audit.evidence_hashes,
        )

    connector_result = evaluate_connector_gate(
        record=record,
        registry_result=registry_result,
        classification_result=classification_result,
        sensitive_scan_result=scan_result,
        approval_result=approval_result,
        audit_result=audit_result,
        connector_policy=connector_policy,
        automatic_publication_requested=automatic_publication_requested,
    )

    suricata_hashes = _suricata_hashes_or_block(
        record,
        suricata_evidence,
        suricata_policy_gate,
        suricata_policy_registry,
        suricata_rule_source,
        suricata_trust_anchor,
        suricata_trust_anchor_finalizer,
        suricata_signing_authority,
        suricata_live_rule_source_enabled,
        suricata_rule_source_fetcher,
        suricata_fetch_receipt,
        suricata_fetch_finalizer,
        suricata_replacement_mode_enabled,
        suricata_replacement_flow,
        suricata_live_fetcher_gate,
        suricata_live_network_fetch,
        suricata_publication_connector,
    )
    if isinstance(suricata_hashes, PublicationDecisionResult):
        return suricata_hashes

    final_result = evaluate_publication_decision(
        record,
        registry_schema=registry_schema,
        classification_policy=classification_policy,
        active_policy_version=active_policy_version,
        approval_state=ApprovalState.APPROVED,
        sensitive_scan_result=scan_result,
        approval_result=approval_result,
        audit_result=audit_result,
        connector_gate_result=connector_result,
    )
    if not final_result.publish_allowed:
        return final_result

    evidence_chain = verify_evidence_chain(
        record=record,
        entries=_build_evidence_chain_entries(
            record=record,
            registry_hash=registry_result.audit.evidence_hashes.get("registry_hash", ""),
            classification_hash=classification_result.audit.evidence_hashes.get("classification_hash", ""),
            sensitive_scan_hash=scan_result.audit.evidence_hashes.get("sensitive_scan_hash", ""),
            approval_hash=approval_result.audit.evidence_hashes.get("approval_validation_hash", ""),
            runtime_validator_hash=audit_result.event.validator_hash if audit_result.event else "",
            connector_gate_hash=connector_result.audit.evidence_hashes.get("connector_gate_hash", ""),
            audit_persistence_hash=audit_result.audit.evidence_hashes.get("evidence_chain_hash", ""),
            final_aggregator_hash=final_result.audit.audit_hash,
        ),
    )
    if not evidence_chain.verified:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=evidence_chain.block_reason,
            policy_version=record.policy_version,
            evidence_hashes=evidence_chain.audit.evidence_hashes,
        )

    if commit_scope_result is None or not commit_scope_result.approved:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.COMMIT_SCOPE_NOT_APPROVED,
            policy_version=record.policy_version,
            evidence_hashes={
                "commit_scope_evidence_hash": (
                    commit_scope_result.evidence_hash if commit_scope_result is not None else hash_payload("MISSING_COMMIT_SCOPE")
                )
            },
        )

    if policy_bundle_result is None or not policy_bundle_result.valid:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.POLICY_BUNDLE_NOT_APPROVED,
            policy_version=record.policy_version,
            evidence_hashes={
                "policy_bundle_evidence_hash": (
                    policy_bundle_result.evidence_hash if policy_bundle_result is not None else hash_payload("MISSING_POLICY_BUNDLE")
                )
            },
        )

    if policy_bundle_readiness is None or not policy_bundle_readiness.ready:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.POLICY_BUNDLE_NOT_APPROVED,
            policy_version=record.policy_version,
            evidence_hashes={
                "policy_bundle_readiness_evidence_hash": (
                    policy_bundle_readiness.evidence_hash
                    if policy_bundle_readiness is not None
                    else hash_payload("MISSING_POLICY_BUNDLE_READINESS")
                )
            },
        )

    evidence_hashes = {
        **final_result.audit.evidence_hashes,
        **evidence_chain.audit.evidence_hashes,
        **suricata_hashes,
        "commit_scope_evidence_hash": commit_scope_result.evidence_hash,
        "policy_bundle_evidence_hash": policy_bundle_result.evidence_hash,
        "policy_bundle_hash": policy_bundle_result.bundle_hash,
        "policy_bundle_readiness_evidence_hash": policy_bundle_readiness.evidence_hash,
    }
    provisional_ready_result = PublicationDecisionResult.allowed(
        artifact_id=record.artifact_id,
        policy_version=record.policy_version,
        evidence_hashes=evidence_hashes,
        details=(*final_result.details, "evidence chain verified"),
    )
    finalization_gate = evaluate_finalization_gate(
        runtime_aggregator_result=provisional_ready_result,
        commit_scope_result=commit_scope_result,
        policy_bundle_readiness_result=policy_bundle_readiness,
        evidence_chain_result=evidence_chain,
    )
    if not finalization_gate.ready:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.FINALIZATION_GATE_BLOCKED,
            policy_version=record.policy_version,
            evidence_hashes={"finalization_gate_evidence_hash": finalization_gate.evidence_hash},
            details=finalization_gate.missing_controls,
        )
    publication_lock = evaluate_publication_lock(
        finalization_gate_result=finalization_gate,
        policy_bundle_readiness_result=policy_bundle_readiness,
        commit_scope_result=commit_scope_result,
        evidence_chain_result=evidence_chain,
        final_publication_report=generate_final_publication_report(
            record=record,
            decision_result=provisional_ready_result,
        ),
        automatic_publication_requested=automatic_publication_requested,
        external_connector_requested=False,
    )
    if not publication_lock.locked:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.PUBLICATION_LOCK_BLOCKED,
            policy_version=record.policy_version,
            evidence_hashes={"publication_lock_evidence_hash": publication_lock.evidence_hash},
            details=publication_lock.missing_controls,
        )
    publication_lock_release = evaluate_publication_lock_release(
        finalization_gate_result=finalization_gate,
        publication_lock_result=publication_lock,
        automatic_publication_requested=automatic_publication_requested,
        external_connector_requested=False,
    )
    if not publication_lock_release.approved:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.PUBLICATION_LOCK_BLOCKED,
            policy_version=record.policy_version,
            evidence_hashes={"publication_lock_release_evidence_hash": publication_lock_release.evidence_hash},
            details=publication_lock_release.rejected_reasons,
        )
    final_publication_report = generate_final_publication_report(
        record=record,
        decision_result=provisional_ready_result,
    )
    publication_release_blocker = validate_publication_release_blocker(
        commit_scope_result=commit_scope_result,
        policy_bundle_readiness_result=policy_bundle_readiness,
        finalization_gate_result=finalization_gate,
        publication_lock_result=publication_lock,
        publication_lock_release_result=publication_lock_release,
        final_publication_report=final_publication_report,
        release_hash=publication_lock_release.evidence_hash,
        automatic_publication_requested=automatic_publication_requested,
        connector_execution_requested=False,
        http_api_publication_requested=False,
    )
    if not publication_release_blocker.approved:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.PUBLICATION_RELEASE_BLOCKED,
            policy_version=record.policy_version,
            evidence_hashes={"publication_release_blocker_evidence_hash": publication_release_blocker.evidence_hash},
            details=publication_release_blocker.rejected_reasons,
        )
    release_blocker_integrity = validate_release_blocker_integrity(
        commit_scope_result=commit_scope_result,
        policy_bundle_readiness_result=policy_bundle_readiness,
        finalization_gate_result=finalization_gate,
        publication_lock_result=publication_lock,
        publication_lock_release_result=publication_lock_release,
        publication_release_blocker_result=publication_release_blocker,
        final_publication_report=final_publication_report,
        release_hash=publication_lock_release.evidence_hash,
        automatic_publication_requested=automatic_publication_requested,
        connector_execution_requested=False,
        http_api_publication_requested=False,
    )
    if not release_blocker_integrity.approved:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.PUBLICATION_RELEASE_BLOCKED,
            policy_version=record.policy_version,
            evidence_hashes={"release_blocker_integrity_evidence_hash": release_blocker_integrity.evidence_hash},
            details=release_blocker_integrity.rejected_reasons,
        )
    runtime_generation_id = f"{record.artifact_id}:{record.version}"
    evidence_consistency = validate_evidence_consistency_gate(
        components=_build_evidence_consistency_components(
            record=record,
            runtime_generation_id=runtime_generation_id,
            registry_hash=registry_result.audit.evidence_hashes.get("registry_hash", ""),
            classification_hash=classification_result.audit.evidence_hashes.get("classification_hash", ""),
            sensitive_scan_hash=scan_result.audit.evidence_hashes.get("sensitive_scan_hash", ""),
            approval_hash=approval_result.audit.evidence_hashes.get("approval_validation_hash", ""),
            audit_persistence_hash=audit_result.audit.evidence_hashes.get("evidence_chain_hash", ""),
            connector_gate_hash=connector_result.audit.evidence_hashes.get("connector_gate_hash", ""),
            runtime_aggregator_hash=final_result.audit.audit_hash,
            evidence_chain_hash=evidence_chain.audit.evidence_hashes.get("evidence_chain_verification_hash", ""),
            final_report_hash=final_publication_report.report_hash,
            commit_scope_hash=commit_scope_result.evidence_hash,
            policy_bundle_hash=policy_bundle_readiness.evidence_hash,
            finalization_hash=finalization_gate.evidence_hash,
            publication_lock_hash=publication_lock.evidence_hash,
            lock_release_hash=publication_lock_release.evidence_hash,
            release_blocker_hash=publication_release_blocker.evidence_hash,
            release_blocker_integrity_hash=release_blocker_integrity.evidence_hash,
        ),
        runtime_policy_version=record.policy_version,
        runtime_generation_id=runtime_generation_id,
    )
    if not evidence_consistency.approved:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.PUBLICATION_RELEASE_BLOCKED,
            policy_version=record.policy_version,
            evidence_hashes={"evidence_consistency_hash": evidence_consistency.consistency_hash},
            details=(evidence_consistency.reason, evidence_consistency.failed_component),
        )
    evidence_seal = validate_evidence_seal(
        seal_inputs={
            "policy_bundle_hash": policy_bundle_result.bundle_hash,
            "evidence_chain_hash": evidence_chain.audit.evidence_hashes.get("evidence_chain_verification_hash", ""),
            "publication_lock_hash": publication_lock.evidence_hash,
            "release_hash": publication_lock_release.evidence_hash,
            "consistency_hash": evidence_consistency.consistency_hash,
            "finalization_hash": finalization_gate.evidence_hash,
            "timestamp_hash": hash_payload(
                {
                    "artifact_id": record.artifact_id,
                    "artifact_version": record.version,
                    "policy_version": record.policy_version,
                }
            ),
        },
        ordered_hash_names=REQUIRED_SEAL_ORDER,
        policy_version=record.policy_version,
        publication_contract_version="PUBGOV-013-035",
        expected_policy_version=record.policy_version,
        expected_publication_contract_version="PUBGOV-013-035",
    )
    if not evidence_seal.approved:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.PUBLICATION_RELEASE_BLOCKED,
            policy_version=record.policy_version,
            evidence_hashes={"evidence_seal_hash": evidence_seal.evidence_seal_hash},
            details=(evidence_seal.reason,),
        )

    return PublicationDecisionResult.allowed(
        artifact_id=record.artifact_id,
        policy_version=record.policy_version,
        evidence_hashes={
            **evidence_hashes,
            "finalization_gate_evidence_hash": finalization_gate.evidence_hash,
            "publication_lock_evidence_hash": publication_lock.evidence_hash,
            "publication_lock_id": publication_lock.lock_id,
            "publication_lock_release_evidence_hash": publication_lock_release.evidence_hash,
            "publication_lock_release_id": publication_lock_release.release_id,
            "publication_release_blocker_evidence_hash": publication_release_blocker.evidence_hash,
            "publication_release_block_id": publication_release_blocker.release_block_id,
            "release_blocker_integrity_evidence_hash": release_blocker_integrity.evidence_hash,
            "release_blocker_integrity_id": release_blocker_integrity.integrity_id,
            "evidence_consistency_hash": evidence_consistency.consistency_hash,
            "evidence_seal_hash": evidence_seal.evidence_seal_hash,
        },
        details=(
            *final_result.details,
            "evidence chain verified",
            "finalization gate ready",
            "publication lock ready",
            "publication lock release approved",
            "publication release blocker approved",
            "release blocker integrity approved",
            "evidence consistency approved",
            "evidence seal approved",
        ),
    )


def aggregate_runtime_publication_report(
    record: RegistryRecord | None,
    *,
    content: str | None,
    approvals: Iterable[ApprovalEvidence | dict[str, Any]] | None,
    registry_schema: dict[str, Any] | None = None,
    classification_policy: dict[str, Any] | None = None,
    approval_policy: dict[str, Any] | None = None,
    connector_policy: dict[str, object] | None = None,
    active_policy_version: str = "1.0",
    now: datetime | None = None,
    audit_store: LocalAuditStore | None = None,
    create_audit: bool = True,
    automatic_publication_requested: bool = False,
    scan_metadata: Mapping[str, Any] | None = None,
    created_at: str | None = None,
    commit_scope_result: CommitScopeResult | None = None,
    policy_bundle_result: PolicyBundleValidationResult | None = None,
    policy_bundle_readiness: PolicyBundleReadinessResult | None = None,
    suricata_evidence: SuricataEvidenceResult | None = None,
    suricata_policy_gate: SuricataPolicyGateResult | None = None,
    suricata_policy_registry: SuricataPolicyRegistryResult | None = None,
    suricata_rule_source: SuricataRuleSignatureResult | None = None,
    suricata_trust_anchor: SuricataTrustAnchorResult | None = None,
    suricata_trust_anchor_finalizer: SuricataTrustAnchorFinalizerResult | None = None,
    suricata_signing_authority: SuricataExternalSigningAuthorityResult | None = None,
    suricata_live_rule_source_enabled: bool = False,
    suricata_rule_source_fetcher: LocalRuleSourceFetchResult | None = None,
    suricata_fetch_receipt: SuricataFetchReceiptResult | None = None,
    suricata_fetch_finalizer: SuricataFetchReceiptFinalizerResult | None = None,
    suricata_replacement_mode_enabled: bool = False,
    suricata_replacement_flow: SuricataSourceReplacementFlowResult | None = None,
    suricata_live_fetcher_gate: SuricataLiveFetcherGateResult | None = None,
    suricata_live_network_fetch: SuricataLiveNetworkFetchResult | None = None,
    suricata_publication_connector: SuricataPublicationConnectorResult | None = None,
) -> FinalPublicationReport:
    decision_result = aggregate_runtime_publication_decision(
        record,
        content=content,
        approvals=approvals,
        registry_schema=registry_schema,
        classification_policy=classification_policy,
        approval_policy=approval_policy,
        connector_policy=connector_policy,
        active_policy_version=active_policy_version,
        now=now,
        audit_store=audit_store,
        create_audit=create_audit,
        automatic_publication_requested=automatic_publication_requested,
        scan_metadata=scan_metadata,
        commit_scope_result=commit_scope_result,
        policy_bundle_result=policy_bundle_result,
        policy_bundle_readiness=policy_bundle_readiness,
        suricata_evidence=suricata_evidence,
        suricata_policy_gate=suricata_policy_gate,
        suricata_policy_registry=suricata_policy_registry,
        suricata_rule_source=suricata_rule_source,
        suricata_trust_anchor=suricata_trust_anchor,
        suricata_trust_anchor_finalizer=suricata_trust_anchor_finalizer,
        suricata_signing_authority=suricata_signing_authority,
        suricata_live_rule_source_enabled=suricata_live_rule_source_enabled,
        suricata_rule_source_fetcher=suricata_rule_source_fetcher,
        suricata_fetch_receipt=suricata_fetch_receipt,
        suricata_fetch_finalizer=suricata_fetch_finalizer,
        suricata_replacement_mode_enabled=suricata_replacement_mode_enabled,
        suricata_replacement_flow=suricata_replacement_flow,
        suricata_live_fetcher_gate=suricata_live_fetcher_gate,
        suricata_live_network_fetch=suricata_live_network_fetch,
        suricata_publication_connector=suricata_publication_connector,
    )
    return generate_final_publication_report(
        record=record,
        decision_result=decision_result,
        created_at=created_at,
    )


def _build_evidence_chain_entries(
    *,
    record: RegistryRecord,
    registry_hash: str,
    classification_hash: str,
    sensitive_scan_hash: str,
    approval_hash: str,
    runtime_validator_hash: str,
    connector_gate_hash: str,
    audit_persistence_hash: str,
    final_aggregator_hash: str,
) -> tuple[EvidenceChainEntry, ...]:
    def entry(stage: EvidenceChainStage, evidence_hash: str) -> EvidenceChainEntry:
        return EvidenceChainEntry(
            stage=stage,
            artifact_id=record.artifact_id,
            artifact_version=record.version,
            policy_version=record.policy_version,
            evidence_hash=evidence_hash,
        )

    return (
        entry(EvidenceChainStage.REGISTRY, registry_hash),
        entry(EvidenceChainStage.CLASSIFICATION, classification_hash),
        entry(EvidenceChainStage.SENSITIVE_DATA_SCAN, sensitive_scan_hash),
        entry(EvidenceChainStage.HUMAN_APPROVAL, approval_hash),
        entry(EvidenceChainStage.RUNTIME_VALIDATOR, runtime_validator_hash),
        entry(EvidenceChainStage.CONNECTOR_GATE, connector_gate_hash),
        entry(EvidenceChainStage.AUDIT_PERSISTENCE, audit_persistence_hash),
        entry(EvidenceChainStage.FINAL_AGGREGATOR, final_aggregator_hash),
    )


def _build_evidence_consistency_components(
    *,
    record: RegistryRecord,
    runtime_generation_id: str,
    registry_hash: str,
    classification_hash: str,
    sensitive_scan_hash: str,
    approval_hash: str,
    audit_persistence_hash: str,
    connector_gate_hash: str,
    runtime_aggregator_hash: str,
    evidence_chain_hash: str,
    final_report_hash: str,
    commit_scope_hash: str,
    policy_bundle_hash: str,
    finalization_hash: str,
    publication_lock_hash: str,
    lock_release_hash: str,
    release_blocker_hash: str,
    release_blocker_integrity_hash: str,
) -> tuple[dict[str, str], ...]:
    def component(name: str, evidence_hash: str, component_policy_version: str = "") -> dict[str, str]:
        return {
            "component": name,
            "evidence_hash": evidence_hash,
            "runtime_policy_version": record.policy_version,
            "runtime_generation_id": runtime_generation_id,
            "component_policy_version": component_policy_version,
        }

    return (
        component("registry", registry_hash),
        component("classification", classification_hash),
        component("sensitive_scan", sensitive_scan_hash),
        component("human_approval", approval_hash),
        component("audit_persistence", audit_persistence_hash),
        component("connector_gate", connector_gate_hash),
        component("runtime_aggregator", runtime_aggregator_hash),
        component("evidence_chain", evidence_chain_hash),
        component("final_publication_report", final_report_hash),
        component("commit_scope", commit_scope_hash, "USBAY-PUBGOV-024"),
        component("policy_bundle", policy_bundle_hash, record.policy_version),
        component("finalization_gate", finalization_hash, "USBAY-PUBGOV-027"),
        component("publication_lock", publication_lock_hash, "USBAY-PUBGOV-028"),
        component("lock_release", lock_release_hash, "USBAY-PUBGOV-029"),
        component("release_blocker", release_blocker_hash, "USBAY-PUBGOV-030"),
        component("release_blocker_integrity", release_blocker_integrity_hash, "USBAY-PUBGOV-031"),
    )


def _create_or_block_audit(
    *,
    record: RegistryRecord,
    registry_result: PublicationDecisionResult,
    classification_result: PublicationDecisionResult,
    scan_hash: str,
    approval_hash: str,
    audit_store: LocalAuditStore | None,
    create_audit: bool,
) -> AuditPersistenceResult:
    if not create_audit:
        return AuditPersistenceResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.AUDIT_EVENT_MISSING,
            policy_version=record.policy_version,
            evidence_hashes={"registry_hash": record.stable_hash()},
        )
    validator_hash = hash_payload(
        {
            "registry_audit_hash": registry_result.audit.audit_hash,
            "classification_audit_hash": classification_result.audit.audit_hash,
            "sensitive_scan_hash": scan_hash,
            "approval_validation_hash": approval_hash,
            "policy_version": record.policy_version,
        }
    )
    return create_publication_audit_event(
        record=record,
        decision=PublicationDecision.ALLOW_PUBLICATION,
        block_reason=BlockReason.NONE,
        sensitive_scan_hash=scan_hash,
        approval_hash=approval_hash,
        validator_hash=validator_hash,
        store=audit_store,
    )


def _suricata_hashes_or_block(
    record: RegistryRecord,
    suricata_evidence: SuricataEvidenceResult | None,
    suricata_policy_gate: SuricataPolicyGateResult | None,
    suricata_policy_registry: SuricataPolicyRegistryResult | None,
    suricata_rule_source: SuricataRuleSignatureResult | None,
    suricata_trust_anchor: SuricataTrustAnchorResult | None,
    suricata_trust_anchor_finalizer: SuricataTrustAnchorFinalizerResult | None,
    suricata_signing_authority: SuricataExternalSigningAuthorityResult | None,
    suricata_live_rule_source_enabled: bool,
    suricata_rule_source_fetcher: LocalRuleSourceFetchResult | None,
    suricata_fetch_receipt: SuricataFetchReceiptResult | None,
    suricata_fetch_finalizer: SuricataFetchReceiptFinalizerResult | None,
    suricata_replacement_mode_enabled: bool,
    suricata_replacement_flow: SuricataSourceReplacementFlowResult | None,
    suricata_live_fetcher_gate: SuricataLiveFetcherGateResult | None,
    suricata_live_network_fetch: SuricataLiveNetworkFetchResult | None,
    suricata_publication_connector: SuricataPublicationConnectorResult | None,
) -> dict[str, str] | PublicationDecisionResult:
    if suricata_evidence is None:
        return {}
    if suricata_trust_anchor is None:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
            decision=PublicationDecision.BLOCK_PUBLICATION,
            policy_version=record.policy_version,
            evidence_hashes={
                "suricata_evidence_hash": suricata_evidence.evidence_hash,
                "suricata_reason": "SURICATA_TRUST_ANCHOR_MISSING",
            },
            details=("SURICATA_TRUST_ANCHOR_MISSING",),
        )
    if not suricata_trust_anchor.approved:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
            decision=PublicationDecision.BLOCK_PUBLICATION,
            policy_version=record.policy_version,
            evidence_hashes={
                "suricata_trust_anchor_hash": suricata_trust_anchor.evidence_hash,
                "suricata_reason": suricata_trust_anchor.reason,
            },
            details=(suricata_trust_anchor.reason,),
        )
    if suricata_trust_anchor_finalizer is None:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
            decision=PublicationDecision.BLOCK_PUBLICATION,
            policy_version=record.policy_version,
            evidence_hashes={
                "suricata_trust_anchor_hash": suricata_trust_anchor.evidence_hash,
                "suricata_reason": "SURICATA_TRUST_ANCHOR_FINALIZER_MISSING",
            },
            details=("SURICATA_TRUST_ANCHOR_FINALIZER_MISSING",),
        )
    if not suricata_trust_anchor_finalizer.approved:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
            decision=PublicationDecision.BLOCK_PUBLICATION,
            policy_version=record.policy_version,
            evidence_hashes={
                "suricata_trust_anchor_finalizer_hash": suricata_trust_anchor_finalizer.evidence_hash,
                "suricata_reason": suricata_trust_anchor_finalizer.finalizer_reason,
            },
            details=(suricata_trust_anchor_finalizer.finalizer_reason,),
        )
    if suricata_live_rule_source_enabled:
        if suricata_fetch_finalizer is None:
            return PublicationDecisionResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
                decision=PublicationDecision.BLOCK_PUBLICATION,
                policy_version=record.policy_version,
                evidence_hashes={
                    "suricata_evidence_hash": suricata_evidence.evidence_hash,
                    "suricata_reason": "SURICATA_FETCH_FINALIZER_MISSING",
                },
                details=("SURICATA_FETCH_FINALIZER_MISSING",),
            )
        if not suricata_fetch_finalizer.approved:
            return PublicationDecisionResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
                decision=PublicationDecision.BLOCK_PUBLICATION,
                policy_version=record.policy_version,
                evidence_hashes={
                    "final_suricata_fetch_hash": suricata_fetch_finalizer.final_suricata_fetch_hash,
                    "suricata_reason": suricata_fetch_finalizer.reason,
                },
                details=(suricata_fetch_finalizer.reason,),
            )
        if suricata_fetch_receipt is None:
            return PublicationDecisionResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
                decision=PublicationDecision.BLOCK_PUBLICATION,
                policy_version=record.policy_version,
                evidence_hashes={
                    "suricata_evidence_hash": suricata_evidence.evidence_hash,
                    "suricata_reason": "SURICATA_FETCH_RECEIPT_MISSING",
                },
                details=("SURICATA_FETCH_RECEIPT_MISSING",),
            )
        if not suricata_fetch_receipt.approved:
            return PublicationDecisionResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
                decision=PublicationDecision.BLOCK_PUBLICATION,
                policy_version=record.policy_version,
                evidence_hashes={
                    "suricata_fetch_receipt_hash": suricata_fetch_receipt.evidence_hash,
                    "suricata_reason": suricata_fetch_receipt.reason,
                },
                details=(suricata_fetch_receipt.reason,),
            )
        if suricata_rule_source_fetcher is None:
            return PublicationDecisionResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
                decision=PublicationDecision.BLOCK_PUBLICATION,
                policy_version=record.policy_version,
                evidence_hashes={
                    "suricata_evidence_hash": suricata_evidence.evidence_hash,
                    "suricata_reason": "SURICATA_RULE_FETCH_MISSING",
                },
                details=("SURICATA_RULE_FETCH_MISSING",),
            )
        if not suricata_rule_source_fetcher.approved:
            return PublicationDecisionResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
                decision=PublicationDecision.BLOCK_PUBLICATION,
                policy_version=record.policy_version,
                evidence_hashes={
                    "suricata_rule_fetcher_hash": suricata_rule_source_fetcher.evidence_hash,
                    "suricata_reason": suricata_rule_source_fetcher.reason,
                },
                details=(suricata_rule_source_fetcher.reason,),
            )
        if suricata_replacement_mode_enabled:
            if suricata_replacement_flow is None:
                return PublicationDecisionResult.blocked(
                    artifact_id=record.artifact_id,
                    reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
                    decision=PublicationDecision.BLOCK_PUBLICATION,
                    policy_version=record.policy_version,
                    evidence_hashes={
                        "final_suricata_fetch_hash": suricata_fetch_finalizer.final_suricata_fetch_hash,
                        "suricata_reason": "SURICATA_REPLACEMENT_FLOW_MISSING",
                    },
                    details=("SURICATA_REPLACEMENT_FLOW_MISSING",),
                )
            if not suricata_replacement_flow.approved:
                return PublicationDecisionResult.blocked(
                    artifact_id=record.artifact_id,
                    reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
                    decision=PublicationDecision.BLOCK_PUBLICATION,
                    policy_version=record.policy_version,
                    evidence_hashes={
                        "replacement_flow_hash": suricata_replacement_flow.replacement_flow_hash,
                        "suricata_reason": suricata_replacement_flow.reason,
                    },
                    details=(suricata_replacement_flow.reason,),
                )
        if suricata_live_fetcher_gate is None:
            return PublicationDecisionResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
                decision=PublicationDecision.BLOCK_PUBLICATION,
                policy_version=record.policy_version,
                evidence_hashes={
                    "final_suricata_fetch_hash": suricata_fetch_finalizer.final_suricata_fetch_hash,
                    "suricata_reason": "SURICATA_LIVE_FETCHER_GATE_MISSING",
                },
                details=("SURICATA_LIVE_FETCHER_GATE_MISSING",),
            )
        if not suricata_live_fetcher_gate.approved:
            return PublicationDecisionResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
                decision=PublicationDecision.BLOCK_PUBLICATION,
                policy_version=record.policy_version,
                evidence_hashes={
                    "suricata_live_fetcher_gate_hash": suricata_live_fetcher_gate.evidence_hash,
                    "suricata_reason": suricata_live_fetcher_gate.reason,
                },
                details=(suricata_live_fetcher_gate.reason,),
            )
        if suricata_live_network_fetch is None:
            return PublicationDecisionResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
                decision=PublicationDecision.BLOCK_PUBLICATION,
                policy_version=record.policy_version,
                evidence_hashes={
                    "suricata_live_fetcher_gate_hash": suricata_live_fetcher_gate.evidence_hash,
                    "suricata_reason": "SURICATA_LIVE_NETWORK_FETCH_MISSING",
                },
                details=("SURICATA_LIVE_NETWORK_FETCH_MISSING",),
            )
        if not suricata_live_network_fetch.approved:
            return PublicationDecisionResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
                decision=PublicationDecision.BLOCK_PUBLICATION,
                policy_version=record.policy_version,
                evidence_hashes={
                    "suricata_live_network_fetch_hash": suricata_live_network_fetch.evidence_hash,
                    "suricata_reason": suricata_live_network_fetch.reason,
                },
                details=(suricata_live_network_fetch.reason,),
            )
        if suricata_publication_connector is None:
            return PublicationDecisionResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
                decision=PublicationDecision.BLOCK_PUBLICATION,
                policy_version=record.policy_version,
                evidence_hashes={
                    "suricata_live_network_fetch_hash": suricata_live_network_fetch.evidence_hash,
                    "suricata_reason": "SURICATA_PUBLICATION_CONNECTOR_MISSING",
                },
                details=("SURICATA_PUBLICATION_CONNECTOR_MISSING",),
            )
        if not suricata_publication_connector.approved:
            return PublicationDecisionResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
                decision=PublicationDecision.BLOCK_PUBLICATION,
                policy_version=record.policy_version,
                evidence_hashes={
                    "suricata_publication_connector_hash": suricata_publication_connector.evidence_hash,
                    "suricata_reason": suricata_publication_connector.reason,
                },
                details=(suricata_publication_connector.reason,),
            )
        if (
            not is_sha256_ref(suricata_publication_connector.evidence_hash)
            or suricata_publication_connector.policy_version != suricata_live_network_fetch.policy_version
            or suricata_publication_connector.trust_fingerprint != suricata_live_network_fetch.trust_anchor_fingerprint
            or suricata_publication_connector.decision != "ALLOW"
            or suricata_publication_connector.connector_version == ""
        ):
            return PublicationDecisionResult.blocked(
                artifact_id=record.artifact_id,
                reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
                decision=PublicationDecision.BLOCK_PUBLICATION,
                policy_version=record.policy_version,
                evidence_hashes={
                    "suricata_publication_connector_hash": suricata_publication_connector.evidence_hash,
                    "suricata_reason": "SURICATA_PUBLICATION_CONNECTOR_MALFORMED",
                },
                details=("SURICATA_PUBLICATION_CONNECTOR_MALFORMED",),
            )
    if suricata_rule_source is None:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
            decision=PublicationDecision.BLOCK_PUBLICATION,
            policy_version=record.policy_version,
            evidence_hashes={
                "suricata_evidence_hash": suricata_evidence.evidence_hash,
                "suricata_reason": "SURICATA_RULE_SOURCE_MISSING",
            },
            details=("SURICATA_RULE_SOURCE_MISSING",),
        )
    if not suricata_rule_source.approved:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
            decision=PublicationDecision.BLOCK_PUBLICATION,
            policy_version=record.policy_version,
            evidence_hashes={
                "suricata_rule_source_hash": suricata_rule_source.evidence_hash,
                "suricata_reason": suricata_rule_source.reason,
            },
            details=(suricata_rule_source.reason,),
        )
    if suricata_policy_registry is None:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
            decision=PublicationDecision.BLOCK_PUBLICATION,
            policy_version=record.policy_version,
            evidence_hashes={
                "suricata_evidence_hash": suricata_evidence.evidence_hash,
                "suricata_reason": "SURICATA_POLICY_REGISTRY_MISSING",
            },
            details=("SURICATA_POLICY_REGISTRY_MISSING",),
        )
    if not suricata_policy_registry.approved:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
            decision=PublicationDecision.BLOCK_PUBLICATION,
            policy_version=record.policy_version,
            evidence_hashes={
                "suricata_policy_registry_hash": suricata_policy_registry.evidence_hash,
                "suricata_reason": suricata_policy_registry.reason,
            },
            details=(suricata_policy_registry.reason,),
        )
    if suricata_policy_gate is None:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
            decision=PublicationDecision.BLOCK_PUBLICATION,
            policy_version=record.policy_version,
            evidence_hashes={
                "suricata_evidence_hash": suricata_evidence.evidence_hash,
                "suricata_reason": "SURICATA_POLICY_GATE_MISSING",
            },
            details=("SURICATA_POLICY_GATE_MISSING",),
        )
    if suricata_signing_authority is None:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
            decision=PublicationDecision.BLOCK_PUBLICATION,
            policy_version=record.policy_version,
            evidence_hashes={
                "suricata_trust_anchor_hash": suricata_trust_anchor.evidence_hash,
                "suricata_reason": "SURICATA_SIGNING_AUTHORITY_MISSING",
            },
            details=("SURICATA_SIGNING_AUTHORITY_MISSING",),
        )
    if (
        not suricata_signing_authority.approved
        or not is_sha256_ref(suricata_signing_authority.evidence_hash)
        or suricata_signing_authority.authority_fingerprint != suricata_trust_anchor.public_key_fingerprint
        or suricata_signing_authority.policy_version != suricata_trust_anchor.policy_version
    ):
        reason = suricata_signing_authority.reason
        if suricata_signing_authority.authority_fingerprint != suricata_trust_anchor.public_key_fingerprint:
            reason = "SURICATA_SIGNING_AUTHORITY_FINGERPRINT_MISMATCH"
        elif suricata_signing_authority.policy_version != suricata_trust_anchor.policy_version:
            reason = "SURICATA_SIGNING_AUTHORITY_POLICY_MISMATCH"
        elif not is_sha256_ref(suricata_signing_authority.evidence_hash):
            reason = "SURICATA_SIGNING_AUTHORITY_EVIDENCE_MISSING"
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
            decision=PublicationDecision.BLOCK_PUBLICATION,
            policy_version=record.policy_version,
            evidence_hashes={
                "suricata_signing_authority_hash": suricata_signing_authority.evidence_hash,
                "suricata_signing_authority_status": "BLOCK",
                "suricata_reason": reason,
            },
            details=(reason,),
        )
    evidence_hashes = {
        "suricata_evidence_hash": suricata_policy_gate.evidence_hash,
        "suricata_policy_version": suricata_policy_gate.policy_version,
        "suricata_reason": suricata_policy_gate.reason,
        "suricata_threshold": str(suricata_policy_gate.threshold),
        "suricata_decision": "ALLOW" if suricata_policy_gate.approved else "BLOCK",
        "suricata_policy_registry_hash": suricata_policy_registry.evidence_hash,
        "suricata_rule_source_hash": suricata_rule_source.evidence_hash,
        "suricata_trust_anchor_hash": suricata_trust_anchor.evidence_hash,
        "suricata_trust_anchor_finalizer_hash": suricata_trust_anchor_finalizer.evidence_hash,
        "suricata_signing_authority_hash": suricata_signing_authority.evidence_hash,
        "suricata_signing_authority_status": "ALLOW",
    }
    if suricata_live_rule_source_enabled and suricata_rule_source_fetcher is not None:
        evidence_hashes["suricata_rule_fetcher_hash"] = suricata_rule_source_fetcher.evidence_hash
    if suricata_live_rule_source_enabled and suricata_fetch_receipt is not None:
        evidence_hashes["suricata_fetch_receipt_hash"] = suricata_fetch_receipt.evidence_hash
    if suricata_live_rule_source_enabled and suricata_fetch_finalizer is not None:
        evidence_hashes["final_suricata_fetch_hash"] = suricata_fetch_finalizer.final_suricata_fetch_hash
    if suricata_live_rule_source_enabled and suricata_live_fetcher_gate is not None:
        evidence_hashes.update(
            {
                "suricata_live_fetcher_gate_hash": suricata_live_fetcher_gate.evidence_hash,
                "suricata_live_fetcher_policy_version": suricata_live_fetcher_gate.policy_version,
                "suricata_live_fetcher_decision": suricata_live_fetcher_gate.decision,
                "suricata_live_fetcher_reason": suricata_live_fetcher_gate.reason,
                "suricata_live_fetcher_timestamp": suricata_live_fetcher_gate.evaluated_at,
            }
        )
    if suricata_live_rule_source_enabled and suricata_live_network_fetch is not None:
        evidence_hashes.update(
            {
                "suricata_live_network_fetch_hash": suricata_live_network_fetch.evidence_hash,
                "suricata_live_network_bundle_hash": suricata_live_network_fetch.bundle_hash,
                "suricata_live_network_timestamp": suricata_live_network_fetch.timestamp,
                "suricata_live_network_policy_version": suricata_live_network_fetch.policy_version,
                "suricata_live_network_trust_fingerprint": suricata_live_network_fetch.trust_anchor_fingerprint,
                "suricata_live_network_decision": suricata_live_network_fetch.decision,
                "suricata_live_network_reason": suricata_live_network_fetch.reason,
            }
        )
    if suricata_live_rule_source_enabled and suricata_publication_connector is not None:
        evidence_hashes.update(
            {
                "suricata_publication_connector_hash": suricata_publication_connector.evidence_hash,
                "suricata_publication_connector_policy_version": suricata_publication_connector.policy_version,
                "suricata_publication_connector_trust_fingerprint": suricata_publication_connector.trust_fingerprint,
                "suricata_publication_connector_decision": suricata_publication_connector.decision,
                "suricata_publication_connector_reason": suricata_publication_connector.reason,
                "suricata_publication_connector_timestamp": suricata_publication_connector.timestamp,
                "suricata_publication_connector_nonce": suricata_publication_connector.nonce,
                "suricata_publication_connector_version": suricata_publication_connector.connector_version,
            }
        )
    if suricata_replacement_mode_enabled and suricata_replacement_flow is not None:
        evidence_hashes.update(
            {
                "replacement_flow_hash": suricata_replacement_flow.replacement_flow_hash,
                "replacement_rule_bundle_hash": suricata_replacement_flow.rule_bundle_hash,
                "replacement_policy_version": suricata_replacement_flow.policy_version,
                "replacement_decision": suricata_replacement_flow.decision,
                "replacement_reason": suricata_replacement_flow.reason,
            }
        )
    if not suricata_evidence.accepted:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.NETWORK_IDS_EVIDENCE_INVALID,
            decision=PublicationDecision.BLOCK_PUBLICATION,
            policy_version=record.policy_version,
            evidence_hashes=evidence_hashes,
            details=(suricata_evidence.reason,),
        )
    if not suricata_policy_gate.approved:
        return PublicationDecisionResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.NETWORK_IDS_EVIDENCE_BLOCKED,
            decision=PublicationDecision.BLOCK_PUBLICATION,
            policy_version=record.policy_version,
            evidence_hashes=evidence_hashes,
            details=("BLOCK_EXECUTION", suricata_evidence.reason),
        )
    return evidence_hashes
