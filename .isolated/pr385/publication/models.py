"""Publication runtime models and deterministic audit helpers."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SHA256_REF_RE = re.compile(r"^sha256:[A-Za-z0-9_.:-]+$")


class TextEnum(str, Enum):
    """String-valued enum compatible with Python 3.9 and 3.11."""


class BlockReason(TextEnum):
    NONE = "NONE"
    REGISTRY_RECORD_MISSING = "REGISTRY_RECORD_MISSING"
    REGISTRY_SCHEMA_INVALID = "REGISTRY_SCHEMA_INVALID"
    ARTIFACT_ID_UNKNOWN = "ARTIFACT_ID_UNKNOWN"
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    INVALID_FIELD_VALUE = "INVALID_FIELD_VALUE"
    INVALID_LIFECYCLE_TRANSITION = "INVALID_LIFECYCLE_TRANSITION"
    CLASSIFICATION_MISSING = "CLASSIFICATION_MISSING"
    CLASSIFICATION_INVALID = "CLASSIFICATION_INVALID"
    CLASSIFICATION_NOT_PUBLISH_ELIGIBLE = "CLASSIFICATION_NOT_PUBLISH_ELIGIBLE"
    HUMAN_APPROVAL_MISSING = "HUMAN_APPROVAL_MISSING"
    MISSING_APPROVAL_EVIDENCE = "MISSING_APPROVAL_EVIDENCE"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    OWNER_SELF_APPROVAL = "OWNER_SELF_APPROVAL"
    REVIEWER_AUTHORITY_MISSING = "REVIEWER_AUTHORITY_MISSING"
    REQUIRED_MULTI_REVIEW_MISSING = "REQUIRED_MULTI_REVIEW_MISSING"
    HASH_MISMATCH = "HASH_MISMATCH"
    ROLLBACK_REFERENCE_MISSING = "ROLLBACK_REFERENCE_MISSING"
    AUDIT_REFERENCE_MISSING = "AUDIT_REFERENCE_MISSING"
    POLICY_VERSION_MISMATCH = "POLICY_VERSION_MISMATCH"
    CONNECTOR_TARGET_UNKNOWN = "CONNECTOR_TARGET_UNKNOWN"
    SENSITIVE_SCAN_MISSING = "SENSITIVE_SCAN_MISSING"
    SENSITIVE_DATA_PRESENT = "SENSITIVE_DATA_PRESENT"
    INVALID_SCAN_INPUT = "INVALID_SCAN_INPUT"
    VALIDATOR_RESULT_MISSING = "VALIDATOR_RESULT_MISSING"
    CONNECTOR_GATE_MISSING = "CONNECTOR_GATE_MISSING"
    CONNECTOR_GATE_BLOCKED = "CONNECTOR_GATE_BLOCKED"
    AUTO_PUBLICATION_FORBIDDEN = "AUTO_PUBLICATION_FORBIDDEN"
    APPROVAL_HASH_MISSING = "APPROVAL_HASH_MISSING"
    SENSITIVE_SCAN_HASH_MISSING = "SENSITIVE_SCAN_HASH_MISSING"
    AUDIT_EVENT_MISSING = "AUDIT_EVENT_MISSING"
    RAW_SENSITIVE_DATA_PRESENT = "RAW_SENSITIVE_DATA_PRESENT"
    EVIDENCE_CHAIN_MISSING = "EVIDENCE_CHAIN_MISSING"
    EVIDENCE_ORDER_INVALID = "EVIDENCE_ORDER_INVALID"
    DUPLICATE_EVIDENCE_STAGE = "DUPLICATE_EVIDENCE_STAGE"
    EVIDENCE_ARTIFACT_MISMATCH = "EVIDENCE_ARTIFACT_MISMATCH"
    REPORT_INCOMPLETE = "REPORT_INCOMPLETE"
    COMMIT_SCOPE_NOT_APPROVED = "COMMIT_SCOPE_NOT_APPROVED"
    POLICY_BUNDLE_NOT_APPROVED = "POLICY_BUNDLE_NOT_APPROVED"
    FINALIZATION_GATE_BLOCKED = "FINALIZATION_GATE_BLOCKED"
    PUBLICATION_LOCK_BLOCKED = "PUBLICATION_LOCK_BLOCKED"
    PUBLICATION_RELEASE_BLOCKED = "PUBLICATION_RELEASE_BLOCKED"
    NETWORK_IDS_EVIDENCE_INVALID = "NETWORK_IDS_EVIDENCE_INVALID"
    NETWORK_IDS_EVIDENCE_BLOCKED = "NETWORK_IDS_EVIDENCE_BLOCKED"


class ApprovalState(TextEnum):
    DRAFT = "DRAFT"
    CLASSIFIED = "CLASSIFIED"
    UNDER_REVIEW = "UNDER_REVIEW"
    CHANGES_REQUIRED = "CHANGES_REQUIRED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    BLOCKED = "BLOCKED"


class LifecycleState(TextEnum):
    DRAFT = "DRAFT"
    REGISTERED = "REGISTERED"
    CLASSIFIED = "CLASSIFIED"
    UNDER_REVIEW = "UNDER_REVIEW"
    APPROVED = "APPROVED"
    PUBLISH_ELIGIBLE = "PUBLISH_ELIGIBLE"
    PUBLISHED = "PUBLISHED"
    SUPERSEDED = "SUPERSEDED"
    REVOKED = "REVOKED"
    BLOCKED = "BLOCKED"
    ARCHIVED = "ARCHIVED"


class PublicationDecision(TextEnum):
    ALLOW_PUBLICATION = "ALLOW_PUBLICATION"
    BLOCK_PUBLICATION = "BLOCK_PUBLICATION"
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"
    NEEDS_RECLASSIFICATION = "NEEDS_RECLASSIFICATION"
    NEEDS_ROLLBACK_REFERENCE = "NEEDS_ROLLBACK_REFERENCE"
    SENSITIVE_DATA_BLOCKED = "SENSITIVE_DATA_BLOCKED"
    CONNECTOR_BLOCKED = "CONNECTOR_BLOCKED"
    AUDIT_EVIDENCE_MISSING = "AUDIT_EVIDENCE_MISSING"


class ConnectorGateDecision(TextEnum):
    CONNECTOR_GATE_ALLOWED = "CONNECTOR_GATE_ALLOWED"
    CONNECTOR_GATE_BLOCKED = "CONNECTOR_GATE_BLOCKED"


class EvidenceChainStage(TextEnum):
    REGISTRY = "REGISTRY"
    CLASSIFICATION = "CLASSIFICATION"
    SENSITIVE_DATA_SCAN = "SENSITIVE_DATA_SCAN"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"
    RUNTIME_VALIDATOR = "RUNTIME_VALIDATOR"
    CONNECTOR_GATE = "CONNECTOR_GATE"
    AUDIT_PERSISTENCE = "AUDIT_PERSISTENCE"
    FINAL_AGGREGATOR = "FINAL_AGGREGATOR"


class ClassificationState(TextEnum):
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    CUSTOMER_DRAFT = "CUSTOMER_DRAFT"
    CUSTOMER_APPROVED = "CUSTOMER_APPROVED"
    PUBLIC_DRAFT = "PUBLIC_DRAFT"
    PUBLIC_APPROVED = "PUBLIC_APPROVED"
    PRICING_DRAFT = "PRICING_DRAFT"
    PRICING_APPROVED = "PRICING_APPROVED"
    LINKEDIN_DRAFT = "LINKEDIN_DRAFT"
    LINKEDIN_APPROVED = "LINKEDIN_APPROVED"
    BLOCKED_SENSITIVE = "BLOCKED_SENSITIVE"


class TargetChannel(TextEnum):
    LINKEDIN = "LINKEDIN"
    NOTION = "NOTION"
    PAGES = "PAGES"
    CUSTOMER_DOCUMENT = "CUSTOMER_DOCUMENT"
    PRICING_ARTIFACT = "PRICING_ARTIFACT"
    PUBLIC_ARTIFACT = "PUBLIC_ARTIFACT"
    PRICING_PDF = "PRICING_PDF"
    PUBLIC_PDF = "PUBLIC_PDF"
    INTERNAL = "INTERNAL"


class SensitiveDataCategory(TextEnum):
    NONE = "NONE"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    API_KEY = "API_KEY"
    TOKEN = "TOKEN"
    PRIVATE_KEY = "PRIVATE_KEY"
    PASSWORD_OR_SECRET = "PASSWORD_OR_SECRET"
    IBAN = "IBAN"
    CREDIT_CARD = "CREDIT_CARD"
    CUSTOMER_CONFIDENTIAL = "CUSTOMER_CONFIDENTIAL"


@dataclass(frozen=True)
class RegistryRecord:
    artifact_id: str
    artifact_type: str
    artifact_title: str
    owner: str
    reviewer: str
    source_path: str
    target_channel: str
    classification: str
    lifecycle_state: str
    version: str
    content_hash: str
    classification_hash: str
    approval_hash: str
    lineage_reference: str
    parent_artifact_id: str | None
    rollback_reference: str
    audit_reference: str
    policy_version: str
    created_at: str
    updated_at: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RegistryRecord":
        return cls(**{field_name: data.get(field_name) for field_name in cls.field_names()})

    @staticmethod
    def field_names() -> tuple[str, ...]:
        return tuple(RegistryRecord.__dataclass_fields__.keys())

    def to_dict(self) -> dict[str, Any]:
        return {field_name: getattr(self, field_name) for field_name in self.field_names()}

    def stable_hash(self) -> str:
        return hash_payload(self.to_dict())


@dataclass(frozen=True)
class AuditEvidence:
    artifact_id: str
    decision: str
    block_reason: str
    policy_version: str
    evidence_hashes: dict[str, str] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "decision": self.decision,
            "block_reason": self.block_reason,
            "policy_version": self.policy_version,
            "evidence_hashes": dict(sorted(self.evidence_hashes.items())),
            "timestamp": self.timestamp,
        }

    @property
    def audit_hash(self) -> str:
        return hash_payload(self.to_dict())


@dataclass(frozen=True)
class SensitiveScanResult:
    artifact_id: str
    passed: bool
    decision: PublicationDecision
    block_reason: BlockReason
    detected_categories: tuple[SensitiveDataCategory, ...]
    evidence: dict[str, Any]
    audit: AuditEvidence

    @classmethod
    def blocked(
        cls,
        *,
        artifact_id: str,
        reason: BlockReason,
        categories: tuple[SensitiveDataCategory, ...],
        evidence: dict[str, Any],
        policy_version: str,
    ) -> "SensitiveScanResult":
        audit = AuditEvidence(
            artifact_id=artifact_id or "UNKNOWN_ARTIFACT",
            decision=PublicationDecision.SENSITIVE_DATA_BLOCKED.value,
            block_reason=reason.value,
            policy_version=policy_version or "UNKNOWN",
            evidence_hashes={"sensitive_scan_hash": hash_payload(evidence)},
        )
        return cls(
            artifact_id=artifact_id or "UNKNOWN_ARTIFACT",
            passed=False,
            decision=PublicationDecision.SENSITIVE_DATA_BLOCKED,
            block_reason=reason,
            detected_categories=categories,
            evidence=evidence,
            audit=audit,
        )

    @classmethod
    def passed_clean(
        cls,
        *,
        artifact_id: str,
        evidence: dict[str, Any],
        policy_version: str,
    ) -> "SensitiveScanResult":
        audit = AuditEvidence(
            artifact_id=artifact_id,
            decision=PublicationDecision.ALLOW_PUBLICATION.value,
            block_reason=BlockReason.NONE.value,
            policy_version=policy_version,
            evidence_hashes={"sensitive_scan_hash": hash_payload(evidence)},
        )
        return cls(
            artifact_id=artifact_id,
            passed=True,
            decision=PublicationDecision.ALLOW_PUBLICATION,
            block_reason=BlockReason.NONE,
            detected_categories=(),
            evidence=evidence,
            audit=audit,
        )


@dataclass(frozen=True)
class ApprovalEvidence:
    artifact_id: str
    artifact_version: str
    owner: str
    reviewer: str
    reviewer_role: str
    approval_state: str
    approval_timestamp: str
    approval_hash: str
    policy_version: str
    audit_reference: str
    rollback_reference: str
    classification: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ApprovalEvidence":
        return cls(**{field_name: data.get(field_name) for field_name in cls.field_names()})

    @staticmethod
    def field_names() -> tuple[str, ...]:
        return tuple(ApprovalEvidence.__dataclass_fields__.keys())

    def redacted_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_version": self.artifact_version,
            "owner": self.owner,
            "reviewer": self.reviewer,
            "reviewer_role": self.reviewer_role,
            "approval_state": self.approval_state,
            "approval_timestamp": self.approval_timestamp,
            "approval_hash": self.approval_hash,
            "policy_version": self.policy_version,
            "audit_reference": self.audit_reference,
            "rollback_reference": self.rollback_reference,
            "classification": self.classification,
            "raw_approval_content_stored": False,
        }

    def stable_hash(self) -> str:
        return hash_payload(self.redacted_dict())


@dataclass(frozen=True)
class ApprovalValidationResult:
    artifact_id: str
    passed: bool
    approval_state: ApprovalState
    block_reason: BlockReason
    reviewer_references: tuple[str, ...]
    evidence: dict[str, Any]
    audit: AuditEvidence

    @classmethod
    def blocked(
        cls,
        *,
        artifact_id: str,
        reason: BlockReason,
        state: ApprovalState = ApprovalState.BLOCKED,
        reviewer_references: tuple[str, ...] = (),
        evidence: dict[str, Any] | None = None,
        policy_version: str = "UNKNOWN",
    ) -> "ApprovalValidationResult":
        redacted_evidence = evidence or {
            "artifact_id": artifact_id or "UNKNOWN_ARTIFACT",
            "approval_hash_present": False,
            "raw_approval_content_stored": False,
        }
        audit = AuditEvidence(
            artifact_id=artifact_id or "UNKNOWN_ARTIFACT",
            decision=PublicationDecision.NEEDS_HUMAN_REVIEW.value,
            block_reason=reason.value,
            policy_version=policy_version or "UNKNOWN",
            evidence_hashes={"approval_validation_hash": hash_payload(redacted_evidence)},
        )
        return cls(
            artifact_id=artifact_id or "UNKNOWN_ARTIFACT",
            passed=False,
            approval_state=state,
            block_reason=reason,
            reviewer_references=reviewer_references,
            evidence=redacted_evidence,
            audit=audit,
        )

    @classmethod
    def approved(
        cls,
        *,
        artifact_id: str,
        reviewer_references: tuple[str, ...],
        evidence: dict[str, Any],
        policy_version: str,
    ) -> "ApprovalValidationResult":
        audit = AuditEvidence(
            artifact_id=artifact_id,
            decision=PublicationDecision.ALLOW_PUBLICATION.value,
            block_reason=BlockReason.NONE.value,
            policy_version=policy_version,
            evidence_hashes={"approval_validation_hash": hash_payload(evidence)},
        )
        return cls(
            artifact_id=artifact_id,
            passed=True,
            approval_state=ApprovalState.APPROVED,
            block_reason=BlockReason.NONE,
            reviewer_references=reviewer_references,
            evidence=evidence,
            audit=audit,
        )


@dataclass(frozen=True)
class PublicationAuditEvent:
    artifact_id: str
    artifact_version: str
    decision: str
    block_reason: str
    policy_version: str
    classification_hash: str
    sensitive_scan_hash: str
    approval_hash: str
    validator_hash: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_version": self.artifact_version,
            "decision": self.decision,
            "block_reason": self.block_reason,
            "policy_version": self.policy_version,
            "classification_hash": self.classification_hash,
            "sensitive_scan_hash": self.sensitive_scan_hash,
            "approval_hash": self.approval_hash,
            "validator_hash": self.validator_hash,
            "timestamp": self.timestamp,
        }

    @property
    def evidence_chain_hash(self) -> str:
        return hash_payload(self.to_dict())


@dataclass(frozen=True)
class AuditPersistenceResult:
    artifact_id: str
    persisted: bool
    block_reason: BlockReason
    event: PublicationAuditEvent | None
    audit: AuditEvidence

    @classmethod
    def blocked(
        cls,
        *,
        artifact_id: str,
        reason: BlockReason,
        policy_version: str,
        evidence_hashes: dict[str, str] | None = None,
    ) -> "AuditPersistenceResult":
        audit = AuditEvidence(
            artifact_id=artifact_id or "UNKNOWN_ARTIFACT",
            decision=PublicationDecision.AUDIT_EVIDENCE_MISSING.value,
            block_reason=reason.value,
            policy_version=policy_version or "UNKNOWN",
            evidence_hashes=evidence_hashes or {},
        )
        return cls(
            artifact_id=artifact_id or "UNKNOWN_ARTIFACT",
            persisted=False,
            block_reason=reason,
            event=None,
            audit=audit,
        )

    @classmethod
    def persisted_event(
        cls,
        *,
        event: PublicationAuditEvent,
    ) -> "AuditPersistenceResult":
        audit = AuditEvidence(
            artifact_id=event.artifact_id,
            decision=event.decision,
            block_reason=event.block_reason,
            policy_version=event.policy_version,
            evidence_hashes={"evidence_chain_hash": event.evidence_chain_hash},
        )
        return cls(
            artifact_id=event.artifact_id,
            persisted=True,
            block_reason=BlockReason.NONE,
            event=event,
            audit=audit,
        )


@dataclass(frozen=True)
class ConnectorGateResult:
    artifact_id: str
    target_channel: str
    publish_allowed: bool
    decision: PublicationDecision
    block_reason: BlockReason
    audit: AuditEvidence
    evidence: dict[str, Any]

    @property
    def gate_decision(self) -> ConnectorGateDecision:
        if self.publish_allowed:
            return ConnectorGateDecision.CONNECTOR_GATE_ALLOWED
        return ConnectorGateDecision.CONNECTOR_GATE_BLOCKED

    @classmethod
    def blocked(
        cls,
        *,
        artifact_id: str,
        target_channel: str,
        reason: BlockReason,
        policy_version: str,
        evidence: dict[str, Any] | None = None,
    ) -> "ConnectorGateResult":
        redacted_evidence = evidence or {
            "artifact_id": artifact_id or "UNKNOWN_ARTIFACT",
            "target_channel": target_channel or "UNKNOWN_CHANNEL",
            "publish_allowed": False,
            "raw_content_stored": False,
        }
        audit = AuditEvidence(
            artifact_id=artifact_id or "UNKNOWN_ARTIFACT",
            decision=PublicationDecision.CONNECTOR_BLOCKED.value,
            block_reason=reason.value,
            policy_version=policy_version or "UNKNOWN",
            evidence_hashes={"connector_gate_hash": hash_payload(redacted_evidence)},
        )
        return cls(
            artifact_id=artifact_id or "UNKNOWN_ARTIFACT",
            target_channel=target_channel or "UNKNOWN_CHANNEL",
            publish_allowed=False,
            decision=PublicationDecision.CONNECTOR_BLOCKED,
            block_reason=reason,
            audit=audit,
            evidence=redacted_evidence,
        )

    @classmethod
    def allowed(
        cls,
        *,
        artifact_id: str,
        target_channel: str,
        policy_version: str,
        evidence: dict[str, Any],
    ) -> "ConnectorGateResult":
        audit = AuditEvidence(
            artifact_id=artifact_id,
            decision=PublicationDecision.ALLOW_PUBLICATION.value,
            block_reason=BlockReason.NONE.value,
            policy_version=policy_version,
            evidence_hashes={"connector_gate_hash": hash_payload(evidence)},
        )
        return cls(
            artifact_id=artifact_id,
            target_channel=target_channel,
            publish_allowed=True,
            decision=PublicationDecision.ALLOW_PUBLICATION,
            block_reason=BlockReason.NONE,
            audit=audit,
            evidence=evidence,
        )


ConnectorEligibilityResult = ConnectorGateResult


@dataclass(frozen=True)
class EvidenceChainEntry:
    stage: EvidenceChainStage
    artifact_id: str
    artifact_version: str
    policy_version: str
    evidence_hash: str

    def to_dict(self) -> dict[str, str]:
        return {
            "stage": self.stage.value,
            "artifact_id": self.artifact_id,
            "artifact_version": self.artifact_version,
            "policy_version": self.policy_version,
            "evidence_hash": self.evidence_hash,
        }


@dataclass(frozen=True)
class EvidenceChainVerificationResult:
    artifact_id: str
    verified: bool
    block_reason: BlockReason
    audit: AuditEvidence
    evidence: dict[str, Any]

    @classmethod
    def blocked(
        cls,
        *,
        artifact_id: str,
        reason: BlockReason,
        policy_version: str,
        evidence: dict[str, Any],
    ) -> "EvidenceChainVerificationResult":
        audit = AuditEvidence(
            artifact_id=artifact_id or "UNKNOWN_ARTIFACT",
            decision=PublicationDecision.BLOCK_PUBLICATION.value,
            block_reason=reason.value,
            policy_version=policy_version or "UNKNOWN",
            evidence_hashes={"evidence_chain_verification_hash": hash_payload(evidence)},
        )
        return cls(
            artifact_id=artifact_id or "UNKNOWN_ARTIFACT",
            verified=False,
            block_reason=reason,
            audit=audit,
            evidence=evidence,
        )

    @classmethod
    def verified_chain(
        cls,
        *,
        artifact_id: str,
        policy_version: str,
        evidence: dict[str, Any],
    ) -> "EvidenceChainVerificationResult":
        audit = AuditEvidence(
            artifact_id=artifact_id,
            decision=PublicationDecision.ALLOW_PUBLICATION.value,
            block_reason=BlockReason.NONE.value,
            policy_version=policy_version,
            evidence_hashes={"evidence_chain_verification_hash": hash_payload(evidence)},
        )
        return cls(
            artifact_id=artifact_id,
            verified=True,
            block_reason=BlockReason.NONE,
            audit=audit,
            evidence=evidence,
        )


@dataclass(frozen=True)
class FinalPublicationReport:
    artifact_id: str
    artifact_version: str
    target_channel: str
    final_decision: PublicationDecision
    block_reason: BlockReason
    policy_version: str
    evidence_chain_verification_hash: str
    audit_hash: str
    connector_gate_hash: str
    human_approval_hash: str
    sensitive_scan_hash: str
    classification_hash: str
    registry_hash: str
    suricata_evidence_hash: str = ""
    suricata_policy_version: str = ""
    suricata_reason: str = ""
    suricata_threshold: str = ""
    suricata_decision: str = ""
    suricata_signing_authority_hash: str = ""
    suricata_signing_authority_status: str = ""
    suricata_live_fetcher_gate_hash: str = ""
    suricata_live_fetcher_policy_version: str = ""
    suricata_live_fetcher_decision: str = ""
    suricata_live_fetcher_reason: str = ""
    suricata_live_fetcher_timestamp: str = ""
    suricata_live_network_fetch_hash: str = ""
    suricata_live_network_bundle_hash: str = ""
    suricata_live_network_timestamp: str = ""
    suricata_live_network_policy_version: str = ""
    suricata_live_network_trust_fingerprint: str = ""
    suricata_live_network_decision: str = ""
    suricata_live_network_reason: str = ""
    suricata_publication_connector_hash: str = ""
    suricata_publication_connector_policy_version: str = ""
    suricata_publication_connector_trust_fingerprint: str = ""
    suricata_publication_connector_decision: str = ""
    suricata_publication_connector_reason: str = ""
    suricata_publication_connector_timestamp: str = ""
    suricata_publication_connector_nonce: str = ""
    suricata_publication_connector_version: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def report_complete(self) -> bool:
        return self.block_reason != BlockReason.REPORT_INCOMPLETE

    def to_dict(self) -> dict[str, str]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_version": self.artifact_version,
            "target_channel": self.target_channel,
            "final_decision": self.final_decision.value,
            "block_reason": self.block_reason.value,
            "policy_version": self.policy_version,
            "evidence_chain_verification_hash": self.evidence_chain_verification_hash,
            "audit_hash": self.audit_hash,
            "connector_gate_hash": self.connector_gate_hash,
            "human_approval_hash": self.human_approval_hash,
            "sensitive_scan_hash": self.sensitive_scan_hash,
            "classification_hash": self.classification_hash,
            "registry_hash": self.registry_hash,
            "suricata_evidence_hash": self.suricata_evidence_hash,
            "suricata_policy_version": self.suricata_policy_version,
            "suricata_reason": self.suricata_reason,
            "suricata_threshold": self.suricata_threshold,
            "suricata_decision": self.suricata_decision,
            "suricata_signing_authority_hash": self.suricata_signing_authority_hash,
            "suricata_signing_authority_status": self.suricata_signing_authority_status,
            "suricata_live_fetcher_gate_hash": self.suricata_live_fetcher_gate_hash,
            "suricata_live_fetcher_policy_version": self.suricata_live_fetcher_policy_version,
            "suricata_live_fetcher_decision": self.suricata_live_fetcher_decision,
            "suricata_live_fetcher_reason": self.suricata_live_fetcher_reason,
            "suricata_live_fetcher_timestamp": self.suricata_live_fetcher_timestamp,
            "suricata_live_network_fetch_hash": self.suricata_live_network_fetch_hash,
            "suricata_live_network_bundle_hash": self.suricata_live_network_bundle_hash,
            "suricata_live_network_timestamp": self.suricata_live_network_timestamp,
            "suricata_live_network_policy_version": self.suricata_live_network_policy_version,
            "suricata_live_network_trust_fingerprint": self.suricata_live_network_trust_fingerprint,
            "suricata_live_network_decision": self.suricata_live_network_decision,
            "suricata_live_network_reason": self.suricata_live_network_reason,
            "suricata_publication_connector_hash": self.suricata_publication_connector_hash,
            "suricata_publication_connector_policy_version": self.suricata_publication_connector_policy_version,
            "suricata_publication_connector_trust_fingerprint": self.suricata_publication_connector_trust_fingerprint,
            "suricata_publication_connector_decision": self.suricata_publication_connector_decision,
            "suricata_publication_connector_reason": self.suricata_publication_connector_reason,
            "suricata_publication_connector_timestamp": self.suricata_publication_connector_timestamp,
            "suricata_publication_connector_nonce": self.suricata_publication_connector_nonce,
            "suricata_publication_connector_version": self.suricata_publication_connector_version,
            "created_at": self.created_at,
        }

    @property
    def report_hash(self) -> str:
        return hash_payload(self.to_dict())


@dataclass(frozen=True)
class CommitScopeResult:
    approved: bool
    rejected_files: tuple[str, ...]
    staged_files: tuple[str, ...]
    evidence_hash: str
    policy_version: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "rejected_files": self.rejected_files,
            "staged_files": self.staged_files,
            "evidence_hash": self.evidence_hash,
            "policy_version": self.policy_version,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class PolicyBundleValidationResult:
    valid: bool
    policy_version: str
    bundle_hash: str
    rejected_policy: str
    reason: str
    evidence_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "policy_version": self.policy_version,
            "bundle_hash": self.bundle_hash,
            "rejected_policy": self.rejected_policy,
            "reason": self.reason,
            "evidence_hash": self.evidence_hash,
        }


@dataclass(frozen=True)
class PolicyBundleReadinessResult:
    ready: bool
    decision: PublicationDecision
    block_reason: BlockReason
    required_policy_ids: tuple[str, ...]
    missing_policy_ids: tuple[str, ...]
    invalid_policy_ids: tuple[str, ...]
    evidence_hash: str
    policy_version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "decision": self.decision.value,
            "block_reason": self.block_reason.value,
            "required_policy_ids": self.required_policy_ids,
            "missing_policy_ids": self.missing_policy_ids,
            "invalid_policy_ids": self.invalid_policy_ids,
            "evidence_hash": self.evidence_hash,
            "policy_version": self.policy_version,
        }


@dataclass(frozen=True)
class FinalizationGateResult:
    ready: bool
    decision: str
    reason: str
    missing_controls: tuple[str, ...]
    evidence_hash: str
    policy_version: str
    required_inputs: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "decision": self.decision,
            "reason": self.reason,
            "missing_controls": self.missing_controls,
            "evidence_hash": self.evidence_hash,
            "policy_version": self.policy_version,
            "required_inputs": self.required_inputs,
        }


@dataclass(frozen=True)
class PublicationLockResult:
    locked: bool
    decision: str
    reason: str
    missing_controls: tuple[str, ...]
    evidence_hash: str
    policy_version: str
    lock_id: str
    required_inputs: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "locked": self.locked,
            "decision": self.decision,
            "reason": self.reason,
            "missing_controls": self.missing_controls,
            "evidence_hash": self.evidence_hash,
            "policy_version": self.policy_version,
            "lock_id": self.lock_id,
            "required_inputs": self.required_inputs,
        }


@dataclass(frozen=True)
class PublicationLockReleaseResult:
    approved: bool
    release_id: str
    lock_id: str
    evidence_hash: str
    policy_version: str
    reason: str
    rejected_reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "release_id": self.release_id,
            "lock_id": self.lock_id,
            "evidence_hash": self.evidence_hash,
            "policy_version": self.policy_version,
            "reason": self.reason,
            "rejected_reasons": self.rejected_reasons,
        }


@dataclass(frozen=True)
class PublicationReleaseBlockerResult:
    approved: bool
    rejected: bool
    rejected_reasons: tuple[str, ...]
    evidence_hash: str
    policy_version: str
    release_block_id: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "rejected": self.rejected,
            "rejected_reasons": self.rejected_reasons,
            "evidence_hash": self.evidence_hash,
            "policy_version": self.policy_version,
            "release_block_id": self.release_block_id,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ReleaseBlockerIntegrityResult:
    approved: bool
    rejected: bool
    rejected_reasons: tuple[str, ...]
    evidence_hash: str
    policy_version: str
    integrity_id: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "rejected": self.rejected,
            "rejected_reasons": self.rejected_reasons,
            "evidence_hash": self.evidence_hash,
            "policy_version": self.policy_version,
            "integrity_id": self.integrity_id,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class EvidenceConsistencyResult:
    approved: bool
    consistency_hash: str
    compared_artifacts: tuple[str, ...]
    failed_component: str
    reason: str
    policy_version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "consistency_hash": self.consistency_hash,
            "compared_artifacts": self.compared_artifacts,
            "failed_component": self.failed_component,
            "reason": self.reason,
            "policy_version": self.policy_version,
        }


@dataclass(frozen=True)
class EvidenceSealResult:
    approved: bool
    evidence_seal_hash: str
    policy_bundle_hash: str
    evidence_chain_hash: str
    publication_lock_hash: str
    release_hash: str
    consistency_hash: str
    finalization_hash: str
    timestamp_hash: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "evidence_seal_hash": self.evidence_seal_hash,
            "policy_bundle_hash": self.policy_bundle_hash,
            "evidence_chain_hash": self.evidence_chain_hash,
            "publication_lock_hash": self.publication_lock_hash,
            "release_hash": self.release_hash,
            "consistency_hash": self.consistency_hash,
            "finalization_hash": self.finalization_hash,
            "timestamp_hash": self.timestamp_hash,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class SuricataPolicyGateResult:
    approved: bool
    severity: int | None
    threshold: int
    evidence_hash: str
    policy_version: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "severity": self.severity,
            "threshold": self.threshold,
            "evidence_hash": self.evidence_hash,
            "policy_version": self.policy_version,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class PublicationDecisionResult:
    artifact_id: str
    decision: PublicationDecision
    block_reason: BlockReason
    publish_allowed: bool
    audit: AuditEvidence
    details: tuple[str, ...] = ()

    @classmethod
    def blocked(
        cls,
        *,
        artifact_id: str,
        reason: BlockReason,
        decision: PublicationDecision = PublicationDecision.BLOCK_PUBLICATION,
        policy_version: str = "UNKNOWN",
        details: tuple[str, ...] = (),
        evidence_hashes: dict[str, str] | None = None,
    ) -> "PublicationDecisionResult":
        audit = AuditEvidence(
            artifact_id=artifact_id or "UNKNOWN_ARTIFACT",
            decision=decision.value,
            block_reason=reason.value,
            policy_version=policy_version or "UNKNOWN",
            evidence_hashes=evidence_hashes or {},
        )
        return cls(
            artifact_id=artifact_id or "UNKNOWN_ARTIFACT",
            decision=decision,
            block_reason=reason,
            publish_allowed=False,
            audit=audit,
            details=details,
        )

    @classmethod
    def allowed(
        cls,
        *,
        artifact_id: str,
        policy_version: str,
        evidence_hashes: dict[str, str],
        details: tuple[str, ...] = (),
    ) -> "PublicationDecisionResult":
        audit = AuditEvidence(
            artifact_id=artifact_id,
            decision=PublicationDecision.ALLOW_PUBLICATION.value,
            block_reason=BlockReason.NONE.value,
            policy_version=policy_version,
            evidence_hashes=evidence_hashes,
        )
        return cls(
            artifact_id=artifact_id,
            decision=PublicationDecision.ALLOW_PUBLICATION,
            block_reason=BlockReason.NONE,
            publish_allowed=True,
            audit=audit,
            details=details,
        )


def hash_payload(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def is_semver(value: str | None) -> bool:
    return bool(value and SEMVER_RE.fullmatch(value))


def is_sha256_ref(value: str | None) -> bool:
    return bool(value and SHA256_REF_RE.fullmatch(value))
