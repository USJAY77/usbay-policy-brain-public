"""Fail-closed publication policy bundle readiness gate."""

from __future__ import annotations

from publication.models import (
    BlockReason,
    PolicyBundleReadinessResult,
    PolicyBundleValidationResult,
    PublicationDecision,
    hash_payload,
)


POLICY_BUNDLE_READINESS_VERSION = "USBAY-PUBGOV-026"

REQUIRED_POLICY_IDS = (
    "https://usbay.local/policy/publication/publication_registry_schema.json",
    "PUB-LINKEDIN-EXAMPLE-001",
    "USBAY_PUBLICATION_CLASSIFICATION_POLICY",
    "USBAY_PUBLICATION_APPROVAL_POLICY",
)

POLICY_KEY_TO_ID = {
    "registry_schema": "https://usbay.local/policy/publication/publication_registry_schema.json",
    "registry_record": "PUB-LINKEDIN-EXAMPLE-001",
    "classification_policy": "USBAY_PUBLICATION_CLASSIFICATION_POLICY",
    "approval_policy": "USBAY_PUBLICATION_APPROVAL_POLICY",
}


def evaluate_policy_bundle_readiness(
    validation_result: PolicyBundleValidationResult | None,
) -> PolicyBundleReadinessResult:
    if validation_result is None:
        return _blocked(
            reason="MISSING_BUNDLE_VALIDATION",
            missing_policy_ids=REQUIRED_POLICY_IDS,
            invalid_policy_ids=(),
        )

    if validation_result.valid:
        evidence = {
            "ready": True,
            "bundle_hash": validation_result.bundle_hash,
            "validation_evidence_hash": validation_result.evidence_hash,
            "required_policy_ids": REQUIRED_POLICY_IDS,
            "policy_version": validation_result.policy_version,
            "raw_policy_content_stored": False,
        }
        return PolicyBundleReadinessResult(
            ready=True,
            decision=PublicationDecision.ALLOW_PUBLICATION,
            block_reason=BlockReason.NONE,
            required_policy_ids=REQUIRED_POLICY_IDS,
            missing_policy_ids=(),
            invalid_policy_ids=(),
            evidence_hash=hash_payload(evidence),
            policy_version=validation_result.policy_version,
        )

    missing_policy_ids = _missing_policy_ids(validation_result)
    invalid_policy_ids = _invalid_policy_ids(validation_result, missing_policy_ids)
    return _blocked(
        reason=validation_result.reason,
        missing_policy_ids=missing_policy_ids,
        invalid_policy_ids=invalid_policy_ids,
        policy_version=validation_result.policy_version,
        validation_evidence_hash=validation_result.evidence_hash,
    )


def _missing_policy_ids(validation_result: PolicyBundleValidationResult) -> tuple[str, ...]:
    if validation_result.reason == "MISSING_POLICY_BUNDLE":
        return REQUIRED_POLICY_IDS
    if validation_result.reason == "MISSING_POLICY":
        return (_policy_id_for_rejected(validation_result.rejected_policy),)
    return ()


def _invalid_policy_ids(
    validation_result: PolicyBundleValidationResult,
    missing_policy_ids: tuple[str, ...],
) -> tuple[str, ...]:
    if missing_policy_ids:
        return ()
    if validation_result.rejected_policy == "BUNDLE":
        return REQUIRED_POLICY_IDS
    return (_policy_id_for_rejected(validation_result.rejected_policy),)


def _policy_id_for_rejected(rejected_policy: str) -> str:
    return POLICY_KEY_TO_ID.get(rejected_policy, rejected_policy or "UNKNOWN_POLICY")


def _blocked(
    *,
    reason: str,
    missing_policy_ids: tuple[str, ...],
    invalid_policy_ids: tuple[str, ...],
    policy_version: str = POLICY_BUNDLE_READINESS_VERSION,
    validation_evidence_hash: str = "",
) -> PolicyBundleReadinessResult:
    evidence = {
        "ready": False,
        "reason": reason,
        "missing_policy_ids": missing_policy_ids,
        "invalid_policy_ids": invalid_policy_ids,
        "validation_evidence_hash": validation_evidence_hash,
        "required_policy_ids": REQUIRED_POLICY_IDS,
        "policy_version": policy_version,
        "raw_policy_content_stored": False,
    }
    return PolicyBundleReadinessResult(
        ready=False,
        decision=PublicationDecision.BLOCK_PUBLICATION,
        block_reason=BlockReason.POLICY_BUNDLE_NOT_APPROVED,
        required_policy_ids=REQUIRED_POLICY_IDS,
        missing_policy_ids=missing_policy_ids,
        invalid_policy_ids=invalid_policy_ids,
        evidence_hash=hash_payload(evidence),
        policy_version=policy_version,
    )
