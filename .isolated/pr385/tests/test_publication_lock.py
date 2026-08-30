from __future__ import annotations

from dataclasses import replace

from publication.commit_scope_validator import APPROVED_PUBGOV_013_021_FILES, validate_commit_scope
from publication.finalization_gate import evaluate_finalization_gate
from publication.models import (
    BlockReason,
    EvidenceChainVerificationResult,
    FinalPublicationReport,
    PublicationDecision,
    PublicationDecisionResult,
    hash_payload,
)
from publication.policy_bundle_readiness import evaluate_policy_bundle_readiness
from publication.policy_bundle_validator import load_publication_policy_bundle, validate_policy_bundle
from publication.publication_lock import evaluate_publication_lock


ARTIFACT_ID = "PUB-ARTIFACT-001"
ARTIFACT_VERSION = "1.0.0"
POLICY_VERSION = "1.0"
TARGET_CHANNEL = "LINKEDIN"
CREATED_AT = "2026-06-25T12:00:00+00:00"


def base_hashes() -> dict[str, str]:
    return {
        "registry_hash": hash_payload("registry"),
        "classification_hash": hash_payload("classification"),
        "sensitive_scan_hash": hash_payload("sensitive_scan"),
        "approval_validation_hash": hash_payload("approval"),
        "connector_gate_hash": hash_payload("connector"),
        "evidence_chain_verification_hash": hash_payload("evidence_chain"),
        "commit_scope_evidence_hash": hash_payload("commit_scope"),
        "policy_bundle_readiness_evidence_hash": hash_payload("policy_readiness"),
    }


def runtime_result() -> PublicationDecisionResult:
    return PublicationDecisionResult.allowed(
        artifact_id=ARTIFACT_ID,
        policy_version=POLICY_VERSION,
        evidence_hashes=base_hashes(),
    )


def commit_scope():
    return validate_commit_scope(APPROVED_PUBGOV_013_021_FILES)


def policy_readiness():
    return evaluate_policy_bundle_readiness(validate_policy_bundle(load_publication_policy_bundle()))


def evidence_chain(*, policy_version: str = POLICY_VERSION):
    return EvidenceChainVerificationResult.verified_chain(
        artifact_id=ARTIFACT_ID,
        policy_version=policy_version,
        evidence={"chain_hash": base_hashes()["evidence_chain_verification_hash"], "raw_payload_stored": False},
    )


def finalization_gate():
    return evaluate_finalization_gate(
        runtime_aggregator_result=runtime_result(),
        commit_scope_result=commit_scope(),
        policy_bundle_readiness_result=policy_readiness(),
        evidence_chain_result=evidence_chain(),
    )


def final_report(**overrides: object) -> FinalPublicationReport:
    hashes = base_hashes()
    data = {
        "artifact_id": ARTIFACT_ID,
        "artifact_version": ARTIFACT_VERSION,
        "target_channel": TARGET_CHANNEL,
        "final_decision": PublicationDecision.ALLOW_PUBLICATION,
        "block_reason": BlockReason.NONE,
        "policy_version": POLICY_VERSION,
        "evidence_chain_verification_hash": hashes["evidence_chain_verification_hash"],
        "audit_hash": hash_payload("audit"),
        "connector_gate_hash": hashes["connector_gate_hash"],
        "human_approval_hash": hashes["approval_validation_hash"],
        "sensitive_scan_hash": hashes["sensitive_scan_hash"],
        "classification_hash": hashes["classification_hash"],
        "registry_hash": hashes["registry_hash"],
        "created_at": CREATED_AT,
    }
    data.update(overrides)
    return FinalPublicationReport(**data)


def publication_lock(**overrides):
    dependencies = {
        "finalization_gate_result": finalization_gate(),
        "policy_bundle_readiness_result": policy_readiness(),
        "commit_scope_result": commit_scope(),
        "evidence_chain_result": evidence_chain(),
        "final_publication_report": final_report(),
    }
    dependencies.update(overrides)
    return evaluate_publication_lock(**dependencies)


def test_all_dependencies_valid_pass() -> None:
    result = publication_lock()

    assert result.locked is True
    assert result.decision == "LOCKED_READY"
    assert result.reason == "PUBLICATION_LOCK_READY"
    assert result.missing_controls == ()
    assert result.evidence_hash.startswith("sha256:")
    assert result.lock_id.startswith("sha256:")


def test_missing_finalization_gate_fails_closed() -> None:
    result = publication_lock(finalization_gate_result=None)

    assert result.locked is False
    assert "finalization_gate_result" in result.missing_controls


def test_rejected_commit_scope_fails_closed() -> None:
    result = publication_lock(commit_scope_result=validate_commit_scope(("gateway/app.py",)))

    assert result.locked is False
    assert "commit_scope_result" in result.missing_controls


def test_invalid_policy_bundle_readiness_fails_closed() -> None:
    result = publication_lock(policy_bundle_readiness_result=evaluate_policy_bundle_readiness(None))

    assert result.locked is False
    assert "policy_bundle_readiness_result" in result.missing_controls


def test_invalid_evidence_chain_fails_closed() -> None:
    result = publication_lock(
        evidence_chain_result=EvidenceChainVerificationResult.blocked(
            artifact_id=ARTIFACT_ID,
            reason=BlockReason.EVIDENCE_CHAIN_MISSING,
            policy_version=POLICY_VERSION,
            evidence={"reason": "missing"},
        )
    )

    assert result.locked is False
    assert "evidence_chain_result" in result.missing_controls


def test_incomplete_final_report_fails_closed() -> None:
    result = publication_lock(final_publication_report=final_report(block_reason=BlockReason.REPORT_INCOMPLETE))

    assert result.locked is False
    assert "final_publication_report" in result.missing_controls


def test_missing_required_hash_fails_closed() -> None:
    result = publication_lock(final_publication_report=final_report(registry_hash=""))

    assert result.locked is False
    assert "final_report_required_hashes" in result.missing_controls


def test_policy_version_mismatch_fails_closed() -> None:
    result = publication_lock(final_publication_report=final_report(policy_version="9.9"))

    assert result.locked is False
    assert "policy_version_mismatch" in result.missing_controls


def test_dependency_version_mismatch_fails_closed() -> None:
    result = publication_lock(finalization_gate_result=replace(finalization_gate(), policy_version="USBAY-PUBGOV-999"))

    assert result.locked is False
    assert "dependency_version_mismatch" in result.missing_controls


def test_missing_finalization_gate_evidence_hash_fails_closed() -> None:
    result = publication_lock(finalization_gate_result=replace(finalization_gate(), evidence_hash=""))

    assert result.locked is False
    assert "finalization_gate_evidence_hash" in result.missing_controls


def test_missing_commit_scope_evidence_hash_fails_closed() -> None:
    result = publication_lock(commit_scope_result=replace(commit_scope(), evidence_hash=""))

    assert result.locked is False
    assert "commit_scope_evidence_hash" in result.missing_controls


def test_missing_policy_bundle_readiness_hash_fails_closed() -> None:
    result = publication_lock(policy_bundle_readiness_result=replace(policy_readiness(), evidence_hash=""))

    assert result.locked is False
    assert "policy_bundle_readiness_hash" in result.missing_controls


def test_unknown_field_fails_closed() -> None:
    result = publication_lock(contract_fields={"finalization_gate_result": True, "unexpected": True})

    assert result.locked is False
    assert "unknown_publication_lock_contract_field" in result.missing_controls


def test_automatic_publication_attempt_fails_closed() -> None:
    result = publication_lock(automatic_publication_requested=True)

    assert result.locked is False
    assert "automatic_publication_attempt" in result.missing_controls


def test_external_connector_attempt_fails_closed() -> None:
    result = publication_lock(external_connector_requested=True)

    assert result.locked is False
    assert "external_connector_attempt" in result.missing_controls


def test_lock_id_is_deterministic() -> None:
    first = publication_lock()
    second = publication_lock()

    assert first.lock_id == second.lock_id


def test_evidence_hash_is_deterministic() -> None:
    first = publication_lock()
    second = publication_lock()

    assert first.evidence_hash == second.evidence_hash
    assert first.to_dict() == second.to_dict()


def test_fail_closed_default() -> None:
    result = evaluate_publication_lock(
        finalization_gate_result=None,
        policy_bundle_readiness_result=None,
        commit_scope_result=None,
        evidence_chain_result=None,
        final_publication_report=None,
    )

    assert result.locked is False
    assert result.decision == "LOCKED_BLOCKED"
    assert set(result.required_inputs) == {
        "finalization_gate_result",
        "policy_bundle_readiness_result",
        "commit_scope_result",
        "evidence_chain_result",
        "final_publication_report",
    }
