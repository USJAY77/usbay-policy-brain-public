from __future__ import annotations

from publication.commit_scope_validator import APPROVED_PUBGOV_013_021_FILES, validate_commit_scope
from publication.finalization_gate import evaluate_finalization_gate
from publication.models import (
    BlockReason,
    EvidenceChainVerificationResult,
    PublicationDecision,
    PublicationDecisionResult,
    hash_payload,
)
from publication.policy_bundle_readiness import evaluate_policy_bundle_readiness
from publication.policy_bundle_validator import load_publication_policy_bundle, validate_policy_bundle


ARTIFACT_ID = "PUB-ARTIFACT-001"
POLICY_VERSION = "1.0"


def runtime_result(*, policy_version: str = POLICY_VERSION, evidence_hashes: dict[str, str] | None = None):
    hashes = {
        "registry_hash": hash_payload("registry"),
        "classification_hash": hash_payload("classification"),
        "sensitive_scan_hash": hash_payload("sensitive_scan"),
        "approval_validation_hash": hash_payload("approval"),
        "connector_gate_hash": hash_payload("connector"),
        "evidence_chain_verification_hash": hash_payload("evidence_chain"),
        "commit_scope_evidence_hash": hash_payload("commit_scope"),
        "policy_bundle_readiness_evidence_hash": hash_payload("policy_readiness"),
    }
    if evidence_hashes is not None:
        hashes.update(evidence_hashes)
    return PublicationDecisionResult.allowed(
        artifact_id=ARTIFACT_ID,
        policy_version=policy_version,
        evidence_hashes=hashes,
    )


def commit_scope():
    return validate_commit_scope(APPROVED_PUBGOV_013_021_FILES)


def policy_readiness():
    return evaluate_policy_bundle_readiness(validate_policy_bundle(load_publication_policy_bundle()))


def evidence_chain(*, policy_version: str = POLICY_VERSION):
    return EvidenceChainVerificationResult.verified_chain(
        artifact_id=ARTIFACT_ID,
        policy_version=policy_version,
        evidence={"chain_hash": hash_payload("ordered_chain"), "raw_payload_stored": False},
    )


def finalization(**overrides):
    dependencies = {
        "runtime_aggregator_result": runtime_result(),
        "commit_scope_result": commit_scope(),
        "policy_bundle_readiness_result": policy_readiness(),
        "evidence_chain_result": evidence_chain(),
    }
    dependencies.update(overrides)
    return evaluate_finalization_gate(**dependencies)


def test_all_dependencies_valid_pass() -> None:
    result = finalization()

    assert result.ready is True
    assert result.decision == "READY"
    assert result.reason == "FINALIZATION_READY"
    assert result.missing_controls == ()
    assert result.evidence_hash.startswith("sha256:")


def test_missing_commit_scope_fails_closed() -> None:
    result = finalization(commit_scope_result=None)

    assert result.ready is False
    assert "commit_scope_result" in result.missing_controls


def test_rejected_commit_scope_fails_closed() -> None:
    result = finalization(commit_scope_result=validate_commit_scope(("gateway/app.py",)))

    assert result.ready is False
    assert "commit_scope_result" in result.missing_controls


def test_missing_policy_readiness_fails_closed() -> None:
    result = finalization(policy_bundle_readiness_result=None)

    assert result.ready is False
    assert "policy_bundle_readiness_result" in result.missing_controls


def test_invalid_policy_readiness_fails_closed() -> None:
    result = finalization(policy_bundle_readiness_result=evaluate_policy_bundle_readiness(None))

    assert result.ready is False
    assert "policy_bundle_readiness_result" in result.missing_controls


def test_missing_evidence_chain_fails_closed() -> None:
    result = finalization(evidence_chain_result=None)

    assert result.ready is False
    assert "evidence_chain_result" in result.missing_controls


def test_invalid_evidence_chain_fails_closed() -> None:
    result = finalization(
        evidence_chain_result=EvidenceChainVerificationResult.blocked(
            artifact_id=ARTIFACT_ID,
            reason=BlockReason.EVIDENCE_CHAIN_MISSING,
            policy_version=POLICY_VERSION,
            evidence={"reason": "missing"},
        )
    )

    assert result.ready is False
    assert "evidence_chain_result" in result.missing_controls


def test_aggregator_allow_without_finalization_inputs_fails_closed() -> None:
    result = finalization(
        runtime_aggregator_result=runtime_result(),
        commit_scope_result=None,
        policy_bundle_readiness_result=None,
        evidence_chain_result=None,
    )

    assert result.ready is False
    assert result.decision == "BLOCKED"
    assert set(result.missing_controls) >= {
        "commit_scope_result",
        "policy_bundle_readiness_result",
        "evidence_chain_result",
    }


def test_dependency_version_mismatch_fails_closed() -> None:
    result = finalization(runtime_aggregator_result=runtime_result(policy_version="9.9"))

    assert result.ready is False
    assert "dependency_version_mismatch" in result.missing_controls


def test_unknown_field_fails_closed() -> None:
    result = finalization(contract_fields={"runtime_aggregator_result": True, "unexpected": True})

    assert result.ready is False
    assert "unknown_finalization_contract_field" in result.missing_controls


def test_missing_required_hash_fails_closed() -> None:
    result = finalization(runtime_aggregator_result=runtime_result(evidence_hashes={"registry_hash": ""}))

    assert result.ready is False
    assert "required_runtime_hashes" in result.missing_controls


def test_evidence_hash_is_deterministic() -> None:
    first = finalization()
    second = finalization()

    assert first.evidence_hash == second.evidence_hash
    assert first.to_dict() == second.to_dict()


def test_fail_closed_default() -> None:
    result = evaluate_finalization_gate(
        runtime_aggregator_result=None,
        commit_scope_result=None,
        policy_bundle_readiness_result=None,
        evidence_chain_result=None,
    )

    assert result.ready is False
    assert result.decision == "BLOCKED"
    assert set(result.required_inputs) == {
        "runtime_aggregator_result",
        "commit_scope_result",
        "policy_bundle_readiness_result",
        "evidence_chain_result",
    }


def test_runtime_result_blocked_fails_closed() -> None:
    blocked = PublicationDecisionResult.blocked(
        artifact_id=ARTIFACT_ID,
        reason=BlockReason.FINALIZATION_GATE_BLOCKED,
        decision=PublicationDecision.BLOCK_PUBLICATION,
        policy_version=POLICY_VERSION,
    )

    result = finalization(runtime_aggregator_result=blocked)

    assert result.ready is False
    assert "runtime_aggregator_result" in result.missing_controls
