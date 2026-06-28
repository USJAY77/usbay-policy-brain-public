from __future__ import annotations

from dataclasses import replace

from publication.models import PublicationReleaseBlockerResult
from publication.publication_lock_release import evaluate_publication_lock_release
from publication.publication_release_blocker import validate_publication_release_blocker
from tests.test_publication_lock import commit_scope, final_report, finalization_gate, policy_readiness, publication_lock


def lock_release():
    return evaluate_publication_lock_release(
        finalization_gate_result=finalization_gate(),
        publication_lock_result=publication_lock(),
    )


def release_blocker(**overrides):
    release = lock_release()
    dependencies = {
        "commit_scope_result": commit_scope(),
        "policy_bundle_readiness_result": policy_readiness(),
        "finalization_gate_result": finalization_gate(),
        "publication_lock_result": publication_lock(),
        "publication_lock_release_result": release,
        "final_publication_report": final_report(),
        "release_hash": release.evidence_hash,
    }
    dependencies.update(overrides)
    return validate_publication_release_blocker(**dependencies)


def test_valid_blocker_pass() -> None:
    result = release_blocker()

    assert result.approved is True
    assert result.rejected is False
    assert result.rejected_reasons == ()
    assert result.reason == "PUBLICATION_RELEASE_BLOCKER_APPROVED"
    assert result.evidence_hash.startswith("sha256:")
    assert result.release_block_id.startswith("sha256:")


def test_missing_commit_scope_fails_closed() -> None:
    result = release_blocker(commit_scope_result=None)

    assert result.approved is False
    assert "missing_commit_scope" in result.rejected_reasons


def test_missing_policy_bundle_readiness_fails_closed() -> None:
    result = release_blocker(policy_bundle_readiness_result=None)

    assert result.approved is False
    assert "missing_policy_bundle_readiness" in result.rejected_reasons


def test_missing_finalization_gate_fails_closed() -> None:
    result = release_blocker(finalization_gate_result=None)

    assert result.approved is False
    assert "missing_finalization_gate" in result.rejected_reasons


def test_missing_publication_lock_fails_closed() -> None:
    result = release_blocker(publication_lock_result=None)

    assert result.approved is False
    assert "missing_publication_lock" in result.rejected_reasons


def test_missing_release_hash_fails_closed() -> None:
    result = release_blocker(release_hash=None)

    assert result.approved is False
    assert "missing_release_hash" in result.rejected_reasons


def test_invalid_mismatched_release_hash_fails_closed() -> None:
    result = release_blocker(release_hash="sha256:not_the_release_hash")

    assert result.approved is False
    assert "mismatched_release_hash" in result.rejected_reasons


def test_automatic_publication_attempt_fails_closed() -> None:
    result = release_blocker(automatic_publication_requested=True)

    assert result.approved is False
    assert "automatic_publication_attempt" in result.rejected_reasons


def test_connector_attempt_fails_closed() -> None:
    result = release_blocker(connector_execution_requested=True)

    assert result.approved is False
    assert "connector_execution_attempt" in result.rejected_reasons


def test_http_api_publication_attempt_fails_closed() -> None:
    result = release_blocker(http_api_publication_requested=True)

    assert result.approved is False
    assert "http_api_publication_attempt" in result.rejected_reasons


def test_unknown_contract_field_fails_closed() -> None:
    result = release_blocker(contract_fields={"release_hash": True, "unexpected": True})

    assert result.approved is False
    assert "unknown_release_contract_field" in result.rejected_reasons


def test_invalid_policy_version_fails_closed() -> None:
    result = release_blocker(finalization_gate_result=replace(finalization_gate(), policy_version="USBAY-PUBGOV-999"))

    assert result.approved is False
    assert "invalid_policy_version" in result.rejected_reasons


def test_deterministic_evidence_hash() -> None:
    first = release_blocker()
    second = release_blocker()

    assert first.evidence_hash == second.evidence_hash
    assert first.to_dict() == second.to_dict()


def test_runtime_aggregator_blocks_without_release_blocker_evidence(monkeypatch) -> None:
    import publication.runtime_aggregator as runtime_aggregator
    from publication.models import BlockReason
    from tests.test_publication_runtime_aggregator import aggregate, example_record

    def blocked_release_blocker(**kwargs):
        return PublicationReleaseBlockerResult(
            approved=False,
            rejected=True,
            rejected_reasons=("missing_release_hash",),
            evidence_hash="sha256:blocked_release_evidence",
            policy_version="USBAY-PUBGOV-030",
            release_block_id="sha256:blocked_release_id",
            reason="PUBLICATION_RELEASE_BLOCKER_BLOCKED",
        )

    monkeypatch.setattr(runtime_aggregator, "validate_publication_release_blocker", blocked_release_blocker)
    record = example_record()

    result = aggregate(
        record,
        connector_policy={
            "policy_version": record.policy_version,
            "allowed_target_channels": [record.target_channel],
        },
    )

    assert result.publish_allowed is False
    assert result.block_reason == BlockReason.PUBLICATION_RELEASE_BLOCKED
    assert result.audit.evidence_hashes["publication_release_blocker_evidence_hash"] == "sha256:blocked_release_evidence"


def test_runtime_aggregator_allows_only_with_prior_gates_and_release_blocker_valid() -> None:
    from tests.test_publication_runtime_aggregator import aggregate, example_record

    record = example_record()
    result = aggregate(
        record,
        connector_policy={
            "policy_version": record.policy_version,
            "allowed_target_channels": [record.target_channel],
        },
    )

    assert result.publish_allowed is True
    assert result.audit.evidence_hashes["publication_release_blocker_evidence_hash"].startswith("sha256:")
    assert result.audit.evidence_hashes["publication_release_block_id"].startswith("sha256:")
