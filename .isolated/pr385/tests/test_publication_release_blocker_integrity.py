from __future__ import annotations

from dataclasses import replace

from publication.models import PublicationReleaseBlockerResult, ReleaseBlockerIntegrityResult
from publication.release_blocker_integrity import validate_release_blocker_integrity
from tests.test_publication_lock import commit_scope, final_report, finalization_gate, policy_readiness, publication_lock
from tests.test_publication_release_blocker import lock_release, release_blocker


def integrity(**overrides):
    release = lock_release()
    dependencies = {
        "commit_scope_result": commit_scope(),
        "policy_bundle_readiness_result": policy_readiness(),
        "finalization_gate_result": finalization_gate(),
        "publication_lock_result": publication_lock(),
        "publication_lock_release_result": release,
        "publication_release_blocker_result": release_blocker(publication_lock_release_result=release, release_hash=release.evidence_hash),
        "final_publication_report": final_report(),
        "release_hash": release.evidence_hash,
    }
    dependencies.update(overrides)
    return validate_release_blocker_integrity(**dependencies)


def test_valid_release_blocker_integrity_pass() -> None:
    result = integrity()

    assert result.approved is True
    assert result.rejected is False
    assert result.rejected_reasons == ()
    assert result.evidence_hash.startswith("sha256:")
    assert result.integrity_id.startswith("sha256:")


def test_missing_blocker_fails_closed() -> None:
    result = integrity(publication_release_blocker_result=None)

    assert result.approved is False
    assert "missing_release_blocker" in result.rejected_reasons


def test_missing_release_hash_fails_closed() -> None:
    result = integrity(release_hash=None)

    assert result.approved is False
    assert "missing_release_hash" in result.rejected_reasons


def test_mismatched_release_hash_fails_closed() -> None:
    result = integrity(release_hash="sha256:not_the_release_hash")

    assert result.approved is False
    assert "mismatched_release_blocker_hash" in result.rejected_reasons


def test_wrong_release_hash_fails_closed() -> None:
    release = lock_release()
    blocker = release_blocker(publication_lock_release_result=release, release_hash=release.evidence_hash)

    result = integrity(publication_release_blocker_result=blocker, release_hash="sha256:wrong_release_hash")

    assert result.approved is False
    assert "mismatched_release_blocker_hash" in result.rejected_reasons


def test_stale_blocker_fails_closed() -> None:
    stale = replace(release_blocker(), release_block_id="sha256:stale_blocker", evidence_hash="sha256:stale_evidence")

    result = integrity(publication_release_blocker_result=stale)

    assert result.approved is False
    assert "stale_release_blocker" in result.rejected_reasons
    assert "mismatched_release_blocker_hash" in result.rejected_reasons


def test_stale_blocker_timestamp_fails_closed() -> None:
    release = lock_release()
    old_report = final_report(created_at="2026-06-24T00:00:00+00:00")
    stale = release_blocker(
        publication_lock_release_result=release,
        final_publication_report=old_report,
        release_hash=release.evidence_hash,
    )

    result = integrity(publication_release_blocker_result=stale, final_publication_report=final_report())

    assert result.approved is False
    assert "stale_release_blocker" in result.rejected_reasons
    assert "mismatched_release_blocker_hash" in result.rejected_reasons


def test_blocker_before_lock_release_fails_closed() -> None:
    result = integrity(publication_lock_release_result=None)

    assert result.approved is False
    assert "blocker_generated_before_lock_release" in result.rejected_reasons


def test_blocker_after_release_lock_passes() -> None:
    release = lock_release()
    blocker = release_blocker(publication_lock_release_result=release, release_hash=release.evidence_hash)

    result = integrity(publication_lock_release_result=release, publication_release_blocker_result=blocker)

    assert result.approved is True
    assert result.rejected_reasons == ()


def test_blocker_before_finalization_gate_fails_closed() -> None:
    result = integrity(finalization_gate_result=None)

    assert result.approved is False
    assert "blocker_generated_before_finalization_gate" in result.rejected_reasons


def test_automatic_publication_attempt_fails_closed() -> None:
    result = integrity(automatic_publication_requested=True)

    assert result.approved is False
    assert "automatic_publication_attempt" in result.rejected_reasons


def test_connector_execution_attempt_fails_closed() -> None:
    result = integrity(connector_execution_requested=True)

    assert result.approved is False
    assert "connector_execution_attempt" in result.rejected_reasons


def test_http_api_publication_attempt_fails_closed() -> None:
    result = integrity(http_api_publication_requested=True)

    assert result.approved is False
    assert "http_api_publication_attempt" in result.rejected_reasons


def test_unknown_contract_field_fails_closed() -> None:
    result = integrity(contract_fields={"release_hash": True, "unexpected": True})

    assert result.approved is False
    assert "unknown_release_contract_field" in result.rejected_reasons


def test_unapproved_file_scope_fails_closed() -> None:
    result = integrity(commit_scope_result=replace(commit_scope(), approved=False, rejected_files=("gateway/app.py",)))

    assert result.approved is False
    assert "rejected_commit_scope" in result.rejected_reasons


def test_aggregator_blocks_without_blocker_integrity(monkeypatch) -> None:
    import publication.runtime_aggregator as runtime_aggregator
    from publication.models import BlockReason
    from tests.test_publication_runtime_aggregator import aggregate, example_record

    def blocked_integrity(**kwargs):
        return ReleaseBlockerIntegrityResult(
            approved=False,
            rejected=True,
            rejected_reasons=("mismatched_release_blocker_hash",),
            evidence_hash="sha256:blocked_integrity_evidence",
            policy_version="USBAY-PUBGOV-031",
            integrity_id="sha256:blocked_integrity_id",
            reason="RELEASE_BLOCKER_INTEGRITY_BLOCKED",
        )

    monkeypatch.setattr(runtime_aggregator, "validate_release_blocker_integrity", blocked_integrity)
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
    assert result.audit.evidence_hashes["release_blocker_integrity_evidence_hash"] == "sha256:blocked_integrity_evidence"


def test_aggregator_allows_only_when_all_prior_gates_plus_integrity_pass() -> None:
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
    assert result.audit.evidence_hashes["release_blocker_integrity_evidence_hash"].startswith("sha256:")
    assert result.audit.evidence_hashes["release_blocker_integrity_id"].startswith("sha256:")


def test_deterministic_evidence_hash() -> None:
    first = integrity()
    second = integrity()

    assert first.evidence_hash == second.evidence_hash
    assert first.to_dict() == second.to_dict()
