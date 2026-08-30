from __future__ import annotations

from dataclasses import replace

from publication.models import PublicationLockResult
from publication.publication_lock_release import evaluate_publication_lock_release
from tests.test_publication_lock import finalization_gate, publication_lock


def release_guard(**overrides):
    dependencies = {
        "finalization_gate_result": finalization_gate(),
        "publication_lock_result": publication_lock(),
    }
    dependencies.update(overrides)
    return evaluate_publication_lock_release(**dependencies)


def blocked_lock(*reasons: str) -> PublicationLockResult:
    valid = publication_lock()
    return replace(
        valid,
        locked=False,
        decision="LOCKED_BLOCKED",
        reason="PUBLICATION_LOCK_BLOCKED",
        missing_controls=tuple(reasons),
    )


def test_valid_release_pass() -> None:
    result = release_guard()

    assert result.approved is True
    assert result.reason == "PUBLICATION_LOCK_RELEASE_APPROVED"
    assert result.rejected_reasons == ()
    assert result.release_id.startswith("sha256:")
    assert result.lock_id.startswith("sha256:")
    assert result.evidence_hash.startswith("sha256:")


def test_missing_finalization_fails_closed() -> None:
    result = release_guard(finalization_gate_result=None)

    assert result.approved is False
    assert "missing_finalization_gate" in result.rejected_reasons


def test_missing_lock_fails_closed() -> None:
    result = release_guard(publication_lock_result=None)

    assert result.approved is False
    assert "missing_publication_lock" in result.rejected_reasons


def test_missing_lock_id_fails_closed() -> None:
    result = release_guard(publication_lock_result=replace(publication_lock(), lock_id=""))

    assert result.approved is False
    assert "missing_lock_id" in result.rejected_reasons


def test_missing_evidence_hash_fails_closed() -> None:
    result = release_guard(publication_lock_result=replace(publication_lock(), evidence_hash=""))

    assert result.approved is False
    assert "missing_lock_evidence_hash" in result.rejected_reasons


def test_missing_finalization_evidence_hash_fails_closed() -> None:
    result = release_guard(finalization_gate_result=replace(finalization_gate(), evidence_hash=""))

    assert result.approved is False
    assert "missing_finalization_evidence_hash" in result.rejected_reasons


def test_invalid_policy_bundle_fails_closed() -> None:
    result = release_guard(publication_lock_result=blocked_lock("policy_bundle_readiness_result"))

    assert result.approved is False
    assert "policy_bundle_readiness_result" in result.rejected_reasons


def test_rejected_commit_scope_fails_closed() -> None:
    result = release_guard(publication_lock_result=blocked_lock("commit_scope_result"))

    assert result.approved is False
    assert "commit_scope_result" in result.rejected_reasons


def test_invalid_evidence_chain_fails_closed() -> None:
    result = release_guard(publication_lock_result=blocked_lock("evidence_chain_result"))

    assert result.approved is False
    assert "evidence_chain_result" in result.rejected_reasons


def test_automatic_publication_attempt_fails_closed() -> None:
    result = release_guard(automatic_publication_requested=True)

    assert result.approved is False
    assert "automatic_publication_attempt" in result.rejected_reasons


def test_external_connector_attempt_fails_closed() -> None:
    result = release_guard(external_connector_requested=True)

    assert result.approved is False
    assert "external_connector_attempt" in result.rejected_reasons


def test_deterministic_release_id() -> None:
    first = release_guard()
    second = release_guard()

    assert first.release_id == second.release_id


def test_deterministic_evidence_hash() -> None:
    first = release_guard()
    second = release_guard()

    assert first.evidence_hash == second.evidence_hash
    assert first.to_dict() == second.to_dict()


def test_aggregator_requires_publication_lock_release_evidence_hash() -> None:
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
    assert result.audit.evidence_hashes["publication_lock_release_evidence_hash"].startswith("sha256:")
    assert result.audit.evidence_hashes["publication_lock_release_id"].startswith("sha256:")
