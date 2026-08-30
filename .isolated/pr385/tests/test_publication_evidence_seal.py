from __future__ import annotations

from publication.evidence_seal import REQUIRED_SEAL_ORDER, validate_evidence_seal
from publication.models import hash_payload


POLICY_VERSION = "1.0"
CONTRACT_VERSION = "PUBGOV-013-035"


def seal_inputs(**overrides: str) -> dict[str, str]:
    data = {name: hash_payload(name) for name in REQUIRED_SEAL_ORDER}
    data.update(overrides)
    return data


def seal(**overrides):
    kwargs = {
        "seal_inputs": seal_inputs(),
        "ordered_hash_names": REQUIRED_SEAL_ORDER,
        "policy_version": POLICY_VERSION,
        "publication_contract_version": CONTRACT_VERSION,
        "expected_policy_version": POLICY_VERSION,
        "expected_publication_contract_version": CONTRACT_VERSION,
    }
    kwargs.update(overrides)
    return validate_evidence_seal(**kwargs)


def test_complete_seal_pass() -> None:
    result = seal()

    assert result.approved is True
    assert result.reason == "EVIDENCE_SEAL_APPROVED"
    assert result.evidence_seal_hash.startswith("sha256:")
    assert result.policy_bundle_hash.startswith("sha256:")
    assert result.evidence_chain_hash.startswith("sha256:")
    assert result.publication_lock_hash.startswith("sha256:")
    assert result.release_hash.startswith("sha256:")
    assert result.consistency_hash.startswith("sha256:")
    assert result.finalization_hash.startswith("sha256:")
    assert result.timestamp_hash.startswith("sha256:")


def test_missing_seal_fails_closed() -> None:
    result = seal(seal_inputs=None)

    assert result.approved is False
    assert result.reason == "MISSING_SEAL"


def test_altered_seal_fails_closed() -> None:
    expected = seal_inputs()
    altered = {**expected, "release_hash": hash_payload("altered_release")}

    result = seal(seal_inputs=altered, expected_hashes=expected)

    assert result.approved is False
    assert result.reason == "MISMATCHED_HASHES"


def test_stale_seal_fails_closed() -> None:
    result = seal(policy_version="0.9")

    assert result.approved is False
    assert result.reason == "POLICY_MISMATCH"


def test_duplicate_seal_fails_closed() -> None:
    values = seal_inputs()
    duplicated = {**values, "release_hash": values["policy_bundle_hash"]}

    result = seal(seal_inputs=duplicated)

    assert result.approved is False
    assert result.reason == "DUPLICATED_HASH"


def test_ordering_fails_closed() -> None:
    result = seal(ordered_hash_names=tuple(reversed(REQUIRED_SEAL_ORDER)))

    assert result.approved is False
    assert result.reason == "UNORDERED_EVIDENCE"


def test_modified_metadata_fails_closed() -> None:
    result = seal(publication_contract_version="PUBGOV-013-034")

    assert result.approved is False
    assert result.reason == "PUBLICATION_CONTRACT_MISMATCH"


def test_missing_hash_fails_closed() -> None:
    result = seal(seal_inputs=seal_inputs(release_hash=""))

    assert result.approved is False
    assert result.reason == "MISSING_HASHES"


def test_deterministic_seal_pass() -> None:
    first = seal()
    second = seal()

    assert first.evidence_seal_hash == second.evidence_seal_hash
    assert first.to_dict() == second.to_dict()


def test_fail_closed_pass() -> None:
    result = validate_evidence_seal(
        seal_inputs=None,
        ordered_hash_names=None,
        policy_version=POLICY_VERSION,
        publication_contract_version=CONTRACT_VERSION,
        expected_policy_version=POLICY_VERSION,
        expected_publication_contract_version=CONTRACT_VERSION,
    )

    assert result.approved is False
    assert result.reason == "MISSING_SEAL"


def test_regression_pubgov_013_to_034_aggregator_includes_evidence_seal_hash() -> None:
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
    assert result.audit.evidence_hashes["evidence_seal_hash"].startswith("sha256:")


def test_runtime_aggregator_blocks_without_evidence_seal(monkeypatch) -> None:
    import publication.runtime_aggregator as runtime_aggregator
    from publication.models import BlockReason, EvidenceSealResult
    from tests.test_publication_runtime_aggregator import aggregate, example_record

    def blocked_seal(**kwargs):
        return EvidenceSealResult(
            approved=False,
            evidence_seal_hash="sha256:blocked_seal_hash",
            policy_bundle_hash="",
            evidence_chain_hash="",
            publication_lock_hash="",
            release_hash="",
            consistency_hash="",
            finalization_hash="",
            timestamp_hash="",
            reason="MISSING_SEAL",
        )

    monkeypatch.setattr(runtime_aggregator, "validate_evidence_seal", blocked_seal)
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
    assert result.audit.evidence_hashes["evidence_seal_hash"] == "sha256:blocked_seal_hash"
