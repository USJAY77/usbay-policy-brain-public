from __future__ import annotations

from publication.evidence_consistency_gate import REQUIRED_EVIDENCE_COMPONENT_ORDER, validate_evidence_consistency_gate
from publication.models import hash_payload


RUNTIME_POLICY_VERSION = "1.0"
RUNTIME_GENERATION_ID = "PUB-ARTIFACT-001:1.0.0"


def component(name: str, *, index: int, **overrides: str) -> dict[str, str]:
    data = {
        "component": name,
        "evidence_hash": hash_payload(f"{name}:{index}"),
        "runtime_policy_version": RUNTIME_POLICY_VERSION,
        "runtime_generation_id": RUNTIME_GENERATION_ID,
        "component_policy_version": "",
    }
    data.update(overrides)
    return data


def valid_components(**overrides: dict[str, str]) -> tuple[dict[str, str], ...]:
    items = []
    for index, name in enumerate(REQUIRED_EVIDENCE_COMPONENT_ORDER):
        items.append(component(name, index=index, **overrides.get(name, {})))
    return tuple(items)


def validate(components=None):
    return validate_evidence_consistency_gate(
        components=valid_components() if components is None else components,
        runtime_policy_version=RUNTIME_POLICY_VERSION,
        runtime_generation_id=RUNTIME_GENERATION_ID,
    )


def test_valid_evidence_pass() -> None:
    result = validate()

    assert result.approved is True
    assert result.reason == "EVIDENCE_CONSISTENCY_APPROVED"
    assert result.compared_artifacts == REQUIRED_EVIDENCE_COMPONENT_ORDER
    assert result.consistency_hash.startswith("sha256:")


def test_stale_evidence_fails() -> None:
    items = list(valid_components())
    items[3] = {**items[3], "runtime_generation_id": "STALE:1.0.0"}

    result = validate(tuple(items))

    assert result.approved is False
    assert result.reason == "INCONSISTENT_RUNTIME_GENERATION"
    assert result.failed_component == "human_approval"


def test_missing_evidence_fails() -> None:
    result = validate(valid_components()[:-1])

    assert result.approved is False
    assert result.reason == "UNORDERED_CHAIN"


def test_mismatched_hash_fails() -> None:
    items = list(valid_components())
    items[0] = {**items[0], "evidence_hash": hash_payload("wrong"), "expected_evidence_hash": items[0]["evidence_hash"]}

    result = validate(tuple(items))

    assert result.approved is False
    assert result.reason == "HASH_MISMATCH"
    assert result.failed_component == "registry"


def test_malformed_artifact_fails() -> None:
    items = list(valid_components())
    items[0] = {**items[0], "evidence_hash": "not-a-sha"}

    result = validate(tuple(items))

    assert result.approved is False
    assert result.reason == "MALFORMED_EVIDENCE"
    assert result.failed_component == "registry"


def test_mismatched_version_fails() -> None:
    items = list(valid_components())
    items[1] = {**items[1], "runtime_policy_version": "9.9"}

    result = validate(tuple(items))

    assert result.approved is False
    assert result.reason == "POLICY_VERSION_MISMATCH"
    assert result.failed_component == "classification"


def test_duplicated_artifact_fails() -> None:
    items = list(valid_components())
    items[2] = {**items[2], "component": "classification"}

    result = validate(tuple(items))

    assert result.approved is False
    assert result.reason == "DUPLICATED_ARTIFACT"


def test_unknown_dependency_fails() -> None:
    items = list(valid_components())
    items[0] = {**items[0], "component": "unknown"}

    result = validate(tuple(items))

    assert result.approved is False
    assert result.reason == "UNKNOWN_DEPENDENCY"


def test_inconsistent_ordering_fails() -> None:
    items = list(valid_components())
    items[0], items[1] = items[1], items[0]

    result = validate(tuple(items))

    assert result.approved is False
    assert result.reason == "UNORDERED_CHAIN"


def test_timestamp_drift_fails() -> None:
    items = list(valid_components(registry={"runtime_timestamp": "2026-06-25T00:00:00Z"}))
    items[1] = {**items[1], "runtime_timestamp": "2026-06-26T00:00:00Z"}

    result = validate(tuple(items))

    assert result.approved is False
    assert result.reason == "TIMESTAMP_DRIFT"


def test_deterministic_hash_pass() -> None:
    first = validate()
    second = validate()

    assert first.consistency_hash == second.consistency_hash
    assert first.to_dict() == second.to_dict()


def test_regression_pubgov_013_through_032_aggregator_includes_consistency_hash() -> None:
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
    assert result.audit.evidence_hashes["evidence_consistency_hash"].startswith("sha256:")


def test_runtime_aggregator_blocks_without_evidence_consistency_hash(monkeypatch) -> None:
    import publication.runtime_aggregator as runtime_aggregator
    from publication.models import BlockReason, EvidenceConsistencyResult
    from tests.test_publication_runtime_aggregator import aggregate, example_record

    def blocked_consistency(**kwargs):
        return EvidenceConsistencyResult(
            approved=False,
            consistency_hash="sha256:blocked_consistency_hash",
            compared_artifacts=("registry",),
            failed_component="registry",
            reason="HASH_MISMATCH",
            policy_version="USBAY-PUBGOV-033",
        )

    monkeypatch.setattr(runtime_aggregator, "validate_evidence_consistency_gate", blocked_consistency)
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
    assert result.audit.evidence_hashes["evidence_consistency_hash"] == "sha256:blocked_consistency_hash"
