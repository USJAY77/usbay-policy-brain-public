from __future__ import annotations

import json
from pathlib import Path

from publication.evidence_chain import REQUIRED_EVIDENCE_ORDER, verify_evidence_chain
from publication.models import BlockReason, EvidenceChainEntry, EvidenceChainStage, RegistryRecord, hash_payload


ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = ROOT / "policy" / "publication" / "publication_registry_record.example.json"


def example_record(**overrides: object) -> RegistryRecord:
    data = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
    data.update(overrides)
    return RegistryRecord.from_dict(data)


def entries(record: RegistryRecord) -> tuple[EvidenceChainEntry, ...]:
    return tuple(
        EvidenceChainEntry(
            stage=stage,
            artifact_id=record.artifact_id,
            artifact_version=record.version,
            policy_version=record.policy_version,
            evidence_hash=hash_payload({"stage": stage.value, "artifact_id": record.artifact_id}),
        )
        for stage in REQUIRED_EVIDENCE_ORDER
    )


def test_evidence_chain_verifier_allows_complete_ordered_chain() -> None:
    record = example_record()

    result = verify_evidence_chain(record=record, entries=entries(record))

    assert result.verified is True
    assert result.block_reason == BlockReason.NONE
    assert result.audit.evidence_hashes["evidence_chain_verification_hash"].startswith("sha256:")
    assert result.evidence["raw_evidence_stored"] is False


def test_evidence_chain_verifier_blocks_missing_stage() -> None:
    record = example_record()

    result = verify_evidence_chain(record=record, entries=entries(record)[:-1])

    assert result.verified is False
    assert result.block_reason == BlockReason.EVIDENCE_CHAIN_MISSING


def test_evidence_chain_verifier_blocks_invalid_order() -> None:
    record = example_record()
    chain = list(entries(record))
    chain[0], chain[1] = chain[1], chain[0]

    result = verify_evidence_chain(record=record, entries=chain)

    assert result.verified is False
    assert result.block_reason == BlockReason.EVIDENCE_ORDER_INVALID


def test_evidence_chain_verifier_blocks_duplicate_stage() -> None:
    record = example_record()
    chain = list(entries(record))
    chain[-1] = EvidenceChainEntry(
        stage=EvidenceChainStage.CONNECTOR_GATE,
        artifact_id=record.artifact_id,
        artifact_version=record.version,
        policy_version=record.policy_version,
        evidence_hash=hash_payload({"duplicate": "connector"}),
    )

    result = verify_evidence_chain(record=record, entries=chain)

    assert result.verified is False
    assert result.block_reason == BlockReason.DUPLICATE_EVIDENCE_STAGE


def test_evidence_chain_verifier_blocks_malformed_stage_hash() -> None:
    record = example_record()
    chain = list(entries(record))
    chain[2] = EvidenceChainEntry(
        stage=EvidenceChainStage.SENSITIVE_DATA_SCAN,
        artifact_id=record.artifact_id,
        artifact_version=record.version,
        policy_version=record.policy_version,
        evidence_hash="not-a-hash",
    )

    result = verify_evidence_chain(record=record, entries=chain)

    assert result.verified is False
    assert result.block_reason == BlockReason.HASH_MISMATCH


def test_evidence_chain_verifier_blocks_artifact_mismatch() -> None:
    record = example_record()
    chain = list(entries(record))
    chain[3] = EvidenceChainEntry(
        stage=EvidenceChainStage.HUMAN_APPROVAL,
        artifact_id="other-artifact",
        artifact_version=record.version,
        policy_version=record.policy_version,
        evidence_hash=hash_payload({"stage": "approval"}),
    )

    result = verify_evidence_chain(record=record, entries=chain)

    assert result.verified is False
    assert result.block_reason == BlockReason.EVIDENCE_ARTIFACT_MISMATCH


def test_evidence_chain_verifier_blocks_version_mismatch() -> None:
    record = example_record()
    chain = list(entries(record))
    chain[4] = EvidenceChainEntry(
        stage=EvidenceChainStage.RUNTIME_VALIDATOR,
        artifact_id=record.artifact_id,
        artifact_version="2.0.0",
        policy_version=record.policy_version,
        evidence_hash=hash_payload({"stage": "runtime"}),
    )

    result = verify_evidence_chain(record=record, entries=chain)

    assert result.verified is False
    assert result.block_reason == BlockReason.EVIDENCE_ARTIFACT_MISMATCH


def test_evidence_chain_verifier_blocks_policy_mismatch() -> None:
    record = example_record()
    chain = list(entries(record))
    chain[5] = EvidenceChainEntry(
        stage=EvidenceChainStage.CONNECTOR_GATE,
        artifact_id=record.artifact_id,
        artifact_version=record.version,
        policy_version="0.0.0",
        evidence_hash=hash_payload({"stage": "connector"}),
    )

    result = verify_evidence_chain(record=record, entries=chain)

    assert result.verified is False
    assert result.block_reason == BlockReason.POLICY_VERSION_MISMATCH
