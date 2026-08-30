from __future__ import annotations

import copy
from pathlib import Path

import pytest

from governance.cross_repository_contracts import (
    CrossRepositoryContractError,
    canonical_contract_hash,
    canonical_contract_json,
    production_compatibility_decision,
    validate_approval_reference,
    validate_evidence_reference,
    validate_production_attestation,
    validate_registry,
)


ZERO_REF = "sha256:" + ("0" * 64)
ONE_REF = "sha256:" + ("1" * 64)
TWO_REF = "sha256:" + ("2" * 64)


def test_registry_validates_and_keeps_production_blocked_without_attestation() -> None:
    result = validate_registry(Path("."))

    assert result["status"] == "PASS"
    assert result["production_ready"] is False
    assert result["registry_hash"].startswith("sha256:")
    assert production_compatibility_decision(Path(".")) == {
        "status": "BLOCKED",
        "reason_code": "PRODUCTION_ATTESTATION_MISSING",
        "production_ready": False,
        "runtime_execution_authorized": False,
    }


def test_hash_vectors_are_canonical_order_independent() -> None:
    left = {"b": ["policy", "gateway"], "a": 1}
    right = {"a": 1, "b": ["policy", "gateway"]}

    assert canonical_contract_json(left) == canonical_contract_json(right)
    assert canonical_contract_hash(left) == canonical_contract_hash(right)


def test_content_change_changes_hash() -> None:
    original = canonical_contract_hash({"a": 1, "b": ["policy", "gateway"]})
    altered = canonical_contract_hash({"a": 1, "b": ["policy", "gateway", "changed"]})

    assert original != altered


def _valid_approval() -> dict:
    return {
        "schema_version": "usbay.cross_repo.approval_reference.v1",
        "approval_request_id": "approval-request-1",
        "approval_decision_id": "approval-decision-1",
        "policy_decision_reference": ZERO_REF,
        "human_authority_reference": ONE_REF,
        "decision": "approved",
        "issued_at": "2026-08-04T00:00:00Z",
        "expires_at": "2026-08-05T00:00:00Z",
        "evidence_hash": TWO_REF,
        "subject_action_reference": ZERO_REF,
        "revocation_reference": ZERO_REF,
        "supersession_reference": ZERO_REF,
        "ai_generated_only": False,
    }


def test_valid_approval_reference_passes() -> None:
    result = validate_approval_reference(_valid_approval(), production=True)

    assert result["status"] == "PASS"
    assert result["approval_reference_hash"].startswith("sha256:")


@pytest.mark.parametrize(
    ("field", "value", "code"),
    (
        ("ai_generated_only", True, "APPROVAL_NOT_HUMAN"),
        ("decision", "rejected", "APPROVAL_NOT_APPROVED"),
        ("evidence_hash", "8b7fad26067bef2e5dc153dc36d9bca7513dbcf65ea3978e95c7df5749d4633a", "APPROVAL_HASH_INVALID"),
        ("schema_version", "unknown", "APPROVAL_SCHEMA_UNSUPPORTED"),
    ),
)
def test_invalid_approval_reference_blocks(field: str, value: object, code: str) -> None:
    payload = _valid_approval()
    payload[field] = value

    with pytest.raises(CrossRepositoryContractError) as exc:
        validate_approval_reference(payload, production=True)

    assert exc.value.code == code


def _valid_evidence() -> dict:
    return {
        "schema_version": "usbay.cross_repo.evidence_reference.v1",
        "decision_evidence": ZERO_REF,
        "approval_evidence": ONE_REF,
        "execution_evidence": TWO_REF,
        "audit_chain_reference": ZERO_REF,
        "policy_package_hash": ONE_REF,
        "chronology_reference": TWO_REF,
        "runtime_attestation_reference": ZERO_REF,
        "integrity_manifest_reference": ONE_REF,
        "hash_algorithm": "sha256",
        "hash_encoding": "sha256_reference",
        "hex_case": "lowercase",
    }


def test_valid_evidence_reference_passes() -> None:
    result = validate_evidence_reference(_valid_evidence())

    assert result["status"] == "PASS"
    assert result["evidence_reference_hash"].startswith("sha256:")


def test_wrong_hash_algorithm_blocks_evidence_reference() -> None:
    payload = _valid_evidence()
    payload["hash_algorithm"] = "md5"

    with pytest.raises(CrossRepositoryContractError) as exc:
        validate_evidence_reference(payload)

    assert exc.value.code == "HASH_ALGORITHM_UNSUPPORTED"


def _valid_attestation() -> dict:
    registry = validate_registry(Path("."))
    return {
        "schema_version": "usbay.cross_repo.production_attestation.v1",
        "repository_identity_hash": registry["identity_hash"],
        "source_commit_sha": "9ec8793b7f27ae5a3bb0adcc7051e245dd6b98cf",
        "contract_registry_hash": registry["registry_hash"],
        "schema_hashes_hash": canonical_contract_hash({"schemas": "verified"}),
        "validator_version": "usbay.cross_repo.validator.v1",
        "validation_result": "PASS",
        "time_reference": "trusted-time-reference:human-approved",
        "environment_classification": "production",
        "production_readiness_decision": "READY",
        "human_approval_reference": ONE_REF,
        "self_issued": False,
    }


def test_valid_production_attestation_satisfies_only_compatibility_gate() -> None:
    result = production_compatibility_decision(Path("."), _valid_attestation())

    assert result["status"] == "PASS"
    assert result["production_ready"] is True
    assert result["runtime_execution_authorized"] is False


@pytest.mark.parametrize(
    ("field", "value", "code"),
    (
        ("environment_classification", "development", "ATTESTATION_NOT_PRODUCTION"),
        ("self_issued", True, "ATTESTATION_SELF_ISSUED"),
        ("validation_result", "FAIL", "ATTESTATION_NOT_READY"),
        ("contract_registry_hash", "legacy-unverified", "ATTESTATION_HASH_INVALID"),
    ),
)
def test_invalid_production_attestation_blocks(field: str, value: object, code: str) -> None:
    payload = _valid_attestation()
    payload[field] = value

    with pytest.raises(CrossRepositoryContractError) as exc:
        validate_production_attestation(payload)

    assert exc.value.code == code


def test_compatibility_metadata_cannot_authorize_execution(tmp_path: Path) -> None:
    source = Path("governance/contracts")
    target = tmp_path / "governance" / "contracts"
    target.mkdir(parents=True)
    for path in source.iterdir():
        if path.is_file():
            (target / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    registry_path = target / "cross_repository_contract_registry.json"
    registry = copy.deepcopy(__import__("json").loads(registry_path.read_text(encoding="utf-8")))
    registry["compatibility"]["runtime_execution_authorized"] = True
    registry_path.write_text(__import__("json").dumps(registry, sort_keys=True), encoding="utf-8")

    with pytest.raises(CrossRepositoryContractError) as exc:
        validate_registry(tmp_path)

    assert exc.value.code == "REGISTRY_EXECUTION_AUTHORITY_INVALID"
