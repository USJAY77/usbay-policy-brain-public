from __future__ import annotations

from runtime.computer_use.precommit_governance_validator import (
    BLOCKED,
    READY,
    READY_WITH_RESTRICTIONS,
    validate_precommit_governance,
)


HASH = "sha256:" + ("c" * 64)


def _metadata(**overrides):
    metadata = {
        "expected_result": READY,
        "governance_status": "VALID",
        "policy_schema_valid": True,
        "execution_contract_valid": True,
        "approval_contract_valid": True,
        "dependency_readiness_valid": True,
        "runtime_readiness_valid": True,
        "adapter_readiness_valid": True,
        "evidence_manifest_valid": True,
        "package_hash_valid": True,
        "evidence_hash_valid": True,
        "rollback_record_valid": True,
        "required_ci_checks": [{"id": "governance-check", "required": True, "status": "PASS"}],
        "required_tests": [{"id": "focused", "required": True, "status": "PASS"}],
        "required_approvals_present": True,
        "branch_protection_valid": True,
        "production_readiness_export_valid": True,
        "timestamp_fresh": True,
        "nonce_valid": True,
        "replay_protection_valid": True,
        "json_valid": True,
        "python_syntax_valid": True,
        "git_diff_valid": True,
        "forbidden_files_absent": True,
        "sensitive_data_absent": True,
        "secrets_absent": True,
        "unsupported_files_absent": True,
        "duplicate_manifests_absent": True,
        "duplicate_hashes_absent": True,
        "references_present": True,
        "references_well_formed": True,
        "restrictions": [],
        "manifest_hash": HASH,
        "computed_manifest_hash": HASH,
    }
    metadata.update(overrides)
    return metadata


def _blocked(result, reason: str):
    assert result.result == BLOCKED
    assert reason in result.reason_codes
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False


def test_valid_validation_ready() -> None:
    assert validate_precommit_governance(_metadata()).result == READY


def test_missing_policy_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(policy_schema_valid=False)), "MISSING_POLICY")


def test_missing_approval_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(required_approvals_present=False)), "MISSING_APPROVAL")


def test_missing_runtime_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(runtime_readiness_valid=False)), "MISSING_RUNTIME")


def test_missing_dependency_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(dependency_readiness_valid=False)), "MISSING_DEPENDENCY")


def test_missing_adapter_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(adapter_readiness_valid=False)), "MISSING_ADAPTER")


def test_missing_evidence_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(evidence_manifest_valid=False)), "MISSING_EVIDENCE")


def test_missing_rollback_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(rollback_record_valid=False)), "MISSING_ROLLBACK")


def test_missing_ci_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(required_ci_checks=[])), "MISSING_CI")


def test_missing_tests_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(required_tests=[])), "MISSING_TEST")


def test_hash_mismatch_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(computed_manifest_hash="sha256:" + ("d" * 64))), "HASH_MISMATCH")


def test_tampered_manifest_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(package_hash_valid=False)), "PACKAGE_HASH_INVALID")


def test_duplicate_manifest_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(duplicate_manifests_absent=False)), "DUPLICATE_MANIFEST")


def test_duplicate_hash_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(duplicate_hashes_absent=False)), "DUPLICATE_HASH")


def test_secret_detection_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(secrets_absent=False)), "SECRET_DETECTED")


def test_credential_detection_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(credential="synthetic")), "SENSITIVE_DATA_REJECTED")


def test_pii_detection_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(pii="synthetic")), "SENSITIVE_DATA_REJECTED")


def test_invalid_json_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(json_valid=False)), "INVALID_JSON")


def test_invalid_contract_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(execution_contract_valid=False)), "MISSING_CONTRACT")


def test_unsupported_state_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(governance_status="UNKNOWN")), "UNKNOWN_GOVERNANCE_STATUS")


def test_validator_exception_blocks() -> None:
    class ExplodingMetadata(dict):
        def get(self, _key, _default=None):
            raise RuntimeError("synthetic failure")

    _blocked(validate_precommit_governance(ExplodingMetadata()), "INTERNAL_ERROR")


def test_unknown_result_blocks() -> None:
    _blocked(validate_precommit_governance(_metadata(expected_result="MERGE_READY")), "UNKNOWN_RESULT")


def test_deterministic_output() -> None:
    assert validate_precommit_governance(_metadata()).to_dict() == validate_precommit_governance(_metadata()).to_dict()


def test_blocked_output() -> None:
    result = validate_precommit_governance(_metadata(policy_schema_valid=False))

    assert result.result == BLOCKED
    assert result.validation_hash.startswith("sha256:")


def test_ready_with_restrictions_requires_authorized_restriction() -> None:
    result = validate_precommit_governance(
        _metadata(
            expected_result=READY_WITH_RESTRICTIONS,
            governance_status="RESTRICTED",
            restrictions=[{"restriction_id": "review-window", "policy_authorized": True}],
        )
    )

    assert result.result == READY_WITH_RESTRICTIONS


def test_no_deployment_side_effects() -> None:
    result = validate_precommit_governance(_metadata())

    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
