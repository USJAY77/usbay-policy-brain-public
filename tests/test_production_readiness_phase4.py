from __future__ import annotations

import copy
import json
from pathlib import Path

from governance.production_readiness_phase4 import (
    ALLOWED_FIELDS,
    BLOCKED,
    CAPABILITY_STATES,
    INVALID,
    REQUIRED_FIELDS,
    READY_METADATA_ONLY,
    deterministic_phase4_signature_reference,
    evaluate_phase4_authorization_boundary,
    export_phase4_evidence,
    load_phase4_manifest,
    load_phase4_manifest_safely,
)


TIMESTAMP = "2026-07-25T12:00:00Z"


def _manifest() -> dict:
    payload = copy.deepcopy(load_phase4_manifest())
    payload["signature_reference"] = deterministic_phase4_signature_reference(payload)
    return payload


def _assert_blocked(manifest: dict, reason: str) -> None:
    result = evaluate_phase4_authorization_boundary(manifest, timestamp=TIMESTAMP)
    assert result.decision == BLOCKED
    assert reason in result.blocking_reasons
    assert result.production_boundary_ready is False
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
    assert result.release_authorized is False


def test_valid_phase4_manifest_is_ready_metadata_only() -> None:
    result = evaluate_phase4_authorization_boundary(_manifest(), timestamp=TIMESTAMP)

    assert result.decision == READY_METADATA_ONLY
    assert result.blocking_reasons == ()
    assert result.production_boundary_ready is True
    assert "execution" not in result.decision.lower()
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
    assert result.release_authorized is False
    assert result.to_dict()["phase4_evaluation_hash"].startswith("sha256:")


def test_phase4_schema_and_manifest_boundaries_are_consistent() -> None:
    schema = json.loads(Path("governance/evidence/production_readiness_phase4_schema.json").read_text(encoding="utf-8"))
    manifest = _manifest()

    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == REQUIRED_FIELDS
    assert set(schema["properties"]) == ALLOWED_FIELDS
    assert set(manifest) <= ALLOWED_FIELDS


def test_capability_state_rendering_is_deterministic_and_truthful() -> None:
    result = evaluate_phase4_authorization_boundary(_manifest(), timestamp=TIMESTAMP)

    assert tuple(sorted(CAPABILITY_STATES)) == (
        "CONFIGURED",
        "INVALID",
        "MISSING",
        "NOT_APPLICABLE",
        "UNAVAILABLE",
        "VERIFIED_INTERFACE",
        "VERIFIED_METADATA",
    )
    assert result.capability_states["external_signing"] == "VERIFIED_INTERFACE"
    assert result.capability_states["rfc3161"] == "VERIFIED_METADATA"
    assert result.capability_states["worm"] == "VERIFIED_METADATA"


def test_documentation_never_claims_live_external_capability() -> None:
    docs = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "docs/governance/PRODUCTION_READINESS_PHASE_4_AUTHORIZATION_BOUNDARY.md",
            "docs/governance/PRODUCTION_READINESS_PHASE_BOUNDARIES.md",
        )
    )

    for required in (
        "Metadata validation is not operational deployment",
        "Metadata validation is not live signing",
        "Metadata validation is not live RFC3161",
        "Metadata validation is not WORM evidence",
        "Metadata validation is not runtime authorization",
        "Gateway",
    ):
        assert required in docs
    assert "Phase 4 does not claim live provider availability" in docs


def test_export_phase4_evidence_is_hash_only_and_flags_false() -> None:
    exported = export_phase4_evidence(evaluate_phase4_authorization_boundary(_manifest(), timestamp=TIMESTAMP))

    assert exported["evidence_export_hash"].startswith("sha256:")
    assert exported["execution_allowed"] is False
    assert exported["provider_execution"] is False
    assert exported["production_activation"] is False
    assert exported["deployment_authorized"] is False
    assert exported["release_authorized"] is False
    assert "signature_material" not in str(exported)


def test_repeated_evaluation_is_deterministic() -> None:
    manifest = _manifest()

    first = evaluate_phase4_authorization_boundary(manifest, timestamp=TIMESTAMP).to_dict()
    second = evaluate_phase4_authorization_boundary(manifest, timestamp=TIMESTAMP).to_dict()

    assert first == second


def test_missing_manifest_blocks() -> None:
    result = evaluate_phase4_authorization_boundary(None, timestamp=TIMESTAMP)

    assert result.decision == BLOCKED
    assert result.blocking_reasons == ("PR4_MANIFEST_MISSING",)


def test_invalid_json_loads_as_missing_and_blocks(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text("{not-json", encoding="utf-8")

    result = evaluate_phase4_authorization_boundary(load_phase4_manifest_safely(path), timestamp=TIMESTAMP)

    assert result.decision == BLOCKED
    assert result.blocking_reasons == ("PR4_MANIFEST_MISSING",)


def test_unknown_schema_version_is_invalid() -> None:
    manifest = _manifest()
    manifest["schema_version"] = "unknown"

    result = evaluate_phase4_authorization_boundary(manifest, timestamp=TIMESTAMP)

    assert result.decision == INVALID
    assert "PR4_SCHEMA_VERSION_UNSUPPORTED" in result.blocking_reasons


def test_unknown_field_is_invalid() -> None:
    manifest = _manifest()
    manifest["raw_payload"] = "forbidden"

    result = evaluate_phase4_authorization_boundary(manifest, timestamp=TIMESTAMP)

    assert result.decision == INVALID
    assert "PR4_UNKNOWN_FIELD:raw_payload" in result.blocking_reasons
    assert "PR4_SENSITIVE_FIELD_PRESENT" in result.blocking_reasons


def test_attempted_true_execution_flag_is_blocked() -> None:
    manifest = _manifest()
    manifest["execution_allowed"] = True

    result = evaluate_phase4_authorization_boundary(manifest, timestamp=TIMESTAMP)

    assert result.decision == BLOCKED
    assert "PR4_PROTECTED_FLAG_TRUE:execution_allowed" in result.blocking_reasons
    assert result.execution_allowed is False


def test_attempted_true_provider_execution_flag_is_blocked() -> None:
    manifest = _manifest()
    manifest["provider_execution"] = True

    _assert_blocked(manifest, "PR4_PROTECTED_FLAG_TRUE:provider_execution")


def test_attempted_true_production_activation_flag_is_blocked() -> None:
    manifest = _manifest()
    manifest["production_activation"] = True

    _assert_blocked(manifest, "PR4_PROTECTED_FLAG_TRUE:production_activation")


def test_attempted_true_deployment_authorized_flag_is_blocked() -> None:
    manifest = _manifest()
    manifest["deployment_authorized"] = True

    _assert_blocked(manifest, "PR4_PROTECTED_FLAG_TRUE:deployment_authorized")


def test_attempted_true_release_authorized_flag_is_blocked() -> None:
    manifest = _manifest()
    manifest["release_authorized"] = True

    _assert_blocked(manifest, "PR4_PROTECTED_FLAG_TRUE:release_authorized")


def test_unknown_signer_blocks() -> None:
    manifest = _manifest()
    manifest["signer_identity_reference"] = "signer:unknown"
    manifest["signature_reference"] = deterministic_phase4_signature_reference(manifest)

    _assert_blocked(manifest, "PR4_SIGNER_UNKNOWN")


def test_malformed_signer_blocks() -> None:
    manifest = _manifest()
    manifest["signer_identity_reference"] = "phase4-test-authority"
    manifest["signature_reference"] = deterministic_phase4_signature_reference(manifest)

    _assert_blocked(manifest, "PR4_SIGNER_IDENTITY_MALFORMED")


def test_missing_signer_blocks() -> None:
    manifest = _manifest()
    manifest["signer_identity_reference"] = ""

    _assert_blocked(manifest, "PR4_SIGNER_MISSING")


def test_unknown_trust_root_blocks() -> None:
    manifest = _manifest()
    manifest["trust_root_reference"] = "trust-root:unknown"
    manifest["signature_reference"] = deterministic_phase4_signature_reference(manifest)

    _assert_blocked(manifest, "PR4_TRUST_ROOT_UNKNOWN")


def test_malformed_trust_root_blocks() -> None:
    manifest = _manifest()
    manifest["trust_root_reference"] = "phase4-test-root"
    manifest["signature_reference"] = deterministic_phase4_signature_reference(manifest)

    _assert_blocked(manifest, "PR4_TRUST_ROOT_MALFORMED")


def test_unsupported_algorithm_blocks() -> None:
    manifest = _manifest()
    manifest["signature_algorithm"] = "RSA-PRODUCTION"

    _assert_blocked(manifest, "PR4_SIGNATURE_ALGORITHM_UNSUPPORTED")


def test_invalid_signature_blocks() -> None:
    manifest = _manifest()
    manifest["signature_reference"] = "sha256:" + "0" * 64

    _assert_blocked(manifest, "PR4_SIGNATURE_INVALID")


def test_unverified_signature_blocks() -> None:
    manifest = _manifest()
    manifest["signature_verified"] = False

    _assert_blocked(manifest, "PR4_SIGNATURE_UNVERIFIED")


def test_missing_timestamp_blocks() -> None:
    manifest = _manifest()
    manifest["timestamp_reference"] = ""

    _assert_blocked(manifest, "PR4_TIMESTAMP_MISSING")


def test_unverified_timestamp_blocks() -> None:
    manifest = _manifest()
    manifest["timestamp_verified"] = False

    _assert_blocked(manifest, "PR4_TIMESTAMP_UNVERIFIED")


def test_invalid_timestamp_blocks() -> None:
    manifest = _manifest()
    manifest["evidence_not_before"] = "invalid-time"

    _assert_blocked(manifest, "PR4_EVIDENCE_TIMESTAMP_INVALID")


def test_future_dated_evidence_blocks() -> None:
    manifest = _manifest()
    manifest["evidence_not_before"] = "2026-07-26T00:00:00Z"

    _assert_blocked(manifest, "PR4_EVIDENCE_FUTURE_DATED")


def test_expired_evidence_blocks() -> None:
    manifest = _manifest()
    manifest["evidence_expires_at"] = "2026-07-25T00:00:00Z"

    _assert_blocked(manifest, "PR4_EVIDENCE_EXPIRED")


def test_stale_evidence_blocks() -> None:
    manifest = _manifest()
    manifest["evidence_fresh"] = False

    _assert_blocked(manifest, "PR4_EVIDENCE_NOT_FRESH")


def test_missing_worm_capability_blocks() -> None:
    manifest = _manifest()
    del manifest["capabilities"]["worm"]

    _assert_blocked(manifest, "PR4_CAPABILITY_MISSING:worm")


def test_missing_rfc3161_capability_blocks() -> None:
    manifest = _manifest()
    del manifest["capabilities"]["rfc3161"]

    _assert_blocked(manifest, "PR4_CAPABILITY_MISSING:rfc3161")


def test_missing_external_signing_capability_blocks() -> None:
    manifest = _manifest()
    del manifest["capabilities"]["external_signing"]

    _assert_blocked(manifest, "PR4_CAPABILITY_MISSING:external_signing")


def test_configured_but_unverified_rfc3161_blocks() -> None:
    manifest = _manifest()
    manifest["capabilities"]["rfc3161"]["state"] = "CONFIGURED"

    _assert_blocked(manifest, "PR4_CAPABILITY_NOT_METADATA_READY:rfc3161:CONFIGURED")


def test_verified_without_evidence_blocks() -> None:
    manifest = _manifest()
    manifest["capabilities"]["external_signing"]["evidence_reference"] = ""

    _assert_blocked(manifest, "PR4_CAPABILITY_READY_WITHOUT_EVIDENCE:external_signing")


def test_insufficient_approvals_blocks() -> None:
    manifest = _manifest()
    manifest["approver_identity_references"] = ["identity:usbay-audit"]
    manifest["recorded_approval_count"] = 1

    _assert_blocked(manifest, "PR4_APPROVAL_QUORUM_INSUFFICIENT")


def test_unauthorized_approver_blocks() -> None:
    manifest = _manifest()
    manifest["approver_identity_references"] = ["identity:usbay-audit", "identity:unknown"]

    _assert_blocked(manifest, "PR4_APPROVER_UNAUTHORIZED:identity:unknown")


def test_malformed_approver_identity_blocks() -> None:
    manifest = _manifest()
    manifest["approver_identity_references"] = ["identity:usbay-audit", "usbay-global23"]

    _assert_blocked(manifest, "PR4_APPROVER_IDENTITY_MALFORMED:usbay-global23")


def test_duplicate_approver_blocks() -> None:
    manifest = _manifest()
    manifest["approver_identity_references"] = ["identity:usbay-audit", "identity:usbay-audit"]

    _assert_blocked(manifest, "PR4_APPROVER_DUPLICATE")


def test_self_approval_blocks() -> None:
    manifest = _manifest()
    manifest["approver_identity_references"] = ["identity:codex", "identity:usbay-audit"]

    _assert_blocked(manifest, "PR4_SELF_APPROVAL_PROHIBITED")


def test_revoked_approval_blocks() -> None:
    manifest = _manifest()
    manifest["revoked_approver_identity_references"] = ["identity:usbay-audit"]

    _assert_blocked(manifest, "PR4_APPROVER_REVOKED")


def test_expired_approval_blocks() -> None:
    manifest = _manifest()
    manifest["approval_expires_at"] = "2026-07-25T00:00:00Z"

    _assert_blocked(manifest, "PR4_APPROVAL_EXPIRED_OR_NOT_YET_VALID")


def test_policy_version_mismatch_blocks() -> None:
    manifest = _manifest()
    manifest["policy_version"] = "old"
    manifest["action_contract"]["policy_version"] = "old"

    _assert_blocked(manifest, "PR4_POLICY_VERSION_MISMATCH")


def test_policy_digest_malformed_blocks() -> None:
    manifest = _manifest()
    manifest["policy_digest"] = "not-a-hash"
    manifest["signature_reference"] = deterministic_phase4_signature_reference(manifest)

    _assert_blocked(manifest, "PR4_POLICY_DIGEST_INVALID")


def test_source_commit_malformed_blocks() -> None:
    manifest = _manifest()
    manifest["source_commit_sha"] = "not-a-commit"
    manifest["action_contract"]["source_commit"] = "not-a-commit"
    manifest["signature_reference"] = deterministic_phase4_signature_reference(manifest)

    _assert_blocked(manifest, "PR4_SOURCE_COMMIT_SHA_INVALID")


def test_evidence_digest_malformed_blocks() -> None:
    manifest = _manifest()
    manifest["evidence_manifest_digest"] = "not-a-hash"
    manifest["action_contract"]["evidence_digest"] = "not-a-hash"
    manifest["signature_reference"] = deterministic_phase4_signature_reference(manifest)

    _assert_blocked(manifest, "PR4_EVIDENCE_MANIFEST_DIGEST_INVALID")


def test_commit_mismatch_blocks() -> None:
    manifest = _manifest()
    manifest["action_contract"]["source_commit"] = "b" * 40

    _assert_blocked(manifest, "PR4_ACTION_CONTRACT_MISMATCH:source_commit")


def test_replay_blocks() -> None:
    manifest = _manifest()
    manifest["used_anti_replay_references"] = [manifest["anti_replay_reference"]]

    _assert_blocked(manifest, "PR4_REPLAY_DETECTED")


def test_rollback_failure_blocks() -> None:
    manifest = _manifest()
    manifest["rollback_check_passed"] = False

    _assert_blocked(manifest, "PR4_ROLLBACK_CHECK_FAILED")


def test_policy_rollback_blocks() -> None:
    manifest = _manifest()
    manifest["minimum_policy_version"] = "usbay.production-readiness.phase3.v1"

    _assert_blocked(manifest, "PR4_POLICY_ROLLBACK_DETECTED")


def test_wrong_action_type_blocks() -> None:
    manifest = _manifest()
    manifest["requested_action_type"] = "deploy"
    manifest["action_contract"]["action_type"] = "deploy"
    manifest["signature_reference"] = deterministic_phase4_signature_reference(manifest)

    _assert_blocked(manifest, "PR4_ACTION_TYPE_UNSUPPORTED")


def test_wrong_target_blocks() -> None:
    manifest = _manifest()
    manifest["action_contract"]["target"] = "other"

    _assert_blocked(manifest, "PR4_ACTION_CONTRACT_MISMATCH:target")


def test_wrong_environment_blocks() -> None:
    manifest = _manifest()
    manifest["action_contract"]["environment"] = "other"

    _assert_blocked(manifest, "PR4_ACTION_CONTRACT_MISMATCH:environment")


def test_wrong_parameters_digest_blocks() -> None:
    manifest = _manifest()
    manifest["action_contract"]["parameters_digest"] = "sha256:" + "9" * 64

    _assert_blocked(manifest, "PR4_ACTION_CONTRACT_MISMATCH:parameters_digest")
