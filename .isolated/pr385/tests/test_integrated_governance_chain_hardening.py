from __future__ import annotations

import json

from runtime.computer_use.integrated_governance_chain_hardening import (
    BLOCKED,
    READY,
    READY_WITH_RESTRICTIONS,
    REQUIRED_STAGE_ORDER,
    canonical_hardening_json,
    evaluate_integrated_governance_chain_hardening,
    expected_hardening_evidence_hash,
)
from runtime.computer_use.integrated_governance_chain_validator import expected_integrated_evidence_hash


HASH = "sha256:" + ("a" * 64)
HASH_B = "sha256:" + ("b" * 64)
HASH_C = "sha256:" + ("c" * 64)
REVISION = "715fe543f6ea118bc2659e2af1cdf741f6b75503"
OBSERVED = "2026-07-27T12:00:00Z"
VERIFIED = "2026-07-27T11:59:00Z"


def _dependency(**overrides):
    dependency = {
        "dependency_id": "policy-source",
        "dependency_type": "policy_source",
        "required": True,
        "readiness_status": "READY",
        "health_status": "READY",
        "compatibility_status": "READY",
        "integrity_status": "READY",
        "last_verified_at": VERIFIED,
        "freshness_window_seconds": 300,
        "expected_version": "v1",
        "observed_version": "v1",
        "evidence_hash": HASH,
        "failure_reason": "",
        "final_decision": "ALLOW",
    }
    dependency.update(overrides)
    return dependency


def _adapter_contract(**overrides):
    contract = {
        "adapter_id": "local_mock_adapter",
        "adapter_type": "local_mock",
        "provider_class": "mock",
        "capability_id": "runtime.execute",
        "execution_contract": HASH_B,
        "policy_version": "policy-v1",
        "approval_reference": HASH,
        "runtime_reference": HASH,
        "dependency_reference": HASH,
        "audit_reference": HASH,
        "timeout_seconds": 30,
        "dry_run": True,
        "provider_version": "v1",
        "expected_version": "v1",
        "observed_version": "v1",
        "execution_status": "READY",
        "decision": "ALLOW",
        "target": "local-control-plane",
        "evidence_reference": HASH,
    }
    contract.update(overrides)
    return contract


def _adapter_prechecks(**overrides):
    checks = {
        "policy_evaluated": True,
        "approval_valid": True,
        "execution_contract_valid": True,
        "capability_authorized": True,
        "target_policy_valid": True,
        "dependency_ready": True,
        "runtime_ready": True,
        "replay_protection_passed": True,
        "nonce_valid": True,
        "timestamp_window_valid": True,
        "parameters_valid": True,
        "evidence_destination_ready": True,
    }
    checks.update(overrides)
    return checks


def _restriction(**overrides):
    restriction = {
        "restriction_id": "human-review-window",
        "reason": "pilot only",
        "owner": "human-governance-review",
        "approval_reference": HASH,
        "expires_at": "2026-08-27T12:00:00Z",
        "evidence_hash": HASH,
        "policy_authorized": True,
    }
    restriction.update(overrides)
    return restriction


def _evidence_manifest(**overrides):
    manifest = {
        "schema": "usbay.production_readiness.evidence_export.v1",
        "manifest_id": "pb-1h",
        "generated_at": OBSERVED,
        "repository_revision": REVISION,
        "source_branch": "usbay/p1-h-integrated-governance-chain-hardening",
        "policy_version": "policy-v1",
        "policy_hash": HASH,
        "execution_contract_version": "pb-1b",
        "execution_contract_hash": HASH,
        "approval_contract_version": "pb-1b",
        "approval_reference": HASH,
        "runtime_gate_version": "pb-1b",
        "runtime_readiness_reference": HASH,
        "dependency_readiness_version": "pb-1c",
        "dependency_readiness_reference": HASH,
        "adapter_contract_version": "pb-1d",
        "adapter_readiness_reference": HASH,
        "evidence_chain_reference": HASH,
        "evidence_chain_integrity": "VERIFIED",
        "timestamp_reference": HASH,
        "timestamp_verification": "VALID_FRESH",
        "test_summary": {"passed": 1, "failed": 0},
        "required_test_results": [{"id": "pb-1h-focused", "required": True, "status": "PASS"}],
        "ci_check_summary": {"passed": 1, "failed": 0},
        "required_ci_results": [{"id": "governance-check", "required": True, "status": "PASS"}],
        "rollback_reference": HASH,
        "rollback_verified": True,
        "known_gaps": [],
        "critical_gap_count": 0,
        "restrictions": [],
        "evidence_hash": HASH,
        "package_hash": "",
        "final_readiness_decision": READY,
        "blocked_reasons": [],
    }
    manifest.update(overrides)
    return manifest


def _precommit_metadata(**overrides):
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
        "required_tests": [{"id": "pb-1h-focused", "required": True, "status": "PASS"}],
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
        "manifest_hash": HASH_C,
        "computed_manifest_hash": HASH_C,
    }
    metadata.update(overrides)
    return metadata


def _integrated_metadata(**overrides):
    metadata = {
        "policy": {"policy_version": "policy-v1", "policy_hash": HASH, "final_decision": "ALLOW"},
        "approval": {"status": "VALID", "expired": False, "approval_reference": HASH},
        "dependencies": [_dependency()],
        "observed_at": OBSERVED,
        "degraded_operation_permitted": False,
        "adapter_contract": _adapter_contract(),
        "adapter_prechecks": _adapter_prechecks(),
        "evidence_manifest": _evidence_manifest(),
        "precommit_metadata": _precommit_metadata(),
    }
    metadata.update(overrides)
    if overrides.get("expected_evidence_hash", "__unset__") == "__unset__":
        metadata["expected_evidence_hash"] = expected_integrated_evidence_hash(metadata)
    return metadata


def _stage_metadata(**overrides):
    stages = {
        stage: {
            "status": READY,
            "evidence_hash": HASH,
            "audit_hash": HASH_B,
            "capability_supported": True,
        }
        for stage in REQUIRED_STAGE_ORDER
    }
    stages.update(overrides)
    return stages


def _controls(**overrides):
    controls = {
        "policy_complete": True,
        "audit_complete": True,
        "evidence_available": True,
        "execution_contract_complete": True,
        "replay_protection_present": True,
        "timestamp_window_present": True,
        "nonce_validation_present": True,
        "approval_chain_present": True,
        "fail_closed_propagation": True,
        "metadata_consistent": True,
    }
    controls.update(overrides)
    return controls


def _payload(**overrides):
    payload = {
        "chain_order": list(REQUIRED_STAGE_ORDER),
        "stage_metadata": _stage_metadata(),
        "controls": _controls(),
        "integrated_chain_metadata": _integrated_metadata(),
    }
    payload["chain_evidence_hash"] = expected_chain_hash(payload)
    payload.update(overrides)
    if overrides.get("expected_hardening_evidence_hash", "__unset__") == "__unset__":
        payload["expected_hardening_evidence_hash"] = expected_hardening_evidence_hash(payload)
    return payload


def expected_chain_hash(payload):
    from governance.hashing import sha256_reference

    redacted = {
        stage: {
            "status": record.get("status"),
            "evidence_hash": record.get("evidence_hash"),
            "audit_hash": record.get("audit_hash"),
            "capability_supported": record.get("capability_supported"),
        }
        for stage, record in sorted(payload.get("stage_metadata", {}).items())
    }
    return sha256_reference({"chain_order": list(payload.get("chain_order", ())), "stage_metadata": redacted})


def _blocked(payload, reason):
    result = evaluate_integrated_governance_chain_hardening(payload)

    assert result.final_decision == BLOCKED
    assert reason in result.reason_codes
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
    assert result.evidence_hash.startswith("sha256:")
    return result


def test_complete_governance_chain_ready() -> None:
    result = evaluate_integrated_governance_chain_hardening(_payload())

    assert result.final_decision == READY
    assert result.reason_codes == ()


def test_ready_with_restrictions_from_integrated_chain() -> None:
    restriction = _restriction()
    integrated = _integrated_metadata(
        dependencies=[_dependency(required=False, readiness_status="DEGRADED")],
        degraded_operation_permitted=True,
        evidence_manifest=_evidence_manifest(
            final_readiness_decision=READY_WITH_RESTRICTIONS,
            known_gaps=[{"gap_id": "gap-low", "severity": "LOW"}],
            restrictions=[restriction],
        ),
        precommit_metadata=_precommit_metadata(
            expected_result=READY_WITH_RESTRICTIONS,
            governance_status="RESTRICTED",
            restrictions=[{"restriction_id": restriction["restriction_id"], "policy_authorized": True}],
        ),
    )

    assert evaluate_integrated_governance_chain_hardening(_payload(integrated_chain_metadata=integrated)).final_decision == READY_WITH_RESTRICTIONS


def test_deterministic_ordering() -> None:
    payload = _payload()

    assert evaluate_integrated_governance_chain_hardening(payload).to_dict() == evaluate_integrated_governance_chain_hardening(payload).to_dict()


def test_complete_audit_chain() -> None:
    result = evaluate_integrated_governance_chain_hardening(_payload())

    assert result.chain_hash.startswith("sha256:")


def test_complete_evidence_chain() -> None:
    result = evaluate_integrated_governance_chain_hardening(_payload())

    assert result.evidence_hash == expected_hardening_evidence_hash(_payload())


def test_missing_evidence_blocks() -> None:
    stages = _stage_metadata()
    stages["PB-1E_PRODUCTION_READINESS_EVIDENCE_EXPORT"]["evidence_hash"] = ""
    _blocked(_payload(stage_metadata=stages, chain_evidence_hash="sha256:" + ("f" * 64)), "MISSING_EVIDENCE")


def test_missing_dependency_blocks() -> None:
    stages = _stage_metadata()
    stages.pop("PB-1C_DEPENDENCY_READINESS")
    _blocked(_payload(stage_metadata=stages, chain_evidence_hash="sha256:" + ("f" * 64)), "MISSING_DEPENDENCY")


def test_missing_approval_blocks() -> None:
    _blocked(_payload(controls=_controls(approval_chain_present=False)), "APPROVAL_CHAIN_MISSING")


def test_missing_policy_blocks() -> None:
    _blocked(_payload(controls=_controls(policy_complete=False)), "POLICY_INCOMPLETE")


def test_stale_dependency_blocks() -> None:
    integrated = _integrated_metadata(dependencies=[_dependency(last_verified_at="2026-07-27T10:00:00Z")])
    _blocked(_payload(integrated_chain_metadata=integrated), "PB_1G_BLOCKED")


def test_malformed_metadata_blocks() -> None:
    _blocked(None, "MALFORMED_HARDENING_METADATA")


def test_invalid_ordering_blocks() -> None:
    invalid_order = list(REQUIRED_STAGE_ORDER)
    invalid_order.reverse()
    _blocked(_payload(chain_order=invalid_order, chain_evidence_hash="sha256:" + ("f" * 64)), "INVALID_DEPENDENCY_ORDER")


def test_replay_protection_missing_blocks() -> None:
    _blocked(_payload(controls=_controls(replay_protection_present=False)), "REPLAY_PROTECTION_MISSING")


def test_timestamp_missing_blocks() -> None:
    _blocked(_payload(controls=_controls(timestamp_window_present=False)), "TIMESTAMP_WINDOW_MISSING")


def test_nonce_missing_blocks() -> None:
    _blocked(_payload(controls=_controls(nonce_validation_present=False)), "NONCE_VALIDATION_MISSING")


def test_corrupted_evidence_blocks() -> None:
    _blocked(_payload(chain_evidence_hash="sha256:" + ("f" * 64)), "CORRUPTED_EVIDENCE")


def test_unsupported_capability_blocks() -> None:
    stages = _stage_metadata(
        PB_1X_UNKNOWN={
            "status": READY,
            "evidence_hash": HASH,
            "audit_hash": HASH,
            "capability_supported": False,
        }
    )
    stages["PB-1D_EXECUTION_ADAPTER_CONTRACT"]["capability_supported"] = False
    _blocked(_payload(stage_metadata=stages, chain_evidence_hash="sha256:" + ("f" * 64)), "UNSUPPORTED_CAPABILITY")


def test_audit_incomplete_blocks() -> None:
    stages = _stage_metadata()
    stages["PB-1G_INTEGRATED_GOVERNANCE_CHAIN_VALIDATION"]["audit_hash"] = ""
    _blocked(_payload(stage_metadata=stages, chain_evidence_hash="sha256:" + ("f" * 64)), "AUDIT_INCOMPLETE")


def test_execution_contract_incomplete_blocks() -> None:
    _blocked(_payload(controls=_controls(execution_contract_complete=False)), "EXECUTION_CONTRACT_INCOMPLETE")


def test_fail_closed_propagation_missing_blocks() -> None:
    _blocked(_payload(controls=_controls(fail_closed_propagation=False)), "FAIL_CLOSED_PROPAGATION_MISSING")


def test_metadata_inconsistent_blocks() -> None:
    _blocked(_payload(controls=_controls(metadata_consistent=False)), "METADATA_INCONSISTENT")


def test_missing_hardening_hash_blocks() -> None:
    _blocked(_payload(expected_hardening_evidence_hash=""), "HARDENING_EVIDENCE_HASH_MISSING")


def test_hardening_hash_mismatch_blocks() -> None:
    _blocked(_payload(expected_hardening_evidence_hash="sha256:" + ("f" * 64)), "HARDENING_EVIDENCE_HASH_MISMATCH")


def test_sensitive_input_blocks_without_leakage() -> None:
    result = _blocked(_payload(raw_payload="synthetic-sensitive"), "SENSITIVE_DATA_REJECTED")

    assert "synthetic-sensitive" not in json.dumps(result.to_dict(), sort_keys=True)


def test_direct_execution_bypass_blocks() -> None:
    _blocked(_payload(direct_execution_requested=True), "DIRECT_EXECUTION_BYPASS")


def test_canonical_json_is_stable() -> None:
    result = evaluate_integrated_governance_chain_hardening(_payload())

    assert canonical_hardening_json(result) == canonical_hardening_json(result)


def test_only_allowed_decisions_are_emitted() -> None:
    result = evaluate_integrated_governance_chain_hardening(_payload())

    assert result.final_decision in {READY, READY_WITH_RESTRICTIONS, BLOCKED}


def test_no_production_side_effect_flags() -> None:
    result = evaluate_integrated_governance_chain_hardening(_payload())

    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
