from __future__ import annotations

import json

from runtime.computer_use.integrated_governance_chain_validator import (
    BLOCKED,
    READY,
    READY_WITH_RESTRICTIONS,
    canonical_integrated_chain_json,
    evaluate_integrated_governance_chain,
    expected_integrated_evidence_hash,
)


HASH = "sha256:" + ("a" * 64)
HASH_B = "sha256:" + ("b" * 64)
HASH_C = "sha256:" + ("c" * 64)
REVISION = "bf85c971986227085da9edeaa89b2c29e3d02de0"
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
        "manifest_id": "pb-1g",
        "generated_at": OBSERVED,
        "repository_revision": REVISION,
        "source_branch": "usbay/p1-g-integrated-governance-chain-validation",
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
        "required_test_results": [{"id": "pb-1g-focused", "required": True, "status": "PASS"}],
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
        "required_tests": [{"id": "pb-1g-focused", "required": True, "status": "PASS"}],
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


def _policy(**overrides):
    policy = {"policy_version": "policy-v1", "policy_hash": HASH, "final_decision": "ALLOW"}
    policy.update(overrides)
    return policy


def _approval(**overrides):
    approval = {"status": "VALID", "expired": False, "approval_reference": HASH}
    approval.update(overrides)
    return approval


def _payload(**overrides):
    payload = {
        "policy": _policy(),
        "approval": _approval(),
        "dependencies": [_dependency()],
        "observed_at": OBSERVED,
        "degraded_operation_permitted": False,
        "adapter_contract": _adapter_contract(),
        "adapter_prechecks": _adapter_prechecks(),
        "evidence_manifest": _evidence_manifest(),
        "precommit_metadata": _precommit_metadata(),
    }
    payload.update(overrides)
    if overrides.get("expected_evidence_hash", "__unset__") == "__unset__":
        payload["expected_evidence_hash"] = expected_integrated_evidence_hash(payload)
    return payload


def _blocked(payload, reason: str):
    result = evaluate_integrated_governance_chain(payload)

    assert result.final_decision == BLOCKED
    assert reason in result.reason_codes
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
    assert result.evidence_hash.startswith("sha256:")
    return result


def test_valid_chain_ready() -> None:
    result = evaluate_integrated_governance_chain(_payload())

    assert result.final_decision == READY
    assert result.reason_codes == ()
    assert result.human_approval_required is True


def test_ready_with_restrictions_from_upstream_metadata() -> None:
    restriction = _restriction()
    payload = _payload(
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

    assert evaluate_integrated_governance_chain(payload).final_decision == READY_WITH_RESTRICTIONS


def test_missing_policy_blocks() -> None:
    _blocked(_payload(policy=None), "POLICY_MISSING")


def test_denied_policy_blocks() -> None:
    _blocked(_payload(policy=_policy(final_decision="DENY")), "POLICY_DENIED")


def test_missing_approval_blocks() -> None:
    _blocked(_payload(approval=None), "APPROVAL_MISSING")


def test_expired_approval_blocks() -> None:
    _blocked(_payload(approval=_approval(expired=True)), "APPROVAL_EXPIRED")


def test_missing_dependency_blocks() -> None:
    _blocked(_payload(dependencies=None), "DEPENDENCY_NOT_READY")


def test_stale_dependency_blocks() -> None:
    _blocked(_payload(dependencies=[_dependency(last_verified_at="2026-07-27T10:00:00Z")]), "DEPENDENCY_STALE")


def test_required_degraded_dependency_blocks() -> None:
    _blocked(_payload(dependencies=[_dependency(readiness_status="DEGRADED")], degraded_operation_permitted=True), "REQUIRED_DEPENDENCY_DEGRADED")


def test_unknown_dependency_state_blocks() -> None:
    _blocked(_payload(dependencies=[_dependency(readiness_status="READYISH")]), "UNKNOWN_DEPENDENCY_STATUS")


def test_missing_adapter_contract_blocks() -> None:
    _blocked(_payload(adapter_contract=None), "ADAPTER_CONTRACT_INVALID")


def test_adapter_version_mismatch_blocks() -> None:
    _blocked(_payload(adapter_contract=_adapter_contract(observed_version="v2")), "ADAPTER_INCOMPATIBLE")


def test_unsupported_adapter_blocks() -> None:
    _blocked(_payload(adapter_contract=_adapter_contract(adapter_id="provider_live_adapter")), "UNSUPPORTED_ADAPTER")


def test_disabled_adapter_blocks() -> None:
    _blocked(_payload(adapter_contract=_adapter_contract(execution_status="DISABLED")), "ADAPTER_NOT_READY")


def test_timeout_adapter_blocks() -> None:
    _blocked(_payload(adapter_contract=_adapter_contract(adapter_id="timeout_adapter")), "ADAPTER_TIMEOUT")


def test_malformed_adapter_response_blocks() -> None:
    _blocked(_payload(adapter_contract=_adapter_contract(adapter_id="malformed_adapter")), "MALFORMED_ADAPTER_RESPONSE")


def test_adapter_parameter_failure_blocks() -> None:
    _blocked(_payload(adapter_prechecks=_adapter_prechecks(parameters_valid=False)), "PARAMETERS_INVALID")


def test_replay_failure_blocks() -> None:
    _blocked(_payload(adapter_prechecks=_adapter_prechecks(replay_protection_passed=False)), "REPLAY_DETECTED")


def test_nonce_failure_blocks() -> None:
    _blocked(_payload(adapter_prechecks=_adapter_prechecks(nonce_valid=False)), "NONCE_INVALID")


def test_timestamp_failure_blocks() -> None:
    _blocked(_payload(adapter_prechecks=_adapter_prechecks(timestamp_window_valid=False)), "TIMESTAMP_INVALID")


def test_audit_unavailable_blocks() -> None:
    _blocked(_payload(adapter_prechecks=_adapter_prechecks(evidence_destination_ready=False)), "AUDIT_DESTINATION_UNAVAILABLE")


def test_missing_evidence_manifest_blocks() -> None:
    _blocked(_payload(evidence_manifest=None), "EVIDENCE_EXPORT_FAILED")


def test_malformed_evidence_manifest_blocks() -> None:
    malformed = _evidence_manifest()
    malformed.pop("manifest_id")
    _blocked(_payload(evidence_manifest=malformed), "MISSING_MANIFEST_ID")


def test_evidence_hash_mismatch_blocks() -> None:
    _blocked(_payload(expected_evidence_hash="sha256:" + ("f" * 64)), "EVIDENCE_HASH_MISMATCH")


def test_missing_expected_evidence_hash_blocks() -> None:
    _blocked(_payload(expected_evidence_hash=""), "EVIDENCE_HASH_MISSING")


def test_evidence_export_failure_blocks() -> None:
    _blocked(_payload(evidence_manifest=_evidence_manifest(evidence_chain_integrity="BROKEN")), "EVIDENCE_CHAIN_BROKEN")


def test_precommit_validation_failure_blocks() -> None:
    _blocked(_payload(precommit_metadata=_precommit_metadata(policy_schema_valid=False)), "MISSING_POLICY")


def test_missing_required_check_blocks() -> None:
    _blocked(_payload(precommit_metadata=_precommit_metadata(required_ci_checks=[])), "REQUIRED_CHECK_MISSING")


def test_unknown_required_check_blocks() -> None:
    _blocked(
        _payload(precommit_metadata=_precommit_metadata(required_ci_checks=[{"id": "governance", "required": True, "status": "UNKNOWN"}])),
        "REQUIRED_CHECK_UNKNOWN",
    )


def test_direct_execution_bypass_blocks() -> None:
    _blocked(_payload(direct_execution_requested=True), "DIRECT_EXECUTION_BYPASS")


def test_command_bypass_blocks() -> None:
    _blocked(_payload(command="synthetic-command"), "DIRECT_EXECUTION_BYPASS")


def test_sensitive_input_blocks_without_leakage() -> None:
    result = _blocked(_payload(raw_payload="synthetic-sensitive"), "SENSITIVE_DATA_REJECTED")

    assert "synthetic-sensitive" not in json.dumps(result.to_dict(), sort_keys=True)


def test_malformed_input_blocks() -> None:
    _blocked(None, "MALFORMED_INTEGRATED_METADATA")


def test_unknown_integrated_decision_blocks() -> None:
    _blocked(_payload(expected_final_decision="CERTIFIED"), "UNKNOWN_INTEGRATED_DECISION")


def test_stage_exception_fails_closed(monkeypatch) -> None:
    import runtime.computer_use.integrated_governance_chain_validator as module

    def explode(*_args, **_kwargs):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(module, "evaluate_dependency_readiness", explode)

    _blocked(_payload(), "INTERNAL_ERROR")


def test_output_is_deterministic() -> None:
    payload = _payload()

    assert evaluate_integrated_governance_chain(payload).to_dict() == evaluate_integrated_governance_chain(payload).to_dict()


def test_canonical_serialization_is_deterministic() -> None:
    decision = evaluate_integrated_governance_chain(_payload())

    assert canonical_integrated_chain_json(decision) == canonical_integrated_chain_json(decision)


def test_evidence_tamper_detection_changes_hash() -> None:
    payload = _payload()
    tampered = dict(payload)
    tampered["approval"] = _approval(approval_reference=HASH_B)

    assert expected_integrated_evidence_hash(payload) != expected_integrated_evidence_hash(tampered)


def test_no_production_side_effect_flags() -> None:
    result = evaluate_integrated_governance_chain(_payload())

    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
