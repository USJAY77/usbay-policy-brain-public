from __future__ import annotations

import json

from runtime.computer_use.pb_1j_governance_chain_release_readiness_contract import BLOCKED, READY, READY_WITH_RESTRICTIONS
from runtime.computer_use.pb_1l_governance_release_candidate_evidence_lock import (
    CAPABILITY_NAME,
    REQUIRED_VALIDATION_CHECKS,
    canonical_pb_1l_json,
    evaluate_pb_1l_release_candidate_evidence_lock,
    expected_pb_1l_evidence_hash,
    expected_pb_1l_package_hash,
    expected_pb_1l_release_candidate_lock_hash,
)


HASH = "sha256:" + ("a" * 64)
HASH_B = "sha256:" + ("b" * 64)
HASH_C = "sha256:" + ("c" * 64)
HASH_D = "sha256:" + ("d" * 64)


def _pb_1k(**overrides):
    record = {
        "final_decision": READY,
        "approval_closure_hash": HASH,
        "evidence_hash": HASH_B,
        "package_hash": HASH_C,
        "decision_hash": HASH_D,
        "audit_hash": HASH,
        "policy_version": "policy-v1",
        "metadata_stale": False,
    }
    record.update(overrides)
    return record


def _release_candidate(**overrides):
    record = {
        "release_candidate_reference": HASH,
        "release_candidate_evidence_hash": HASH_B,
        "expected_release_candidate_evidence_hash": HASH_B,
        "pb_1k_decision_hash": HASH_D,
        "pb_1k_package_hash": HASH_C,
        "policy_reference": HASH,
        "tenant_reference": HASH_B,
        "correlation_reference": HASH_C,
        "chronology_reference": HASH,
        "duplicate": False,
        "metadata_stale": False,
    }
    record.update(overrides)
    return record


def _policy(**overrides):
    record = {"policy_reference": HASH, "policy_version": "policy-v1", "metadata_stale": False}
    record.update(overrides)
    return record


def _tenant(**overrides):
    record = {"tenant_reference": HASH_B, "expected_tenant_reference": HASH_B, "metadata_stale": False}
    record.update(overrides)
    return record


def _correlation(**overrides):
    record = {"correlation_reference": HASH_C}
    record.update(overrides)
    return record


def _approval(**overrides):
    record = {
        "status": "VALID",
        "approval_reference": HASH_D,
        "approval_evidence_hash": HASH_B,
        "capability": CAPABILITY_NAME,
        "pb_1k_decision_hash": HASH_D,
        "pb_1k_package_hash": HASH_C,
        "release_candidate_reference": HASH,
        "release_candidate_evidence_hash": HASH_B,
        "rollback_evidence_reference": HASH_C,
        "policy_reference": HASH,
        "tenant_reference": HASH_B,
        "correlation_reference": HASH_C,
        "replay_metadata_reference": HASH,
        "chronology_reference": HASH,
        "duplicate": False,
        "expired": False,
        "metadata_stale": False,
    }
    record.update(overrides)
    return record


def _approval_evidence(**overrides):
    record = {
        "approval_evidence_hash": HASH_B,
        "expected_approval_evidence_hash": HASH_B,
        "human_approval_reference": HASH_D,
        "metadata_stale": False,
    }
    record.update(overrides)
    return record


def _audit(**overrides):
    record = {
        "pb_1k_audit_hash": HASH,
        "pb_1l_validation_audit_hash": HASH_B,
        "previous_audit_hash": HASH_C,
        "current_audit_hash": HASH_D,
        "expected_current_audit_hash": HASH_D,
        "approval_audit_reference": HASH_D,
        "release_candidate_audit_reference": HASH,
        "correlation_reference": HASH_C,
        "policy_reference": HASH,
        "tenant_reference": HASH_B,
        "chronology_marker": 1,
        "duplicate": False,
        "metadata_stale": False,
    }
    record.update(overrides)
    return record


def _evidence(**overrides):
    record = {
        "pb_1k_approval_closure_reference": HASH,
        "pb_1k_evidence_reference": HASH_B,
        "pb_1k_audit_reference": HASH,
        "release_candidate_evidence_reference": HASH_B,
        "approval_evidence_reference": HASH_B,
        "human_approval_reference": HASH_D,
        "audit_chain_evidence_reference": HASH,
        "evidence_chain_reference": HASH_B,
        "rollback_evidence_reference": HASH_C,
        "rollback_plan_evidence_reference": HASH,
        "replay_metadata_evidence_reference": HASH_C,
        "validation_evidence_reference": HASH,
        "boundary_verification_evidence_reference": HASH,
        "sensitive_data_scan_evidence_reference": HASH,
        "execution_surface_scan_evidence_reference": HASH,
        "current_evidence_hash": HASH_D,
        "expected_current_evidence_hash": HASH_D,
        "chronology_marker": 2,
        "metadata_stale": False,
    }
    record.update(overrides)
    return record


def _rollback(**overrides):
    record = {
        "status": "VERIFIED",
        "rollback_plan_reference": HASH,
        "rollback_evidence_reference": HASH_C,
        "previous_release_candidate_package_hash": HASH_B,
        "current_release_candidate_package_hash": "",
        "rollback_owner_reference": HASH_D,
        "rollback_chronology_reference": HASH,
        "duplicate": False,
        "metadata_stale": False,
    }
    record.update(overrides)
    return record


def _replay(**overrides):
    record = {
        "nonce_reference": HASH,
        "timestamp_reference": HASH_B,
        "previous_package_hash": HASH_C,
        "current_package_hash": "",
        "replay_window_seconds": 300,
        "duplicate_approval_detected": False,
        "duplicate_release_candidate_detected": False,
        "duplicate_package_detected": False,
        "chronology_marker": 3,
        "expired": False,
        "metadata_stale": False,
    }
    record.update(overrides)
    return record


def _validation(**overrides):
    checks = {check: {"status": "PASS", "evidence_reference": HASH} for check in REQUIRED_VALIDATION_CHECKS}
    checks.update(overrides)
    return checks


def _safety(**overrides):
    flags = {
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "deployment_authorized": False,
        "runtime_mutation": False,
        "policy_mutation": False,
    }
    flags.update(overrides)
    return flags


def _payload(**overrides):
    payload = {
        "pb_1k": _pb_1k(),
        "release_candidate": _release_candidate(),
        "approval_chain": _approval(),
        "approval_evidence": _approval_evidence(),
        "audit_chain": _audit(),
        "evidence_chain": _evidence(),
        "rollback_references": _rollback(),
        "replay_protection": _replay(),
        "validation_metadata": _validation(),
        "policy_reference": _policy(),
        "tenant_reference": _tenant(),
        "correlation_reference": _correlation(),
        "safety_flags": _safety(),
        "restriction_metadata": [],
    }
    payload["expected_release_candidate_lock_hash"] = expected_pb_1l_release_candidate_lock_hash(payload)
    payload["expected_evidence_hash"] = expected_pb_1l_evidence_hash(payload)
    payload["expected_package_hash"] = expected_pb_1l_package_hash(payload)
    payload["rollback_references"]["current_release_candidate_package_hash"] = payload["expected_package_hash"]
    payload["replay_protection"]["current_package_hash"] = payload["expected_package_hash"]
    payload.update(overrides)
    return payload


def _blocked(payload, reason):
    result = evaluate_pb_1l_release_candidate_evidence_lock(payload)

    assert result.final_decision == BLOCKED
    assert reason in result.reason_codes
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
    assert result.runtime_mutation is False
    assert result.policy_mutation is False
    assert result.evidence_hash.startswith("sha256:")
    return result


def test_valid_release_candidate_evidence_lock_ready() -> None:
    result = evaluate_pb_1l_release_candidate_evidence_lock(_payload())

    assert result.final_decision == READY
    assert result.reason_codes == ()


def test_valid_lock_with_governed_restrictions() -> None:
    payload = _payload(
        pb_1k=_pb_1k(final_decision=READY_WITH_RESTRICTIONS),
        restriction_metadata=[{"restriction_reference": HASH}],
    )
    payload["expected_release_candidate_lock_hash"] = expected_pb_1l_release_candidate_lock_hash(payload)
    payload["expected_evidence_hash"] = expected_pb_1l_evidence_hash(payload)
    payload["expected_package_hash"] = expected_pb_1l_package_hash(payload)
    payload["rollback_references"]["current_release_candidate_package_hash"] = payload["expected_package_hash"]
    payload["replay_protection"]["current_package_hash"] = payload["expected_package_hash"]

    assert evaluate_pb_1l_release_candidate_evidence_lock(payload).final_decision == READY_WITH_RESTRICTIONS


def test_missing_pb_1k_metadata_blocks() -> None:
    _blocked(_payload(pb_1k=None), "PB_1K_METADATA_MISSING")


def test_invalid_pb_1k_decision_blocks() -> None:
    _blocked(_payload(pb_1k=_pb_1k(final_decision="ALLOW")), "INVALID_PB_1K_DECISION")


def test_missing_pb_1k_hashes_block() -> None:
    _blocked(_payload(pb_1k=_pb_1k(approval_closure_hash="")), "PB_1K_APPROVAL_CLOSURE_HASH_MISSING")


def test_missing_release_candidate_reference_blocks() -> None:
    _blocked(_payload(release_candidate=None), "RELEASE_CANDIDATE_REFERENCE_MISSING")


def test_missing_release_candidate_evidence_blocks() -> None:
    _blocked(_payload(release_candidate=_release_candidate(expected_release_candidate_evidence_hash=HASH)), "RELEASE_CANDIDATE_EVIDENCE_MISSING")


def test_missing_approval_reference_blocks() -> None:
    _blocked(_payload(approval_chain=None), "APPROVAL_REFERENCE_MISSING")


def test_invalid_approval_reference_blocks() -> None:
    _blocked(_payload(approval_chain=_approval(status="EXPIRED")), "APPROVAL_INVALID")


def test_missing_approval_evidence_blocks() -> None:
    _blocked(_payload(approval_evidence=None), "APPROVAL_EVIDENCE_MISSING")


def test_missing_audit_chain_blocks() -> None:
    _blocked(_payload(audit_chain=None), "AUDIT_CHAIN_MISSING")


def test_audit_hash_mismatch_blocks() -> None:
    _blocked(_payload(audit_chain=_audit(expected_current_audit_hash=HASH)), "AUDIT_HASH_MISMATCH")


def test_missing_evidence_chain_blocks() -> None:
    _blocked(_payload(evidence_chain=None), "EVIDENCE_CHAIN_MISSING")


def test_evidence_hash_mismatch_blocks() -> None:
    _blocked(_payload(evidence_chain=_evidence(expected_current_evidence_hash=HASH)), "EVIDENCE_HASH_MISMATCH")


def test_missing_rollback_reference_blocks() -> None:
    _blocked(_payload(rollback_references=None), "ROLLBACK_REFERENCE_MISSING")


def test_missing_rollback_evidence_blocks() -> None:
    _blocked(_payload(rollback_references=_rollback(status="MISSING")), "ROLLBACK_EVIDENCE_MISSING")


def test_missing_replay_metadata_blocks() -> None:
    _blocked(_payload(replay_protection=None), "REPLAY_METADATA_MISSING")


def test_duplicate_approval_metadata_blocks() -> None:
    _blocked(_payload(approval_chain=_approval(duplicate=True)), "DUPLICATE_RELEASE_CANDIDATE_METADATA")


def test_duplicate_release_candidate_metadata_blocks() -> None:
    _blocked(_payload(release_candidate=_release_candidate(duplicate=True)), "DUPLICATE_RELEASE_CANDIDATE_METADATA")


def test_duplicate_package_metadata_blocks() -> None:
    _blocked(_payload(replay_protection=_replay(duplicate_package_detected=True)), "DUPLICATE_RELEASE_CANDIDATE_METADATA")


def test_missing_validation_metadata_blocks() -> None:
    _blocked(_payload(validation_metadata=None), "VALIDATION_METADATA_MISSING")


def test_missing_policy_reference_blocks() -> None:
    _blocked(_payload(policy_reference=None), "POLICY_VERSION_MISSING")


def test_policy_version_mismatch_blocks() -> None:
    _blocked(_payload(policy_reference=_policy(policy_version="policy-v2")), "POLICY_VERSION_MISMATCH")


def test_missing_tenant_reference_blocks() -> None:
    _blocked(_payload(tenant_reference=None), "TENANT_REFERENCE_MISSING")


def test_tenant_mismatch_blocks() -> None:
    _blocked(_payload(tenant_reference=_tenant(expected_tenant_reference=HASH)), "TENANT_REFERENCE_MISMATCH")


def test_missing_correlation_reference_blocks() -> None:
    _blocked(_payload(correlation_reference=None), "CORRELATION_REFERENCE_MISSING")


def test_chronology_mismatch_blocks() -> None:
    _blocked(_payload(evidence_chain=_evidence(chronology_marker=0)), "CHRONOLOGY_MISMATCH")


def test_stale_metadata_blocks() -> None:
    _blocked(_payload(pb_1k=_pb_1k(metadata_stale=True)), "STALE_METADATA")


def test_unsupported_metadata_blocks() -> None:
    _blocked(_payload(unknown_field=HASH), "UNSUPPORTED_CAPABILITY_METADATA")


def test_upstream_blocked_propagates() -> None:
    _blocked(_payload(pb_1k=_pb_1k(final_decision=BLOCKED)), "UPSTREAM_BLOCKED")


def test_hash_mismatch_blocks() -> None:
    _blocked(_payload(expected_release_candidate_lock_hash=HASH), "RELEASE_CANDIDATE_LOCK_HASH_MISMATCH")


def test_execution_shaped_input_blocks() -> None:
    _blocked(_payload(direct_execution_requested=True), "EXECUTION_SURFACE_REJECTED")


def test_provider_execution_request_blocks() -> None:
    _blocked(_payload(safety_flags=_safety(provider_execution=True)), "EXECUTION_FLAG_NOT_FALSE")


def test_deployment_request_blocks() -> None:
    _blocked(_payload(safety_flags=_safety(deployment_authorized=True)), "EXECUTION_FLAG_NOT_FALSE")


def test_production_activation_request_blocks() -> None:
    _blocked(_payload(safety_flags=_safety(production_activation=True)), "EXECUTION_FLAG_NOT_FALSE")


def test_runtime_mutation_request_blocks() -> None:
    _blocked(_payload(safety_flags=_safety(runtime_mutation=True)), "EXECUTION_FLAG_NOT_FALSE")


def test_policy_mutation_request_blocks() -> None:
    _blocked(_payload(safety_flags=_safety(policy_mutation=True)), "EXECUTION_FLAG_NOT_FALSE")


def test_network_subprocess_request_blocks() -> None:
    _blocked(_payload(network_access=True), "EXECUTION_SURFACE_REJECTED")


def test_sensitive_input_blocks_without_leakage() -> None:
    result = _blocked(_payload(raw_payload="synthetic-sensitive"), "SENSITIVE_DATA_REJECTED")

    assert "synthetic-sensitive" not in json.dumps(result.to_dict(), sort_keys=True)


def test_credential_literal_blocks_without_leakage() -> None:
    synthetic_marker = "g" + "hp_" + ("x" * 36)
    result = _blocked(_payload(reference=synthetic_marker), "CREDENTIAL_LITERAL_REJECTED")

    assert synthetic_marker not in json.dumps(result.to_dict(), sort_keys=True)


def test_malformed_metadata_blocks() -> None:
    _blocked(None, "MALFORMED_PB_1L_METADATA")


def test_deterministic_repeated_evaluation() -> None:
    payload = _payload()

    assert evaluate_pb_1l_release_candidate_evidence_lock(payload).to_dict() == evaluate_pb_1l_release_candidate_evidence_lock(payload).to_dict()


def test_canonical_decision_state_and_reason_order() -> None:
    result = evaluate_pb_1l_release_candidate_evidence_lock(_payload(pb_1k=None, approval_chain=None))

    assert result.final_decision in {READY, READY_WITH_RESTRICTIONS, BLOCKED}
    assert result.reason_codes == tuple(sorted(result.reason_codes))


def test_canonical_json_is_stable() -> None:
    decision = evaluate_pb_1l_release_candidate_evidence_lock(_payload())

    assert canonical_pb_1l_json(decision) == canonical_pb_1l_json(decision)


def test_false_execution_flags_and_redacted_output() -> None:
    result = evaluate_pb_1l_release_candidate_evidence_lock(_payload())
    payload = result.to_dict()

    assert payload["release_candidate_lock_hash"].startswith("sha256:")
    assert payload["evidence_hash"].startswith("sha256:")
    assert payload["package_hash"].startswith("sha256:")
    assert payload["execution_allowed"] is False
    assert payload["provider_execution"] is False
    assert payload["production_activation"] is False
