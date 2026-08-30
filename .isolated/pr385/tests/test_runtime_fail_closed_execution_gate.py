from __future__ import annotations

import json
from pathlib import Path

from runtime.computer_use.fail_closed_execution_gate import (
    ALLOW,
    APPROVAL_EXPIRED,
    APPROVAL_INVALID,
    APPROVAL_PENDING,
    APPROVAL_VALID,
    GATE_ALLOWED,
    GATE_BLOCKED,
    GATE_ERROR,
    GATE_HOLD,
    GATE_UNKNOWN,
    REQUIRED_REASON_CODES,
    evaluate_runtime_execution_gate,
)


HASH1 = "sha256:" + ("1" * 64)
HASH2 = "sha256:" + ("2" * 64)
HASH3 = "sha256:" + ("3" * 64)
OBSERVED_AT = "2026-07-26T12:00:00Z"
NOT_BEFORE = "2026-07-26T11:00:00Z"
EXPIRES_AT = "2026-07-26T13:00:00Z"


def _request() -> dict:
    return {
        "request_id": "req-p1-b1",
        "tenant_id": "tenant-usbay",
        "actor": "codex",
        "action": "runtime.execute",
        "target": "local-control-plane",
        "policy_version": "policy-v1",
    }


def _policy(succeeded: bool = True, policy_hash: str = HASH1) -> dict:
    return {"succeeded": succeeded, "policy_hash": policy_hash}


def _approval(status: str = APPROVAL_VALID, valid: bool = True, expired: bool = False) -> dict:
    return {
        "status": status,
        "valid": valid,
        "expired": expired,
        "approval_hash": HASH3,
        "approver": "human-governance-review",
    }


def _contract(valid: bool = True) -> dict:
    return {"valid": valid, "contract_hash": HASH1}


def _capability(authorized: bool = True) -> dict:
    return {"authorized": authorized, "capability": "runtime.execute"}


def _target(allowed: bool = True) -> dict:
    return {"allowed": allowed, "target": "local-control-plane"}


def _parameters(valid: bool = True) -> dict:
    return {"valid": valid, "parameter_hash": HASH2}


def _replay(passed: bool = True, replayed: bool = False) -> dict:
    return {"passed": passed, "replayed": replayed, "replay_hash": HASH3}


def _nonce(valid: bool = True, used: bool = False) -> dict:
    return {"valid": valid, "used": used, "nonce_hash": HASH1}


def _timestamp(
    valid: bool = True,
    observed_at: str = OBSERVED_AT,
    not_before: str = NOT_BEFORE,
    expires_at: str = EXPIRES_AT,
) -> dict:
    return {
        "valid": valid,
        "observed_at": observed_at,
        "not_before": not_before,
        "expires_at": expires_at,
        "timestamp_hash": HASH2,
    }


def _audit(write: bool = True, verified: bool = True, before: bool = True, audit_hash: str = HASH2) -> dict:
    return {"write_succeeded": write, "verified": verified, "before_execute": before, "audit_hash": audit_hash}


def _dependencies(*states: str) -> list[dict]:
    return [{"component": f"dependency-{index}", "state": state} for index, state in enumerate(states or ("READY",), 1)]


def _evaluate(**overrides):
    payload = {
        "request": _request(),
        "policy_evaluation": _policy(),
        "final_decision": ALLOW,
        "approval_state": _approval(),
        "execution_contract": _contract(),
        "capability": _capability(),
        "target_policy": _target(),
        "parameter_validation": _parameters(),
        "replay_protection": _replay(),
        "nonce_state": _nonce(),
        "timestamp_state": _timestamp(),
        "audit_gate": _audit(),
        "runtime_state": "READY",
        "dependencies": _dependencies("READY"),
        "provider_execution_permitted": True,
        "production_activation_permitted": True,
        "deployment_authorized": True,
    }
    payload.update(overrides)
    return evaluate_runtime_execution_gate(**payload)


def _assert_not_allowed(result, reason: str, gate_status: str = GATE_BLOCKED) -> None:
    assert result.gate_status == gate_status
    assert result.reason_code == reason
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
    assert result.release_authorized is False
    assert result.to_dict()["decision_hash"].startswith("sha256:")


def test_required_reason_codes_cover_mandatory_fail_closed_contract() -> None:
    required = {
        "POLICY_DENIED",
        "POLICY_UNKNOWN",
        "APPROVAL_MISSING",
        "APPROVAL_EXPIRED",
        "APPROVAL_INVALID",
        "CONTRACT_INVALID",
        "CAPABILITY_DENIED",
        "TARGET_NOT_ALLOWED",
        "PARAMETERS_INVALID",
        "REPLAY_DETECTED",
        "NONCE_INVALID",
        "TIMESTAMP_INVALID",
        "AUDIT_WRITE_FAILED",
        "AUDIT_VERIFICATION_FAILED",
        "RUNTIME_NOT_READY",
        "DEPENDENCY_NOT_READY",
        "PROVIDER_EXECUTION_DISABLED",
        "PRODUCTION_ACTIVATION_DISABLED",
        "DEPLOYMENT_NOT_AUTHORIZED",
        "MALFORMED_INPUT",
        "UNSUPPORTED_STATE",
        "INTERNAL_ERROR",
    }

    assert set(REQUIRED_REASON_CODES) == required


def test_missing_policy_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(policy_evaluation=None), "POLICY_UNKNOWN")


def test_failed_policy_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(policy_evaluation=_policy(False)), "POLICY_UNKNOWN")


def test_invalid_policy_hash_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(policy_evaluation=_policy(policy_hash="not-a-hash")), "POLICY_UNKNOWN")


def test_final_decision_missing_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(final_decision=None), "POLICY_UNKNOWN")


def test_final_decision_not_allow_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(final_decision="DENY"), "POLICY_DENIED")


def test_unsupported_final_decision_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(final_decision="ALLOW_WITHOUT_AUDIT"), "UNSUPPORTED_STATE")


def test_missing_approval_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(approval_state=None), "APPROVAL_MISSING")


def test_pending_approval_holds_and_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(approval_state=_approval(APPROVAL_PENDING, False)), "APPROVAL_MISSING", GATE_HOLD)


def test_expired_approval_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(approval_state=_approval(APPROVAL_EXPIRED, True, True)), "APPROVAL_EXPIRED")


def test_invalid_approval_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(approval_state=_approval(APPROVAL_INVALID, False)), "APPROVAL_INVALID")


def test_actor_cannot_self_approve() -> None:
    approval = _approval()
    approval["approver"] = "codex"

    _assert_not_allowed(_evaluate(approval_state=approval), "APPROVAL_INVALID")


def test_invalid_execution_contract_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(execution_contract=_contract(False)), "CONTRACT_INVALID")


def test_unauthorized_capability_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(capability=_capability(False)), "CAPABILITY_DENIED")


def test_disallowed_target_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(target_policy=_target(False)), "TARGET_NOT_ALLOWED")


def test_invalid_parameters_block_execution() -> None:
    _assert_not_allowed(_evaluate(parameter_validation=_parameters(False)), "PARAMETERS_INVALID")


def test_replay_detected_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(replay_protection=_replay(replayed=True)), "REPLAY_DETECTED")


def test_missing_replay_proof_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(replay_protection=_replay(passed=False)), "REPLAY_DETECTED")


def test_invalid_nonce_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(nonce_state=_nonce(False)), "NONCE_INVALID")


def test_used_nonce_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(nonce_state=_nonce(True, True)), "NONCE_INVALID")


def test_expired_timestamp_blocks_execution() -> None:
    _assert_not_allowed(
        _evaluate(timestamp_state=_timestamp(observed_at="2026-07-26T14:00:00Z")),
        "TIMESTAMP_INVALID",
    )


def test_future_timestamp_window_blocks_execution() -> None:
    _assert_not_allowed(
        _evaluate(timestamp_state=_timestamp(observed_at="2026-07-26T10:00:00Z")),
        "TIMESTAMP_INVALID",
    )


def test_missing_audit_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(audit_gate=None), "AUDIT_WRITE_FAILED")


def test_audit_write_failure_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(audit_gate=_audit(write=False)), "AUDIT_WRITE_FAILED")


def test_audit_verification_failure_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(audit_gate=_audit(verified=False)), "AUDIT_VERIFICATION_FAILED")


def test_invalid_audit_hash_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(audit_gate=_audit(audit_hash="not-a-hash")), "AUDIT_VERIFICATION_FAILED")


def test_audit_before_execute_is_required() -> None:
    _assert_not_allowed(_evaluate(audit_gate=_audit(before=False)), "AUDIT_WRITE_FAILED")


def test_unknown_runtime_state_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(runtime_state="UNKNOWN"), "RUNTIME_NOT_READY")


def test_unsupported_runtime_state_fails_unknown_without_allowing_execution() -> None:
    _assert_not_allowed(_evaluate(runtime_state="READY_ENOUGH"), "UNSUPPORTED_STATE", GATE_UNKNOWN)


def test_dependency_not_ready_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(dependencies=_dependencies("READY", "BLOCKED")), "DEPENDENCY_NOT_READY")


def test_missing_dependency_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(dependencies=[]), "DEPENDENCY_NOT_READY")


def test_provider_execution_disabled_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(provider_execution_permitted=False), "PROVIDER_EXECUTION_DISABLED")


def test_production_activation_disabled_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(production_activation_permitted=False), "PRODUCTION_ACTIVATION_DISABLED")


def test_deployment_authorization_missing_blocks_execution() -> None:
    _assert_not_allowed(_evaluate(deployment_authorized=False), "DEPLOYMENT_NOT_AUTHORIZED")


def test_malformed_request_blocks_execution() -> None:
    request = _request()
    request["tenant_id"] = ""

    _assert_not_allowed(_evaluate(request=request), "MALFORMED_INPUT")


def test_raw_payload_request_blocks_execution_and_is_not_logged() -> None:
    request = _request()
    request["raw_payload"] = "do-not-log-this-sensitive-payload"

    result = _evaluate(request=request)

    _assert_not_allowed(result, "MALFORMED_INPUT")
    assert "do-not-log-this-sensitive-payload" not in json.dumps(result.to_dict(), sort_keys=True)


def test_internal_errors_fail_closed() -> None:
    class ExplodingPolicy(dict):
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            raise RuntimeError("synthetic validation failure")

    result = _evaluate(policy_evaluation=ExplodingPolicy())

    _assert_not_allowed(result, "INTERNAL_ERROR", GATE_ERROR)


def test_explicit_allow_path_succeeds_after_all_controls_and_audit_before_execute() -> None:
    result = _evaluate()

    assert result.gate_status == GATE_ALLOWED
    assert result.reason_code == "EXECUTION_GATE_ALLOWED"
    assert result.execution_allowed is True
    assert result.provider_execution is True
    assert result.production_activation is True
    assert result.deployment_authorized is True
    assert result.release_authorized is False
    assert result.audit_hash == HASH2
    assert result.to_dict()["decision_hash"].startswith("sha256:")


def test_outputs_are_deterministic_for_identical_inputs() -> None:
    assert _evaluate().to_dict() == _evaluate().to_dict()


def test_evidence_file_records_required_paths_and_reason_codes() -> None:
    evidence = json.loads(Path("governance/evidence/runtime_fail_closed_execution_gate.json").read_text(encoding="utf-8"))

    assert evidence["batch"] == "P1-B1"
    assert evidence["evidence"]["deny_path"]["expected_gate_status"] == "BLOCKED"
    assert evidence["evidence"]["hold_path"]["expected_gate_status"] == "HOLD"
    assert evidence["evidence"]["allow_path"]["expected_gate_status"] == "ALLOWED"
    assert evidence["evidence"]["audit_before_execute_path"]["required"] is True
    assert evidence["fail_closed_defaults"]["execution_allowed"] is False
    assert set(evidence["reason_codes"]) == set(REQUIRED_REASON_CODES)
