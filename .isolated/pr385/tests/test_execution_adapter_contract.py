from __future__ import annotations

from runtime.computer_use.execution_adapter_contract import evaluate_execution_adapter_contract


HASH = "sha256:" + ("b" * 64)


def _contract(**overrides):
    contract = {
        "adapter_id": "local_mock_adapter",
        "adapter_type": "local_mock",
        "provider_class": "mock",
        "capability_id": "runtime.execute",
        "execution_contract": HASH,
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


def _prechecks(**overrides):
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


def _blocked(result, reason: str):
    assert result.decision == "BLOCKED"
    assert result.reason_code == reason
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
    assert result.evidence_hash.startswith("sha256:")


def test_valid_governed_execution_allows_mock_boundary() -> None:
    result = evaluate_execution_adapter_contract(_contract(), prechecks=_prechecks())

    assert result.decision == "ALLOWED"
    assert result.reason_code == "GOVERNED_ADAPTER_ALLOWED"
    assert result.execution_allowed is True
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False


def test_missing_policy_blocks() -> None:
    _blocked(evaluate_execution_adapter_contract(_contract(), prechecks=_prechecks(policy_evaluated=False)), "POLICY_MISSING")


def test_missing_approval_blocks() -> None:
    _blocked(evaluate_execution_adapter_contract(_contract(), prechecks=_prechecks(approval_valid=False)), "APPROVAL_MISSING")


def test_missing_execution_contract_blocks() -> None:
    _blocked(
        evaluate_execution_adapter_contract(_contract(), prechecks=_prechecks(execution_contract_valid=False)),
        "EXECUTION_CONTRACT_MISSING",
    )


def test_missing_dependency_blocks() -> None:
    _blocked(evaluate_execution_adapter_contract(_contract(), prechecks=_prechecks(dependency_ready=False)), "DEPENDENCY_NOT_READY")


def test_missing_runtime_blocks() -> None:
    _blocked(evaluate_execution_adapter_contract(_contract(), prechecks=_prechecks(runtime_ready=False)), "RUNTIME_NOT_READY")


def test_disabled_adapter_blocks() -> None:
    _blocked(evaluate_execution_adapter_contract(_contract(execution_status="DISABLED"), prechecks=_prechecks()), "ADAPTER_NOT_READY")


def test_timeout_adapter_blocks() -> None:
    _blocked(evaluate_execution_adapter_contract(_contract(adapter_id="timeout_adapter"), prechecks=_prechecks()), "ADAPTER_TIMEOUT")


def test_adapter_exception_blocks() -> None:
    def exploding_adapter(_contract):
        raise RuntimeError("synthetic failure")

    _blocked(
        evaluate_execution_adapter_contract(
            _contract(adapter_id="local_mock_adapter"),
            prechecks=_prechecks(),
            adapter_registry={"local_mock_adapter": exploding_adapter},
        ),
        "ADAPTER_EXCEPTION",
    )


def test_unsupported_adapter_blocks() -> None:
    _blocked(evaluate_execution_adapter_contract(_contract(adapter_id="provider_live_adapter"), prechecks=_prechecks()), "UNSUPPORTED_ADAPTER")


def test_malformed_adapter_response_blocks() -> None:
    _blocked(evaluate_execution_adapter_contract(_contract(adapter_id="malformed_adapter"), prechecks=_prechecks()), "MALFORMED_ADAPTER_RESPONSE")


def test_parameter_failure_blocks() -> None:
    _blocked(evaluate_execution_adapter_contract(_contract(), prechecks=_prechecks(parameters_valid=False)), "PARAMETERS_INVALID")


def test_replay_attack_blocks() -> None:
    _blocked(evaluate_execution_adapter_contract(_contract(), prechecks=_prechecks(replay_protection_passed=False)), "REPLAY_DETECTED")


def test_nonce_failure_blocks() -> None:
    _blocked(evaluate_execution_adapter_contract(_contract(), prechecks=_prechecks(nonce_valid=False)), "NONCE_INVALID")


def test_timestamp_expired_blocks() -> None:
    _blocked(evaluate_execution_adapter_contract(_contract(), prechecks=_prechecks(timestamp_window_valid=False)), "TIMESTAMP_INVALID")


def test_audit_unavailable_blocks() -> None:
    _blocked(
        evaluate_execution_adapter_contract(_contract(), prechecks=_prechecks(evidence_destination_ready=False)),
        "AUDIT_DESTINATION_UNAVAILABLE",
    )


def test_malformed_contract_blocks() -> None:
    malformed = _contract()
    malformed.pop("adapter_id")
    _blocked(evaluate_execution_adapter_contract(malformed, prechecks=_prechecks()), "MALFORMED_ADAPTER_CONTRACT")


def test_sensitive_contract_data_blocks_and_is_not_reported() -> None:
    result = evaluate_execution_adapter_contract(_contract(raw_payload="do-not-log"), prechecks=_prechecks())

    _blocked(result, "SENSITIVE_DATA_REJECTED")
    assert "do-not-log" not in str(result.to_dict())


def test_attempted_direct_execution_bypass_blocks() -> None:
    _blocked(evaluate_execution_adapter_contract(_contract(dry_run=False, decision="DENY"), prechecks=_prechecks()), "FINAL_DECISION_NOT_ALLOW")
