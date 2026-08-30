from __future__ import annotations

import json

from governance.audit_evidence import ZERO_AUDIT_CHAIN_HASH
from governance.production_integration_contracts import (
    PRODUCTION_INTEGRATION_CONTRACT_VERSION,
    PRODUCTION_INTEGRATION_RECEIPT_SCHEMA,
    REQUIRED_CAPABILITY_BY_INTEGRATION,
    RFC3161_INTEGRATION,
    ProductionIntegrationRequest,
)
from governance.production_provider_activation import (
    ACTIVATION_DECISION_STATES,
    PROHIBITED_ACTIVATION_STATES,
    ActivationRequest,
    bind_human_approval,
    build_production_decision_package,
    build_simulated_receipt,
    production_provider_activation_schema,
    run_offline_activation_simulation,
    serialize_provider_activation_result,
    validate_activation_request,
    verify_receipt_chain,
    verify_simulated_receipt,
)
from governance.production_provider_registry import (
    HealthObservation,
    HumanApprovalReference,
    ProviderRegistration,
    assess_controlled_activation,
)


HASH_A = "sha256:" + ("a" * 64)
HASH_B = "sha256:" + ("b" * 64)
HASH_C = "sha256:" + ("c" * 64)
HASH_D = "sha256:" + ("d" * 64)
HASH_E = "sha256:" + ("e" * 64)
HASH_F = "sha256:" + ("f" * 64)
REQUESTED_AT = "2026-07-21T00:00:00Z"
CHECKED_AT = "2026-07-21T01:00:00Z"
EXPIRES_AT = "2026-07-22T00:00:00Z"


def _registration(**overrides):
    data = {
        "provider_id": "provider-a",
        "integration_type": RFC3161_INTEGRATION,
        "adapter_version": "adapter-v1",
        "contract_version": PRODUCTION_INTEGRATION_CONTRACT_VERSION,
        "supported_capabilities": (REQUIRED_CAPABILITY_BY_INTEGRATION[RFC3161_INTEGRATION],),
        "tenant_scope": "tenant-a",
        "policy_version_scope": "policy.v1",
        "configuration_hash": HASH_A,
        "enabled": True,
        "health_state": "HEALTHY",
        "readiness_state": "REGISTERED",
        "failure_code": "",
        "timeout_ms": 3000,
        "retry_policy": {"max_attempts": 1, "backoff_ms": 100},
        "receipt_schema": PRODUCTION_INTEGRATION_RECEIPT_SCHEMA,
        "supported_guarantees": ("message_imprint_match",),
    }
    data.update(overrides)
    return ProviderRegistration(**data)


def _integration_request(**overrides):
    data = {
        "integration_name": RFC3161_INTEGRATION,
        "tenant": "tenant-a",
        "policy_version": "policy.v1",
        "correlation_id": HASH_B,
        "evidence_references": (HASH_C,),
        "timeout_ms": 3000,
        "provider_identifier": "provider-a",
    }
    data.update(overrides)
    return ProductionIntegrationRequest(**data)


def _health(**overrides):
    data = {
        "provider_id": "provider-a",
        "integration_type": RFC3161_INTEGRATION,
        "observed_at": REQUESTED_AT,
        "expires_at": EXPIRES_AT,
        "status": "HEALTHY",
        "observation_hash": HASH_D,
        "source_reference": HASH_E,
        "tenant": "tenant-a",
        "policy_version": "policy.v1",
    }
    data.update(overrides)
    return HealthObservation(**data)


def _approval(**overrides):
    data = {
        "approval_reference_hash": HASH_F,
        "provider_id": "provider-a",
        "integration_type": RFC3161_INTEGRATION,
        "tenant": "tenant-a",
        "policy_version": "policy.v1",
        "approved_at": REQUESTED_AT,
        "expires_at": EXPIRES_AT,
    }
    data.update(overrides)
    return HumanApprovalReference(**data)


def _readiness(registration=None, health=None, approval=None, request=None):
    return assess_controlled_activation(
        (registration or _registration()).to_dict(),
        request=request or _integration_request(),
        health_observation=health or _health(),
        approval=approval or _approval(),
        checked_at=CHECKED_AT,
    )


def _activation_request(**overrides):
    registration = _registration().to_dict()
    readiness = _readiness()
    data = {
        "activation_request_id": HASH_E,
        "provider_id": "provider-a",
        "integration_type": RFC3161_INTEGRATION,
        "tenant": "tenant-a",
        "policy_version": "policy.v1",
        "contract_version": PRODUCTION_INTEGRATION_CONTRACT_VERSION,
        "registry_record_hash": registration["registry_record_hash"],
        "configuration_hash": registration["configuration_hash"],
        "capability_hash": readiness.capability_hash,
        "health_observation_hash": readiness.health_observation_hash,
        "approval_reference_hash": readiness.approval_reference_hash,
        "requested_at": REQUESTED_AT,
        "expires_at": EXPIRES_AT,
        "correlation_id": HASH_B,
        "requested_by_reference": HASH_C,
        "reason_code": "OFFLINE_PROVIDER_REVIEW",
    }
    data.update(overrides)
    return ActivationRequest(**data)


def _simulation(request=None, registration=None, health=None, approval=None):
    return run_offline_activation_simulation(
        request or _activation_request(),
        provider_record=(registration or _registration()).to_dict(),
        integration_request=_integration_request(),
        health_observation=(health or _health()).to_dict(),
        approval=approval or _approval(),
        checked_at=CHECKED_AT,
    )


def test_schema_is_hash_only_simulation_only_and_execution_disabled() -> None:
    schema = production_provider_activation_schema()

    assert schema["payload_policy"] == "hash-only"
    assert schema["simulation_only"] is True
    assert "READY_FOR_HUMAN_PRODUCTION_DECISION" in schema["decision_states"]
    assert not set(PROHIBITED_ACTIVATION_STATES).intersection(ACTIVATION_DECISION_STATES)
    assert schema["execution_allowed"] is False
    assert schema["provider_execution"] is False
    assert schema["production_activation"] is False
    assert schema["runtime_execution"] is False
    assert schema["deployment_execution"] is False
    assert schema["policy_mutation"] is False
    assert schema["network_access"] is False
    assert schema["credentials_access"] is False
    assert schema["live_provider_call"] is False


def test_valid_activation_request() -> None:
    errors = validate_activation_request(
        _activation_request(),
        provider_record=_registration().to_dict(),
        readiness_assessment=_readiness(),
        checked_at=CHECKED_AT,
    )

    assert errors == ()


def test_malformed_request_blocks() -> None:
    request = _activation_request(activation_request_id="not-a-hash").to_dict()
    request["schema"] = "bad"

    errors = validate_activation_request(
        request,
        provider_record=_registration().to_dict(),
        readiness_assessment=_readiness(),
        checked_at=CHECKED_AT,
    )

    assert "ACTIVATION_REQUEST_MALFORMED" in errors


def test_expired_request_blocks() -> None:
    errors = validate_activation_request(
        _activation_request(expires_at="2026-07-20T00:00:00Z"),
        provider_record=_registration().to_dict(),
        readiness_assessment=_readiness(),
        checked_at=CHECKED_AT,
    )

    assert "ACTIVATION_REQUEST_EXPIRED" in errors


def test_duplicate_request_blocks() -> None:
    request = _activation_request().to_dict()

    errors = validate_activation_request(
        request,
        provider_record=_registration().to_dict(),
        readiness_assessment=_readiness(),
        checked_at=CHECKED_AT,
        existing_requests=(request,),
    )

    assert "ACTIVATION_DUPLICATE" in errors


def test_conflicting_request_blocks() -> None:
    request = _activation_request().to_dict()
    conflicting = {**request, "reason_code": "DIFFERENT_REASON"}

    errors = validate_activation_request(
        request,
        provider_record=_registration().to_dict(),
        readiness_assessment=_readiness(),
        checked_at=CHECKED_AT,
        existing_requests=(conflicting,),
    )

    assert "ACTIVATION_CONFLICTING_REQUEST" in errors


def test_missing_approval_requires_approval_without_activation() -> None:
    binding = bind_human_approval(_activation_request(), None, checked_at=CHECKED_AT)

    assert binding.result == "ACTIVATION_APPROVAL_REQUIRED"
    assert binding.failure_code == "ACTIVATION_APPROVAL_REQUIRED"
    assert binding.to_dict()["production_activation"] is False


def test_expired_approval_blocks() -> None:
    binding = bind_human_approval(
        _activation_request(),
        _approval(expires_at="2026-07-20T00:00:00Z"),
        checked_at=CHECKED_AT,
    )

    assert binding.result == "ACTIVATION_APPROVAL_EXPIRED"


def test_approval_replay_blocks() -> None:
    binding = bind_human_approval(
        _activation_request(),
        _approval(),
        checked_at=CHECKED_AT,
        replayed_approval_hashes=(HASH_F,),
    )

    assert binding.result == "ACTIVATION_REPLAY_BLOCKED"
    assert binding.failure_code == "ACTIVATION_APPROVAL_REPLAYED"


def test_consumed_approval_blocks() -> None:
    binding = bind_human_approval(
        _activation_request(),
        _approval(),
        checked_at=CHECKED_AT,
        consumed_approval_hashes=(HASH_F,),
    )

    assert binding.result == "ACTIVATION_REPLAY_BLOCKED"
    assert binding.failure_code == "ACTIVATION_APPROVAL_CONSUMED"


def test_tenant_mismatch_blocks() -> None:
    errors = validate_activation_request(
        _activation_request(tenant="tenant-b"),
        provider_record=_registration().to_dict(),
        readiness_assessment=_readiness(),
        checked_at=CHECKED_AT,
    )

    assert "ACTIVATION_SCOPE_MISMATCH" in errors


def test_policy_mismatch_blocks() -> None:
    errors = validate_activation_request(
        _activation_request(policy_version="policy.v2"),
        provider_record=_registration().to_dict(),
        readiness_assessment=_readiness(),
        checked_at=CHECKED_AT,
    )

    assert "ACTIVATION_SCOPE_MISMATCH" in errors


def test_provider_mismatch_blocks() -> None:
    binding = bind_human_approval(
        _activation_request(),
        _approval(provider_id="provider-b"),
        checked_at=CHECKED_AT,
    )

    assert binding.result == "ACTIVATION_SCOPE_MISMATCH"


def test_integration_mismatch_blocks() -> None:
    binding = bind_human_approval(
        _activation_request(),
        _approval(integration_type="worm_storage"),
        checked_at=CHECKED_AT,
    )

    assert binding.result == "ACTIVATION_SCOPE_MISMATCH"


def test_provider_not_ready_blocks_simulation() -> None:
    registration = _registration(enabled=False, failure_code="PROVIDER_DISABLED")
    request = _activation_request(registry_record_hash=registration.to_dict()["registry_record_hash"])
    simulation = _simulation(request=request, registration=registration)

    assert simulation.result == "ACTIVATION_SIMULATION_FAILED"
    assert simulation.failure_code == "ACTIVATION_PROVIDER_NOT_READY"


def test_invalid_health_blocks_simulation() -> None:
    simulation = _simulation(health=_health(status="DEGRADED"))

    assert simulation.result == "ACTIVATION_SIMULATION_FAILED"
    assert simulation.failure_code == "ACTIVATION_PROVIDER_NOT_READY"


def test_incompatible_contract_blocks() -> None:
    errors = validate_activation_request(
        _activation_request(contract_version="contract-v0"),
        provider_record=_registration().to_dict(),
        readiness_assessment=_readiness(),
        checked_at=CHECKED_AT,
    )

    assert "ACTIVATION_CONTRACT_INCOMPATIBLE" in errors


def test_successful_offline_simulation() -> None:
    simulation = _simulation()

    assert simulation.result == "ACTIVATION_SIMULATION_PASSED"
    assert simulation.failure_code == ""
    assert simulation.to_dict()["execution_allowed"] is False


def test_failed_offline_simulation() -> None:
    simulation = _simulation(request=_activation_request(expires_at="2026-07-21T00:30:00Z"))

    assert simulation.result == "ACTIVATION_SIMULATION_FAILED"
    assert simulation.failure_code == "ACTIVATION_REQUEST_EXPIRED"


def test_deterministic_simulated_receipt() -> None:
    request = _activation_request()
    simulation = _simulation(request=request)

    first = build_simulated_receipt(
        simulation,
        request,
        provider_record=_registration().to_dict(),
        approval_reference_hash=HASH_F,
        issued_at=REQUESTED_AT,
        expires_at=EXPIRES_AT,
    ).to_dict()
    second = build_simulated_receipt(
        simulation,
        request,
        provider_record=_registration().to_dict(),
        approval_reference_hash=HASH_F,
        issued_at=REQUESTED_AT,
        expires_at=EXPIRES_AT,
    ).to_dict()

    assert first == second
    assert first["simulation_only"] is True


def test_receipt_replay_detection() -> None:
    request = _activation_request()
    receipt = build_simulated_receipt(
        _simulation(request=request),
        request,
        provider_record=_registration().to_dict(),
        approval_reference_hash=HASH_F,
        issued_at=REQUESTED_AT,
        expires_at=EXPIRES_AT,
    ).to_dict()

    chain = verify_receipt_chain((receipt, receipt))

    assert chain.valid is False
    assert chain.failure_code == "ACTIVATION_RECEIPT_DUPLICATE"


def test_receipt_tamper_detection() -> None:
    request = _activation_request()
    receipt = build_simulated_receipt(
        _simulation(request=request),
        request,
        provider_record=_registration().to_dict(),
        approval_reference_hash=HASH_F,
        issued_at=REQUESTED_AT,
        expires_at=EXPIRES_AT,
    ).to_dict()
    receipt["tenant"] = "tenant-b"

    errors = verify_simulated_receipt(receipt, request=request, previous_receipt_hash=ZERO_AUDIT_CHAIN_HASH)

    assert "ACTIVATION_RECEIPT_SCHEMA_INVALID" in errors
    assert "ACTIVATION_RECEIPT_TAMPERED" in errors


def test_receipt_reorder_detection() -> None:
    request = _activation_request()
    first = build_simulated_receipt(
        _simulation(request=request),
        request,
        provider_record=_registration().to_dict(),
        approval_reference_hash=HASH_F,
        issued_at=REQUESTED_AT,
        expires_at=EXPIRES_AT,
    ).to_dict()
    second_request = _activation_request(activation_request_id=HASH_D)
    second = build_simulated_receipt(
        _simulation(request=second_request),
        second_request,
        provider_record=_registration().to_dict(),
        approval_reference_hash=HASH_F,
        issued_at="2026-07-21T02:00:00Z",
        expires_at=EXPIRES_AT,
        previous_receipt_hash=first["receipt_hash"],
    ).to_dict()

    chain = verify_receipt_chain((second, first))

    assert chain.valid is False
    assert chain.failure_code == "ACTIVATION_RECEIPT_REORDERED"


def test_receipt_deletion_detection() -> None:
    request = _activation_request()
    first = build_simulated_receipt(
        _simulation(request=request),
        request,
        provider_record=_registration().to_dict(),
        approval_reference_hash=HASH_F,
        issued_at=REQUESTED_AT,
        expires_at=EXPIRES_AT,
    ).to_dict()
    second_request = _activation_request(activation_request_id=HASH_D)
    second = build_simulated_receipt(
        _simulation(request=second_request),
        second_request,
        provider_record=_registration().to_dict(),
        approval_reference_hash=HASH_F,
        issued_at="2026-07-21T02:00:00Z",
        expires_at=EXPIRES_AT,
        previous_receipt_hash=first["receipt_hash"],
    ).to_dict()

    deleted_prefix_chain = verify_receipt_chain((second,))

    assert deleted_prefix_chain.valid is False
    assert deleted_prefix_chain.failure_code == "ACTIVATION_RECEIPT_REORDERED"


def test_raw_secret_marker_rejected() -> None:
    request = _activation_request().to_dict()
    request["raw_secret"] = "blocked"

    errors = validate_activation_request(
        request,
        provider_record=_registration().to_dict(),
        readiness_assessment=_readiness(),
        checked_at=CHECKED_AT,
    )

    assert errors == ("ACTIVATION_RAW_DATA_FORBIDDEN",)
    try:
        serialize_provider_activation_result(request)
    except ValueError as exc:
        assert str(exc) == "ACTIVATION_RAW_DATA_FORBIDDEN"
    else:
        raise AssertionError("raw marker serialization should fail closed")


def test_final_package_determinism() -> None:
    request = _activation_request()
    simulation = _simulation(request=request)
    receipt = build_simulated_receipt(
        simulation,
        request,
        provider_record=_registration().to_dict(),
        approval_reference_hash=HASH_F,
        issued_at=REQUESTED_AT,
        expires_at=EXPIRES_AT,
    )
    chain = verify_receipt_chain((receipt.to_dict(),))

    first = build_production_decision_package(
        request,
        provider_record=_registration().to_dict(),
        readiness_assessment=_readiness(),
        health_observation=_health().to_dict(),
        approval=_approval(),
        receipt=receipt,
        chain=chain,
        rollback_plan_reference=HASH_A,
    )
    second = build_production_decision_package(
        request,
        provider_record=_registration().to_dict(),
        readiness_assessment=_readiness(),
        health_observation=_health().to_dict(),
        approval=_approval(),
        receipt=receipt,
        chain=chain,
        rollback_plan_reference=HASH_A,
    )

    assert first == second
    assert first.result == "READY_FOR_HUMAN_PRODUCTION_DECISION"


def test_final_result_never_authorizes_execution() -> None:
    request = _activation_request()
    simulation = _simulation(request=request)
    receipt = build_simulated_receipt(
        simulation,
        request,
        provider_record=_registration().to_dict(),
        approval_reference_hash=HASH_F,
        issued_at=REQUESTED_AT,
        expires_at=EXPIRES_AT,
    )
    package = build_production_decision_package(
        request,
        provider_record=_registration().to_dict(),
        readiness_assessment=_readiness(),
        health_observation=_health().to_dict(),
        approval=_approval(),
        receipt=receipt,
        chain=verify_receipt_chain((receipt.to_dict(),)),
        rollback_plan_reference=HASH_A,
    ).to_dict()

    assert package["result"] == "READY_FOR_HUMAN_PRODUCTION_DECISION"
    assert package["execution_allowed"] is False
    assert package["provider_execution"] is False
    assert package["production_activation"] is False
    assert package["runtime_execution"] is False
    assert package["deployment_execution"] is False
    assert package["policy_mutation"] is False
    assert package["network_access"] is False
    assert package["credentials_access"] is False
    assert package["live_provider_call"] is False


def test_activation_serialization_is_hash_only_and_redacted() -> None:
    rendered = serialize_provider_activation_result(_activation_request())
    payload = json.loads(rendered)

    assert payload["schema"].endswith(".request")
    assert "raw_payload" not in rendered
    assert "private_key" not in rendered
    assert "secret" not in rendered
    assert "provider_response" not in rendered
