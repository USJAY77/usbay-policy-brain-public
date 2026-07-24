from __future__ import annotations

import json

from governance.production_integration_contracts import (
    PRODUCTION_INTEGRATION_CONTRACT_VERSION,
    PRODUCTION_INTEGRATION_RECEIPT_SCHEMA,
    REQUIRED_CAPABILITY_BY_INTEGRATION,
    RFC3161_INTEGRATION,
    WORM_INTEGRATION,
    ProductionIntegrationRequest,
)
from governance.production_provider_registry import (
    HealthObservation,
    HumanApprovalReference,
    ProviderRegistration,
    assess_controlled_activation,
    production_provider_registry_schema,
    register_provider,
    select_provider,
    serialize_provider_registry_result,
    validate_provider_registration,
    verify_health_observation,
)


HASH_A = "sha256:" + ("a" * 64)
HASH_B = "sha256:" + ("b" * 64)
HASH_C = "sha256:" + ("c" * 64)
OBSERVED_AT = "2026-07-21T00:00:00Z"
EXPIRES_AT = "2026-07-22T00:00:00Z"
CHECKED_AT = "2026-07-21T01:00:00Z"


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


def _request(**overrides):
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
        "observed_at": OBSERVED_AT,
        "expires_at": EXPIRES_AT,
        "status": "HEALTHY",
        "observation_hash": HASH_A,
        "source_reference": HASH_B,
        "tenant": "tenant-a",
        "policy_version": "policy.v1",
    }
    data.update(overrides)
    return HealthObservation(**data)


def _approval(**overrides):
    data = {
        "approval_reference_hash": HASH_C,
        "provider_id": "provider-a",
        "integration_type": RFC3161_INTEGRATION,
        "tenant": "tenant-a",
        "policy_version": "policy.v1",
        "approved_at": OBSERVED_AT,
        "expires_at": EXPIRES_AT,
    }
    data.update(overrides)
    return HumanApprovalReference(**data)


def test_schema_is_hash_only_and_execution_disabled() -> None:
    schema = production_provider_registry_schema()

    assert schema["payload_policy"] == "hash-only"
    assert schema["execution_allowed"] is False
    assert schema["provider_execution"] is False
    assert schema["production_activation"] is False
    assert schema["runtime_execution"] is False
    assert schema["deployment_execution"] is False
    assert schema["policy_mutation"] is False
    assert schema["network_access"] is False


def test_valid_registration() -> None:
    record = _registration().to_dict()

    assert validate_provider_registration(record) == ()
    assert record["registry_record_hash"].startswith("sha256:")


def test_duplicate_identical_registration_is_not_appended() -> None:
    registration = _registration()
    status, records, errors = register_provider((), registration)
    duplicate_status, duplicate_records, duplicate_errors = register_provider(records, registration)

    assert status == "REGISTERED"
    assert errors == ()
    assert duplicate_status == "REGISTERED"
    assert duplicate_errors == ("DUPLICATE_REGISTRATION",)
    assert duplicate_records == records


def test_conflicting_duplicate_registration_blocks() -> None:
    registration = _registration()
    _status, records, _errors = register_provider((), registration)

    status, updated_records, errors = register_provider(records, _registration(configuration_hash=HASH_B))

    assert status == "CONFIGURATION_INVALID"
    assert errors == ("CONFLICTING_REGISTRATION",)
    assert updated_records == records


def test_disabled_provider_blocks_selection() -> None:
    record = _registration(enabled=False, failure_code="PROVIDER_DISABLED").to_dict()
    result = select_provider(
        (record,),
        integration_type=RFC3161_INTEGRATION,
        provider_id="provider-a",
        tenant="tenant-a",
        policy_version="policy.v1",
        required_capabilities=(REQUIRED_CAPABILITY_BY_INTEGRATION[RFC3161_INTEGRATION],),
        contract_version=PRODUCTION_INTEGRATION_CONTRACT_VERSION,
    )

    assert result.result == "BLOCKED"
    assert result.failure_code == "PROVIDER_DISABLED"


def test_unknown_provider_blocks() -> None:
    result = select_provider(
        (),
        integration_type=RFC3161_INTEGRATION,
        provider_id="provider-a",
        tenant="tenant-a",
        policy_version="policy.v1",
        required_capabilities=(REQUIRED_CAPABILITY_BY_INTEGRATION[RFC3161_INTEGRATION],),
        contract_version=PRODUCTION_INTEGRATION_CONTRACT_VERSION,
    )

    assert result.failure_code == "PROVIDER_UNREGISTERED"


def test_ambiguous_provider_resolution_blocks() -> None:
    first = _registration(provider_id="provider-a").to_dict()
    second = _registration(provider_id="provider-b", configuration_hash=HASH_B).to_dict()

    result = select_provider(
        (first, second),
        integration_type=RFC3161_INTEGRATION,
        provider_id=None,
        tenant="tenant-a",
        policy_version="policy.v1",
        required_capabilities=(REQUIRED_CAPABILITY_BY_INTEGRATION[RFC3161_INTEGRATION],),
        contract_version=PRODUCTION_INTEGRATION_CONTRACT_VERSION,
    )

    assert result.failure_code == "AMBIGUOUS_PROVIDER"


def test_capability_mismatch_blocks() -> None:
    record = _registration(supported_capabilities=("detached_signature",)).to_dict()

    assert "CAPABILITY_MISMATCH" in validate_provider_registration(record)


def test_tenant_mismatch_blocks_selection() -> None:
    result = select_provider(
        (_registration().to_dict(),),
        integration_type=RFC3161_INTEGRATION,
        provider_id="provider-a",
        tenant="tenant-b",
        policy_version="policy.v1",
        required_capabilities=(REQUIRED_CAPABILITY_BY_INTEGRATION[RFC3161_INTEGRATION],),
        contract_version=PRODUCTION_INTEGRATION_CONTRACT_VERSION,
    )

    assert result.failure_code == "TENANT_SCOPE_MISMATCH"


def test_policy_version_mismatch_blocks_selection() -> None:
    result = select_provider(
        (_registration().to_dict(),),
        integration_type=RFC3161_INTEGRATION,
        provider_id="provider-a",
        tenant="tenant-a",
        policy_version="policy.v2",
        required_capabilities=(REQUIRED_CAPABILITY_BY_INTEGRATION[RFC3161_INTEGRATION],),
        contract_version=PRODUCTION_INTEGRATION_CONTRACT_VERSION,
    )

    assert result.failure_code == "POLICY_SCOPE_MISMATCH"


def test_incompatible_contract_version_blocks() -> None:
    record = _registration(contract_version="contract-v0").to_dict()

    assert "CONTRACT_VERSION_INCOMPATIBLE" in validate_provider_registration(record)


def test_malformed_timeout_and_retry_policy_block() -> None:
    record = _registration(timeout_ms=0, retry_policy={"max_attempts": 99, "backoff_ms": -1}).to_dict()

    errors = validate_provider_registration(record)

    assert "TIMEOUT_INVALID" in errors
    assert "RETRY_POLICY_INVALID" in errors


def test_expired_health_observation_blocks() -> None:
    errors = verify_health_observation(
        _health(expires_at="2026-07-20T00:00:00Z"),
        provider_record=_registration().to_dict(),
        checked_at=CHECKED_AT,
    )

    assert "HEALTH_OBSERVATION_INVALID" in errors
    assert "HEALTH_EXPIRED" in errors


def test_malformed_health_observation_blocks() -> None:
    payload = _health(status="BROKEN", observation_hash="bad").to_dict()

    errors = verify_health_observation(payload, provider_record=_registration().to_dict(), checked_at=CHECKED_AT)

    assert "HEALTH_OBSERVATION_INVALID" in errors


def test_missing_human_approval_blocks_activation() -> None:
    result = assess_controlled_activation(
        _registration().to_dict(),
        request=_request(),
        health_observation=_health(),
        approval=None,
        checked_at=CHECKED_AT,
    )

    assert result.result == "BLOCKED"
    assert result.failure_code == "HUMAN_APPROVAL_MISSING"


def test_expired_human_approval_blocks_activation() -> None:
    result = assess_controlled_activation(
        _registration().to_dict(),
        request=_request(),
        health_observation=_health(),
        approval=_approval(expires_at="2026-07-20T00:00:00Z"),
        checked_at=CHECKED_AT,
    )

    assert result.failure_code == "HUMAN_APPROVAL_EXPIRED"


def test_approval_scope_mismatch_blocks_activation() -> None:
    result = assess_controlled_activation(
        _registration().to_dict(),
        request=_request(),
        health_observation=_health(),
        approval=_approval(provider_id="provider-b"),
        checked_at=CHECKED_AT,
    )

    assert result.failure_code == "HUMAN_APPROVAL_SCOPE_MISMATCH"


def test_deterministic_registry_hashing_and_selection() -> None:
    first = _registration().to_dict()
    second = _registration().to_dict()
    first_selection = select_provider(
        (first,),
        integration_type=RFC3161_INTEGRATION,
        provider_id="provider-a",
        tenant="tenant-a",
        policy_version="policy.v1",
        required_capabilities=(REQUIRED_CAPABILITY_BY_INTEGRATION[RFC3161_INTEGRATION],),
        contract_version=PRODUCTION_INTEGRATION_CONTRACT_VERSION,
    )
    second_selection = select_provider(
        (second,),
        integration_type=RFC3161_INTEGRATION,
        provider_id="provider-a",
        tenant="tenant-a",
        policy_version="policy.v1",
        required_capabilities=(REQUIRED_CAPABILITY_BY_INTEGRATION[RFC3161_INTEGRATION],),
        contract_version=PRODUCTION_INTEGRATION_CONTRACT_VERSION,
    )

    assert first == second
    assert first_selection == second_selection


def test_raw_secret_marker_rejected() -> None:
    payload = _registration().to_dict()
    payload["raw_config"] = "blocked"

    assert "RAW_DATA_FORBIDDEN" in validate_provider_registration(payload)


def test_activation_never_enables_execution() -> None:
    result = assess_controlled_activation(
        _registration().to_dict(),
        request=_request(),
        health_observation=_health(),
        approval=_approval(),
        checked_at=CHECKED_AT,
    )
    payload = result.to_dict()

    assert result.result == "READY_FOR_CONTROLLED_ACTIVATION"
    assert payload["execution_allowed"] is False
    assert payload["provider_execution"] is False
    assert payload["production_activation"] is False
    assert payload["runtime_execution"] is False
    assert payload["deployment_execution"] is False
    assert payload["policy_mutation"] is False
    assert payload["network_access"] is False


def test_provider_registry_serialization_is_deterministic_and_hash_only() -> None:
    first = serialize_provider_registry_result(_registration())
    second = serialize_provider_registry_result(dict(reversed(_registration().to_dict().items())))

    assert first == second
    rendered = json.dumps(json.loads(first), sort_keys=True)
    assert "raw_config" not in rendered
    assert "private_key" not in rendered
    assert "credential" not in rendered
    assert "secret" not in rendered


def test_worm_provider_registration_uses_worm_capability() -> None:
    record = _registration(
        integration_type=WORM_INTEGRATION,
        supported_capabilities=(REQUIRED_CAPABILITY_BY_INTEGRATION[WORM_INTEGRATION],),
        supported_guarantees=("append_only_receipt",),
    ).to_dict()

    assert validate_provider_registration(record) == ()
