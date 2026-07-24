from __future__ import annotations

import json

import pytest

from governance.production_integration_contracts import (
    EXTERNAL_SIGNING_INTEGRATION,
    OBJECT_LOCK_INTEGRATION,
    PRODUCTION_INTEGRATION_RECEIPT_SCHEMA,
    REGULATOR_EXPORT_INTEGRATION,
    REQUIRED_CAPABILITY_BY_INTEGRATION,
    RFC3161_INTEGRATION,
    SUPPORTED_GUARANTEE_BY_INTEGRATION,
    WORM_INTEGRATION,
    ProductionIntegrationRequest,
    ProviderCapability,
    UnavailableProductionIntegrationAdapter,
    build_readiness_report,
    build_receipt,
    build_unavailable_readiness_report,
    production_integration_contract_schema,
    serialize_contract_result,
    validate_integration_request,
    validate_provider_capability,
    verify_receipt,
)


HASH_A = "sha256:" + ("a" * 64)
HASH_B = "sha256:" + ("b" * 64)
HASH_C = "sha256:" + ("c" * 64)


def _request(integration_name: str = RFC3161_INTEGRATION) -> ProductionIntegrationRequest:
    return ProductionIntegrationRequest(
        integration_name=integration_name,
        tenant="tenant-a",
        policy_version="policy.v1",
        correlation_id=HASH_A,
        evidence_references=(HASH_B,),
        timeout_ms=3000,
        provider_identifier="provider-a",
    )


def _capability(integration_name: str = RFC3161_INTEGRATION) -> ProviderCapability:
    return ProviderCapability(
        integration_name=integration_name,
        provider_identifier="provider-a",
        tenant_scope="tenant-a",
        policy_version_scope="policy.v1",
        capabilities=(REQUIRED_CAPABILITY_BY_INTEGRATION[integration_name],),
        supported_guarantees=(SUPPORTED_GUARANTEE_BY_INTEGRATION[integration_name][0],),
        receipt_schema=PRODUCTION_INTEGRATION_RECEIPT_SCHEMA,
        timeout_ms=3000,
    )


def test_contract_schema_is_hash_only_and_execution_disabled() -> None:
    schema = production_integration_contract_schema()

    assert schema["payload_policy"] == "hash-only"
    assert schema["execution_allowed"] is False
    assert schema["provider_execution"] is False
    assert schema["production_activation"] is False
    assert schema["runtime_execution"] is False
    assert schema["deployment_execution"] is False
    assert schema["policy_mutation"] is False
    assert schema["network_access"] is False


@pytest.mark.parametrize(
    ("integration_name", "expected_failure"),
    (
        (RFC3161_INTEGRATION, "RFC3161_UNAVAILABLE"),
        (EXTERNAL_SIGNING_INTEGRATION, "SIGNING_UNAVAILABLE"),
        (WORM_INTEGRATION, "WORM_UNAVAILABLE"),
        (OBJECT_LOCK_INTEGRATION, "OBJECT_LOCK_UNAVAILABLE"),
        (REGULATOR_EXPORT_INTEGRATION, "REGULATOR_TRANSPORT_UNAVAILABLE"),
    ),
)
def test_unavailable_provider_fails_closed_without_receipt(integration_name: str, expected_failure: str) -> None:
    adapter = UnavailableProductionIntegrationAdapter(integration_name)
    response = adapter.evaluate(_request(integration_name))

    assert response.status == "UNAVAILABLE"
    assert response.failure_code == expected_failure
    assert response.receipt is None
    assert response.to_dict()["execution_allowed"] is False
    assert response.to_dict()["provider_execution"] is False
    assert response.to_dict()["production_activation"] is False


def test_malformed_request_blocks() -> None:
    request = _request()
    malformed = request.to_dict()
    malformed["evidence_references"] = []
    malformed["timeout_ms"] = 0

    errors = validate_integration_request(malformed)

    assert "EVIDENCE_REFERENCE_MISSING" in errors
    assert "TIMEOUT_INVALID" in errors


def test_provider_capability_rejects_missing_provider_identifier() -> None:
    capability = _capability().to_dict()
    capability["provider_identifier"] = ""

    assert "PROVIDER_IDENTIFIER_MISSING" in validate_provider_capability(capability, request=_request())


def test_provider_capability_rejects_tenant_and_policy_mismatch() -> None:
    capability = _capability().to_dict()
    capability["tenant_scope"] = "tenant-b"
    capability["policy_version_scope"] = "policy.v2"

    errors = validate_provider_capability(capability, request=_request())

    assert "TENANT_MISMATCH" in errors
    assert "POLICY_VERSION_MISMATCH" in errors


def test_provider_capability_rejects_unsupported_capability_and_guarantee() -> None:
    capability = _capability().to_dict()
    capability["capabilities"] = ["network_execute"]
    capability["supported_guarantees"] = ["provider_claims_success"]

    errors = validate_provider_capability(capability, request=_request())

    assert "PROVIDER_CAPABILITY_MISSING" in errors
    assert "PROVIDER_CAPABILITY_UNSUPPORTED" in errors
    assert "UNSUPPORTED_GUARANTEE" in errors


def test_provider_capability_rejects_invalid_receipt_schema_and_timeout() -> None:
    capability = _capability().to_dict()
    capability["receipt_schema"] = "schema.invalid"
    capability["timeout_ms"] = 999999

    errors = validate_provider_capability(capability, request=_request())

    assert "RECEIPT_SCHEMA_INVALID" in errors
    assert "TIMEOUT_INVALID" in errors


def test_readiness_report_is_deterministic_and_never_production_ready() -> None:
    first = build_readiness_report(
        RFC3161_INTEGRATION,
        capability=_capability(),
        request=_request(),
        required_dependencies=("proof_timestamp_anchor",),
    )
    second = build_readiness_report(
        RFC3161_INTEGRATION,
        capability=_capability(),
        request=_request(),
        required_dependencies=("proof_timestamp_anchor",),
    )

    assert first == second
    assert first.configured is True
    assert first.production_ready is False
    assert first.to_dict()["production_activation"] is False


def test_unavailable_readiness_report_blocks() -> None:
    report = build_unavailable_readiness_report(WORM_INTEGRATION, required_dependencies=("sealed_audit_archive",))

    assert report.configured is False
    assert report.provider_capability_status == "UNAVAILABLE"
    assert report.blocking_failure_code == "WORM_UNAVAILABLE"
    assert report.production_ready is False


def test_valid_rejected_receipt_is_deterministic_and_hash_only() -> None:
    request = _request()
    receipt = build_receipt(
        request,
        provider_identifier="provider-a",
        receipt_status="RECEIPT_REJECTED",
        failure_code="PROVIDER_UNAVAILABLE",
        provider_receipt_hash=HASH_C,
    )
    repeated = build_receipt(
        request,
        provider_identifier="provider-a",
        receipt_status="RECEIPT_REJECTED",
        failure_code="PROVIDER_UNAVAILABLE",
        provider_receipt_hash=HASH_C,
    )

    assert receipt == repeated
    assert verify_receipt(receipt, request=request) == ()
    rendered = serialize_contract_result(receipt)
    assert "raw_payload" not in rendered
    assert "private_key" not in rendered
    assert "credential" not in rendered
    assert "secret" not in rendered
    assert receipt.to_dict()["execution_allowed"] is False


def test_invalid_receipt_blocks_missing_evidence_reference() -> None:
    request = _request()
    receipt = build_receipt(
        request,
        provider_identifier="provider-a",
        receipt_status="RECEIPT_REJECTED",
        failure_code="PROVIDER_UNAVAILABLE",
        provider_receipt_hash=HASH_C,
    ).to_dict()
    receipt["evidence_references"] = []
    receipt["receipt_hash"] = HASH_A

    assert "EVIDENCE_REFERENCE_MISSING" in verify_receipt(receipt, request=request)


def test_duplicate_receipt_detection() -> None:
    request = _request()
    receipt = build_receipt(
        request,
        provider_identifier="provider-a",
        receipt_status="RECEIPT_REJECTED",
        failure_code="PROVIDER_UNAVAILABLE",
        provider_receipt_hash=HASH_C,
    ).to_dict()

    assert "DUPLICATE_RECEIPT" in verify_receipt(receipt, request=request, existing_receipts=(receipt,))


def test_fake_success_is_rejected() -> None:
    request = _request()
    receipt = build_receipt(
        request,
        provider_identifier="provider-a",
        receipt_status="RECEIPT_REJECTED",
        failure_code="PROVIDER_UNAVAILABLE",
        provider_receipt_hash=HASH_C,
    ).to_dict()
    receipt["receipt_status"] = "SUCCESS"
    receipt["receipt_hash"] = HASH_A

    assert "FAKE_SUCCESS_REJECTED" in verify_receipt(receipt, request=request)


def test_raw_data_rejected() -> None:
    request = _request()
    payload = request.to_dict()
    payload["raw_payload"] = "blocked"

    assert "RAW_DATA_FORBIDDEN" in validate_integration_request(payload)


def test_contract_serialization_is_stable() -> None:
    request = _request()
    first = serialize_contract_result(request)
    second = serialize_contract_result(dict(reversed(request.to_dict().items())))

    assert first == second
    assert json.loads(first)["execution_allowed"] is False
