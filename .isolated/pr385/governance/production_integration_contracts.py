from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from governance.audit_evidence import canonical_audit_json, sha256_audit_hash
from governance.production_integration_matrix import (
    EXTERNAL_SIGNING_INTEGRATION,
    OBJECT_LOCK_INTEGRATION,
    REGULATOR_EXPORT_INTEGRATION,
    RFC3161_INTEGRATION,
    WORM_INTEGRATION,
    fail_closed_execution_flags,
)


PRODUCTION_INTEGRATION_CONTRACT_SCHEMA = "usbay.governance.production_integration_contracts.v1"
PRODUCTION_INTEGRATION_RECEIPT_SCHEMA = PRODUCTION_INTEGRATION_CONTRACT_SCHEMA + ".receipt"
PRODUCTION_INTEGRATION_READINESS_SCHEMA = PRODUCTION_INTEGRATION_CONTRACT_SCHEMA + ".readiness"
PRODUCTION_INTEGRATION_CONTRACT_VERSION = "production-integration-contracts-v1"
SUPPORTED_INTEGRATIONS = (
    RFC3161_INTEGRATION,
    EXTERNAL_SIGNING_INTEGRATION,
    WORM_INTEGRATION,
    OBJECT_LOCK_INTEGRATION,
    REGULATOR_EXPORT_INTEGRATION,
)
UNAVAILABLE_STATUS_BY_INTEGRATION = {
    RFC3161_INTEGRATION: "RFC3161_UNAVAILABLE",
    EXTERNAL_SIGNING_INTEGRATION: "SIGNING_UNAVAILABLE",
    WORM_INTEGRATION: "WORM_UNAVAILABLE",
    OBJECT_LOCK_INTEGRATION: "OBJECT_LOCK_UNAVAILABLE",
    REGULATOR_EXPORT_INTEGRATION: "REGULATOR_TRANSPORT_UNAVAILABLE",
}
REQUIRED_CAPABILITY_BY_INTEGRATION = {
    RFC3161_INTEGRATION: "rfc3161_timestamp_token",
    EXTERNAL_SIGNING_INTEGRATION: "detached_signature",
    WORM_INTEGRATION: "worm_write_receipt",
    OBJECT_LOCK_INTEGRATION: "object_lock_receipt",
    REGULATOR_EXPORT_INTEGRATION: "regulator_submission_receipt",
}
RECEIPT_STATUS_VALUES = (
    "RECEIPT_VERIFIED",
    "RECEIPT_REJECTED",
    *UNAVAILABLE_STATUS_BY_INTEGRATION.values(),
)
READINESS_STATUS_VALUES = ("CONFIGURED", "UNAVAILABLE", "BLOCKED")
CONTRACT_FAILURE_CODES = (
    "INTEGRATION_UNKNOWN",
    "PROVIDER_IDENTIFIER_MISSING",
    "PROVIDER_CAPABILITY_MISSING",
    "PROVIDER_CAPABILITY_UNSUPPORTED",
    "TENANT_MISMATCH",
    "POLICY_VERSION_MISMATCH",
    "TIMEOUT_INVALID",
    "RECEIPT_SCHEMA_INVALID",
    "EVIDENCE_REFERENCE_MISSING",
    "UNSUPPORTED_GUARANTEE",
    "DUPLICATE_RECEIPT",
    "FAKE_SUCCESS_REJECTED",
    "RAW_DATA_FORBIDDEN",
    "PROVIDER_UNAVAILABLE",
    "FAILED_CLOSED",
)
SUPPORTED_GUARANTEE_BY_INTEGRATION = {
    RFC3161_INTEGRATION: ("message_imprint_match", "tsa_policy_oid_bound", "tsa_chain_verifiable"),
    EXTERNAL_SIGNING_INTEGRATION: ("detached_signature_verified", "signer_fingerprint_bound"),
    WORM_INTEGRATION: ("append_only_receipt", "retention_policy_bound"),
    OBJECT_LOCK_INTEGRATION: ("object_version_bound", "legal_hold_bound", "retain_until_bound"),
    REGULATOR_EXPORT_INTEGRATION: ("delivery_receipt_verified", "jurisdiction_bound", "dry_run_supported"),
}
_RAW_MARKERS = (
    "raw_payload",
    "raw_evidence",
    "raw_approval",
    "approval_content",
    "payload_body",
    "private_key",
    "credential",
    "credentials",
    "secret",
    "access_token",
    "certificate_body",
)
_EXECUTION_FLAGS = (
    "execution_allowed",
    "provider_execution",
    "production_activation",
    "runtime_execution",
    "deployment_execution",
    "policy_mutation",
    "network_access",
)


class ProductionIntegrationProvider(Protocol):
    integration_name: str
    provider_identifier: str

    def evaluate(self, request: "ProductionIntegrationRequest") -> "ProductionIntegrationResponse":
        ...


@dataclass(frozen=True)
class ProductionIntegrationRequest:
    integration_name: str
    tenant: str
    policy_version: str
    correlation_id: str
    evidence_references: tuple[str, ...]
    timeout_ms: int
    provider_identifier: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_name": self.integration_name,
            "tenant": self.tenant,
            "policy_version": self.policy_version,
            "correlation_id": self.correlation_id,
            "evidence_references": list(self.evidence_references),
            "timeout_ms": self.timeout_ms,
            "provider_identifier": self.provider_identifier,
            **_false_execution_flags(),
        }


@dataclass(frozen=True)
class ProviderCapability:
    integration_name: str
    provider_identifier: str
    tenant_scope: str
    policy_version_scope: str
    capabilities: tuple[str, ...]
    supported_guarantees: tuple[str, ...]
    receipt_schema: str
    timeout_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_name": self.integration_name,
            "provider_identifier": self.provider_identifier,
            "tenant_scope": self.tenant_scope,
            "policy_version_scope": self.policy_version_scope,
            "capabilities": list(self.capabilities),
            "supported_guarantees": list(self.supported_guarantees),
            "receipt_schema": self.receipt_schema,
            "timeout_ms": self.timeout_ms,
            **_false_execution_flags(),
        }


@dataclass(frozen=True)
class ProductionIntegrationReceipt:
    integration_name: str
    provider_identifier: str
    tenant: str
    policy_version: str
    correlation_id: str
    evidence_references: tuple[str, ...]
    receipt_status: str
    failure_code: str
    provider_receipt_hash: str
    timeout_ms: int
    receipt_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PRODUCTION_INTEGRATION_RECEIPT_SCHEMA,
            "integration_name": self.integration_name,
            "provider_identifier": self.provider_identifier,
            "tenant": self.tenant,
            "policy_version": self.policy_version,
            "correlation_id": self.correlation_id,
            "evidence_references": list(self.evidence_references),
            "receipt_status": self.receipt_status,
            "failure_code": self.failure_code,
            "provider_receipt_hash": self.provider_receipt_hash,
            "timeout_ms": self.timeout_ms,
            "receipt_hash": self.receipt_hash,
            **_false_execution_flags(),
        }


@dataclass(frozen=True)
class ProductionIntegrationResponse:
    integration_name: str
    status: str
    failure_code: str
    receipt: ProductionIntegrationReceipt | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_name": self.integration_name,
            "status": self.status,
            "failure_code": self.failure_code,
            "receipt": self.receipt.to_dict() if self.receipt else None,
            **_false_execution_flags(),
        }


@dataclass(frozen=True)
class IntegrationReadinessReport:
    integration_name: str
    configured: bool
    provider_capability_status: str
    contract_version: str
    required_dependencies: tuple[str, ...]
    blocking_failure_code: str
    production_ready: bool
    readiness_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PRODUCTION_INTEGRATION_READINESS_SCHEMA,
            "integration_name": self.integration_name,
            "configured": self.configured,
            "provider_capability_status": self.provider_capability_status,
            "contract_version": self.contract_version,
            "required_dependencies": list(self.required_dependencies),
            "blocking_failure_code": self.blocking_failure_code,
            "production_ready": self.production_ready,
            "readiness_hash": self.readiness_hash,
            **_false_execution_flags(),
        }


class UnavailableProductionIntegrationAdapter:
    def __init__(self, integration_name: str, provider_identifier: str = "unavailable") -> None:
        if integration_name not in SUPPORTED_INTEGRATIONS:
            raise ValueError("INTEGRATION_UNKNOWN")
        self.integration_name = integration_name
        self.provider_identifier = provider_identifier

    def evaluate(self, request: ProductionIntegrationRequest) -> ProductionIntegrationResponse:
        errors = validate_integration_request(request)
        failure_code = errors[0] if errors else UNAVAILABLE_STATUS_BY_INTEGRATION[self.integration_name]
        return ProductionIntegrationResponse(
            integration_name=self.integration_name,
            status="UNAVAILABLE",
            failure_code=failure_code,
            receipt=None,
        )


def production_integration_contract_schema() -> dict[str, Any]:
    return {
        "schema": PRODUCTION_INTEGRATION_CONTRACT_SCHEMA,
        "receipt_schema": PRODUCTION_INTEGRATION_RECEIPT_SCHEMA,
        "readiness_schema": PRODUCTION_INTEGRATION_READINESS_SCHEMA,
        "contract_version": PRODUCTION_INTEGRATION_CONTRACT_VERSION,
        "supported_integrations": list(SUPPORTED_INTEGRATIONS),
        "receipt_status_values": list(RECEIPT_STATUS_VALUES),
        "readiness_status_values": list(READINESS_STATUS_VALUES),
        "failure_codes": list(CONTRACT_FAILURE_CODES),
        "payload_policy": "hash-only",
        **_false_execution_flags(),
    }


def validate_integration_request(request: ProductionIntegrationRequest | dict[str, Any]) -> tuple[str, ...]:
    payload = request.to_dict() if isinstance(request, ProductionIntegrationRequest) else dict(request)
    errors: list[str] = []
    integration_name = str(payload.get("integration_name", ""))
    if integration_name not in SUPPORTED_INTEGRATIONS:
        errors.append("INTEGRATION_UNKNOWN")
    if not str(payload.get("tenant", "")).strip():
        errors.append("TENANT_MISMATCH")
    if not str(payload.get("policy_version", "")).strip():
        errors.append("POLICY_VERSION_MISMATCH")
    if not _is_sha256_reference(payload.get("correlation_id")):
        errors.append("EVIDENCE_REFERENCE_MISSING")
    if not _evidence_references_valid(payload.get("evidence_references")):
        errors.append("EVIDENCE_REFERENCE_MISSING")
    if not _timeout_valid(payload.get("timeout_ms")):
        errors.append("TIMEOUT_INVALID")
    if any(payload.get(flag) is not False for flag in _EXECUTION_FLAGS):
        errors.append("FAILED_CLOSED")
    if _has_raw_marker(payload):
        errors.append("RAW_DATA_FORBIDDEN")
    return _ordered_unique(errors)


def validate_provider_capability(
    capability: ProviderCapability | dict[str, Any],
    *,
    request: ProductionIntegrationRequest,
) -> tuple[str, ...]:
    payload = capability.to_dict() if isinstance(capability, ProviderCapability) else dict(capability)
    errors = list(validate_integration_request(request))
    integration_name = str(payload.get("integration_name", ""))
    if integration_name not in SUPPORTED_INTEGRATIONS or integration_name != request.integration_name:
        errors.append("INTEGRATION_UNKNOWN")
    if not str(payload.get("provider_identifier", "")).strip():
        errors.append("PROVIDER_IDENTIFIER_MISSING")
    required_capability = REQUIRED_CAPABILITY_BY_INTEGRATION.get(request.integration_name, "")
    capabilities = tuple(payload.get("capabilities", ())) if isinstance(payload.get("capabilities"), (list, tuple)) else ()
    if required_capability not in capabilities:
        errors.append("PROVIDER_CAPABILITY_MISSING")
    if not set(capabilities).issubset(set(REQUIRED_CAPABILITY_BY_INTEGRATION.values())):
        errors.append("PROVIDER_CAPABILITY_UNSUPPORTED")
    if payload.get("tenant_scope") != request.tenant:
        errors.append("TENANT_MISMATCH")
    if payload.get("policy_version_scope") != request.policy_version:
        errors.append("POLICY_VERSION_MISMATCH")
    if not _timeout_valid(payload.get("timeout_ms")) or payload.get("timeout_ms") != request.timeout_ms:
        errors.append("TIMEOUT_INVALID")
    if payload.get("receipt_schema") != PRODUCTION_INTEGRATION_RECEIPT_SCHEMA:
        errors.append("RECEIPT_SCHEMA_INVALID")
    guarantees = tuple(payload.get("supported_guarantees", ())) if isinstance(payload.get("supported_guarantees"), (list, tuple)) else ()
    if not set(guarantees).issubset(set(SUPPORTED_GUARANTEE_BY_INTEGRATION.get(request.integration_name, ()))) or not guarantees:
        errors.append("UNSUPPORTED_GUARANTEE")
    if any(payload.get(flag) is not False for flag in _EXECUTION_FLAGS):
        errors.append("FAILED_CLOSED")
    if _has_raw_marker(payload):
        errors.append("RAW_DATA_FORBIDDEN")
    return _ordered_unique(errors)


def build_unavailable_readiness_report(
    integration_name: str,
    *,
    required_dependencies: tuple[str, ...],
) -> IntegrationReadinessReport:
    if integration_name not in SUPPORTED_INTEGRATIONS:
        blocking = "INTEGRATION_UNKNOWN"
    else:
        blocking = UNAVAILABLE_STATUS_BY_INTEGRATION[integration_name]
    payload = {
        "schema": PRODUCTION_INTEGRATION_READINESS_SCHEMA,
        "integration_name": integration_name,
        "configured": False,
        "provider_capability_status": "UNAVAILABLE",
        "contract_version": PRODUCTION_INTEGRATION_CONTRACT_VERSION,
        "required_dependencies": list(required_dependencies),
        "blocking_failure_code": blocking,
        "production_ready": False,
        **_false_execution_flags(),
    }
    return IntegrationReadinessReport(
        integration_name=integration_name,
        configured=False,
        provider_capability_status="UNAVAILABLE",
        contract_version=PRODUCTION_INTEGRATION_CONTRACT_VERSION,
        required_dependencies=required_dependencies,
        blocking_failure_code=blocking,
        production_ready=False,
        readiness_hash=sha256_audit_hash(payload),
    )


def build_readiness_report(
    integration_name: str,
    *,
    capability: ProviderCapability | dict[str, Any] | None,
    request: ProductionIntegrationRequest,
    required_dependencies: tuple[str, ...],
) -> IntegrationReadinessReport:
    if capability is None:
        return build_unavailable_readiness_report(integration_name, required_dependencies=required_dependencies)
    errors = validate_provider_capability(capability, request=request)
    status = "CONFIGURED" if not errors else "BLOCKED"
    blocking = "" if not errors else errors[0]
    payload = {
        "schema": PRODUCTION_INTEGRATION_READINESS_SCHEMA,
        "integration_name": integration_name,
        "configured": not errors,
        "provider_capability_status": status,
        "contract_version": PRODUCTION_INTEGRATION_CONTRACT_VERSION,
        "required_dependencies": list(required_dependencies),
        "blocking_failure_code": blocking,
        "production_ready": False,
        **_false_execution_flags(),
    }
    return IntegrationReadinessReport(
        integration_name=integration_name,
        configured=not errors,
        provider_capability_status=status,
        contract_version=PRODUCTION_INTEGRATION_CONTRACT_VERSION,
        required_dependencies=required_dependencies,
        blocking_failure_code=blocking,
        production_ready=False,
        readiness_hash=sha256_audit_hash(payload),
    )


def build_receipt(
    request: ProductionIntegrationRequest,
    *,
    provider_identifier: str,
    receipt_status: str,
    failure_code: str,
    provider_receipt_hash: str,
) -> ProductionIntegrationReceipt:
    payload = {
        "schema": PRODUCTION_INTEGRATION_RECEIPT_SCHEMA,
        "integration_name": request.integration_name,
        "provider_identifier": provider_identifier,
        "tenant": request.tenant,
        "policy_version": request.policy_version,
        "correlation_id": request.correlation_id,
        "evidence_references": list(request.evidence_references),
        "receipt_status": receipt_status,
        "failure_code": failure_code,
        "provider_receipt_hash": provider_receipt_hash,
        "timeout_ms": request.timeout_ms,
        **_false_execution_flags(),
    }
    receipt = ProductionIntegrationReceipt(
        integration_name=request.integration_name,
        provider_identifier=provider_identifier,
        tenant=request.tenant,
        policy_version=request.policy_version,
        correlation_id=request.correlation_id,
        evidence_references=request.evidence_references,
        receipt_status=receipt_status,
        failure_code=failure_code,
        provider_receipt_hash=provider_receipt_hash,
        timeout_ms=request.timeout_ms,
        receipt_hash=sha256_audit_hash(payload),
    )
    errors = verify_receipt(receipt.to_dict(), request=request)
    if errors:
        raise ValueError(errors[0])
    return receipt


def verify_receipt(
    receipt: ProductionIntegrationReceipt | dict[str, Any],
    *,
    request: ProductionIntegrationRequest,
    existing_receipts: tuple[dict[str, Any], ...] | list[dict[str, Any]] = (),
) -> tuple[str, ...]:
    payload = receipt.to_dict() if isinstance(receipt, ProductionIntegrationReceipt) else dict(receipt)
    errors = list(validate_integration_request(request))
    if payload.get("schema") != PRODUCTION_INTEGRATION_RECEIPT_SCHEMA:
        errors.append("RECEIPT_SCHEMA_INVALID")
    for field, expected, code in (
        ("integration_name", request.integration_name, "INTEGRATION_UNKNOWN"),
        ("tenant", request.tenant, "TENANT_MISMATCH"),
        ("policy_version", request.policy_version, "POLICY_VERSION_MISMATCH"),
        ("correlation_id", request.correlation_id, "EVIDENCE_REFERENCE_MISSING"),
        ("timeout_ms", request.timeout_ms, "TIMEOUT_INVALID"),
    ):
        if payload.get(field) != expected:
            errors.append(code)
    if tuple(payload.get("evidence_references", ())) != request.evidence_references:
        errors.append("EVIDENCE_REFERENCE_MISSING")
    if not str(payload.get("provider_identifier", "")).strip():
        errors.append("PROVIDER_IDENTIFIER_MISSING")
    if payload.get("receipt_status") not in RECEIPT_STATUS_VALUES:
        errors.append("FAKE_SUCCESS_REJECTED")
    if payload.get("receipt_status") == "RECEIPT_VERIFIED" and not payload.get("failure_code"):
        errors.append("FAKE_SUCCESS_REJECTED")
    if payload.get("failure_code") in ("", None):
        errors.append("FAILED_CLOSED")
    if not _is_sha256_reference(payload.get("provider_receipt_hash")):
        errors.append("RECEIPT_SCHEMA_INVALID")
    if any(payload.get(flag) is not False for flag in _EXECUTION_FLAGS):
        errors.append("FAILED_CLOSED")
    if _has_raw_marker(payload):
        errors.append("RAW_DATA_FORBIDDEN")
    expected_hash = sha256_audit_hash({key: value for key, value in payload.items() if key != "receipt_hash"})
    if payload.get("receipt_hash") != expected_hash:
        errors.append("RECEIPT_SCHEMA_INVALID")
    seen: set[str] = set()
    for existing in existing_receipts:
        if not isinstance(existing, dict):
            errors.append("RECEIPT_SCHEMA_INVALID")
            continue
        receipt_hash = str(existing.get("receipt_hash", ""))
        if receipt_hash in seen or receipt_hash == payload.get("receipt_hash"):
            errors.append("DUPLICATE_RECEIPT")
        seen.add(receipt_hash)
    return _ordered_unique(errors)


def serialize_contract_result(payload: Any) -> str:
    if hasattr(payload, "to_dict"):
        payload = payload.to_dict()
    if _has_raw_marker(payload):
        raise ValueError("RAW_DATA_FORBIDDEN")
    return canonical_audit_json(payload)


def _false_execution_flags() -> dict[str, bool]:
    return {**fail_closed_execution_flags(), **{flag: False for flag in _EXECUTION_FLAGS}}


def _ordered_unique(errors: list[str]) -> tuple[str, ...]:
    return tuple(code for code in CONTRACT_FAILURE_CODES if code in errors)


def _timeout_valid(value: Any) -> bool:
    return isinstance(value, int) and 0 < value <= 300_000


def _evidence_references_valid(value: Any) -> bool:
    return isinstance(value, (tuple, list)) and bool(value) and all(_is_sha256_reference(item) for item in value)


def _is_sha256_reference(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def _has_raw_marker(payload: Any) -> bool:
    rendered = canonical_audit_json(payload).lower()
    return any(marker in rendered for marker in _RAW_MARKERS)
