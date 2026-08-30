from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from governance.audit_evidence import canonical_audit_json, sha256_audit_hash
from governance.production_integration_contracts import (
    PRODUCTION_INTEGRATION_CONTRACT_VERSION,
    PRODUCTION_INTEGRATION_RECEIPT_SCHEMA,
    REQUIRED_CAPABILITY_BY_INTEGRATION,
    SUPPORTED_GUARANTEE_BY_INTEGRATION,
    SUPPORTED_INTEGRATIONS,
    ProviderCapability,
    ProductionIntegrationRequest,
    validate_provider_capability,
)


PRODUCTION_PROVIDER_REGISTRY_SCHEMA = "usbay.governance.production_provider_registry.v1"
PRODUCTION_PROVIDER_REGISTRY_RECORD_SCHEMA = PRODUCTION_PROVIDER_REGISTRY_SCHEMA + ".record"
PRODUCTION_PROVIDER_READINESS_SCHEMA = PRODUCTION_PROVIDER_REGISTRY_SCHEMA + ".readiness"
PRODUCTION_PROVIDER_HEALTH_SCHEMA = PRODUCTION_PROVIDER_REGISTRY_SCHEMA + ".health_observation"
PRODUCTION_PROVIDER_APPROVAL_SCHEMA = PRODUCTION_PROVIDER_REGISTRY_SCHEMA + ".approval_reference"
PRODUCTION_PROVIDER_REGISTRY_VERSION = "production-provider-registry-v1"
PROVIDER_LIFECYCLE_STATES = (
    "UNREGISTERED",
    "REGISTERED",
    "CONFIGURATION_INVALID",
    "DISABLED",
    "UNAVAILABLE",
    "CAPABILITY_MISMATCH",
    "TENANT_SCOPE_MISMATCH",
    "POLICY_SCOPE_MISMATCH",
    "HEALTH_UNKNOWN",
    "HEALTHY",
    "DEGRADED",
    "BLOCKED",
    "READY_FOR_CONTROLLED_ACTIVATION",
)
PROVIDER_FAILURE_CODES = (
    "PROVIDER_UNREGISTERED",
    "PROVIDER_ID_INVALID",
    "INTEGRATION_TYPE_INVALID",
    "ADAPTER_VERSION_INVALID",
    "CONTRACT_VERSION_INCOMPATIBLE",
    "CAPABILITY_MISMATCH",
    "TENANT_SCOPE_MISMATCH",
    "POLICY_SCOPE_MISMATCH",
    "TIMEOUT_INVALID",
    "RETRY_POLICY_INVALID",
    "RECEIPT_SCHEMA_INVALID",
    "DUPLICATE_REGISTRATION",
    "CONFLICTING_REGISTRATION",
    "PROVIDER_DISABLED",
    "AMBIGUOUS_PROVIDER",
    "HEALTH_OBSERVATION_MISSING",
    "HEALTH_OBSERVATION_INVALID",
    "HEALTH_EXPIRED",
    "HEALTH_DEGRADED",
    "HUMAN_APPROVAL_MISSING",
    "HUMAN_APPROVAL_EXPIRED",
    "HUMAN_APPROVAL_SCOPE_MISMATCH",
    "RAW_DATA_FORBIDDEN",
    "FAILED_CLOSED",
)
HEALTH_STATES = ("HEALTHY", "DEGRADED", "BLOCKED", "UNKNOWN")
READINESS_STATES = ("REGISTERED", "BLOCKED", "READY_FOR_CONTROLLED_ACTIVATION")
_RAW_MARKERS = (
    "raw_payload",
    "raw_config",
    "raw_configuration",
    "raw_approval",
    "approval_content",
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


@dataclass(frozen=True)
class ProviderRegistration:
    provider_id: str
    integration_type: str
    adapter_version: str
    contract_version: str
    supported_capabilities: tuple[str, ...]
    tenant_scope: str
    policy_version_scope: str
    configuration_hash: str
    enabled: bool
    health_state: str
    readiness_state: str
    failure_code: str
    timeout_ms: int
    retry_policy: dict[str, Any]
    receipt_schema: str
    supported_guarantees: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema": PRODUCTION_PROVIDER_REGISTRY_RECORD_SCHEMA,
            "provider_id": self.provider_id,
            "integration_type": self.integration_type,
            "adapter_version": self.adapter_version,
            "contract_version": self.contract_version,
            "supported_capabilities": list(self.supported_capabilities),
            "tenant_scope": self.tenant_scope,
            "policy_version_scope": self.policy_version_scope,
            "configuration_hash": self.configuration_hash,
            "enabled": self.enabled,
            "health_state": self.health_state,
            "readiness_state": self.readiness_state,
            "failure_code": self.failure_code,
            "timeout_ms": self.timeout_ms,
            "retry_policy": dict(self.retry_policy),
            "receipt_schema": self.receipt_schema,
            "supported_guarantees": list(self.supported_guarantees),
            **_false_execution_flags(),
        }
        return {**payload, "registry_record_hash": sha256_audit_hash(payload)}


@dataclass(frozen=True)
class HealthObservation:
    provider_id: str
    integration_type: str
    observed_at: str
    expires_at: str
    status: str
    observation_hash: str
    source_reference: str
    tenant: str
    policy_version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PRODUCTION_PROVIDER_HEALTH_SCHEMA,
            "provider_id": self.provider_id,
            "integration_type": self.integration_type,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "status": self.status,
            "observation_hash": self.observation_hash,
            "source_reference": self.source_reference,
            "tenant": self.tenant,
            "policy_version": self.policy_version,
            **_false_execution_flags(),
        }


@dataclass(frozen=True)
class HumanApprovalReference:
    approval_reference_hash: str
    provider_id: str
    integration_type: str
    tenant: str
    policy_version: str
    approved_at: str
    expires_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PRODUCTION_PROVIDER_APPROVAL_SCHEMA,
            "approval_reference_hash": self.approval_reference_hash,
            "provider_id": self.provider_id,
            "integration_type": self.integration_type,
            "tenant": self.tenant,
            "policy_version": self.policy_version,
            "approved_at": self.approved_at,
            "expires_at": self.expires_at,
            **_false_execution_flags(),
        }


@dataclass(frozen=True)
class ProviderSelectionResult:
    result: str
    failure_code: str
    provider_record: dict[str, Any] | None
    selection_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "failure_code": self.failure_code,
            "provider_record_hash": self.provider_record.get("registry_record_hash", "") if self.provider_record else "",
            "selection_hash": self.selection_hash,
            **_false_execution_flags(),
        }


@dataclass(frozen=True)
class ActivationAssessment:
    result: str
    failure_code: str
    registry_record_hash: str
    configuration_hash: str
    capability_hash: str
    health_observation_hash: str
    approval_reference_hash: str
    readiness_report_hash: str
    correlation_id: str
    tenant: str
    policy_version: str
    provider_id: str
    integration_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PRODUCTION_PROVIDER_READINESS_SCHEMA,
            "result": self.result,
            "failure_code": self.failure_code,
            "registry_record_hash": self.registry_record_hash,
            "configuration_hash": self.configuration_hash,
            "capability_hash": self.capability_hash,
            "health_observation_hash": self.health_observation_hash,
            "approval_reference_hash": self.approval_reference_hash,
            "readiness_report_hash": self.readiness_report_hash,
            "correlation_id": self.correlation_id,
            "tenant": self.tenant,
            "policy_version": self.policy_version,
            "provider_id": self.provider_id,
            "integration_type": self.integration_type,
            **_false_execution_flags(),
        }


def production_provider_registry_schema() -> dict[str, Any]:
    return {
        "schema": PRODUCTION_PROVIDER_REGISTRY_SCHEMA,
        "record_schema": PRODUCTION_PROVIDER_REGISTRY_RECORD_SCHEMA,
        "readiness_schema": PRODUCTION_PROVIDER_READINESS_SCHEMA,
        "health_schema": PRODUCTION_PROVIDER_HEALTH_SCHEMA,
        "approval_reference_schema": PRODUCTION_PROVIDER_APPROVAL_SCHEMA,
        "version": PRODUCTION_PROVIDER_REGISTRY_VERSION,
        "states": list(PROVIDER_LIFECYCLE_STATES),
        "failure_codes": list(PROVIDER_FAILURE_CODES),
        "supported_integrations": list(SUPPORTED_INTEGRATIONS),
        "payload_policy": "hash-only",
        **_false_execution_flags(),
    }


def validate_provider_registration(record: ProviderRegistration | dict[str, Any]) -> tuple[str, ...]:
    payload = record.to_dict() if isinstance(record, ProviderRegistration) else dict(record)
    errors: list[str] = []
    if payload.get("schema") != PRODUCTION_PROVIDER_REGISTRY_RECORD_SCHEMA:
        errors.append("PROVIDER_ID_INVALID")
    if not _provider_id_valid(payload.get("provider_id")):
        errors.append("PROVIDER_ID_INVALID")
    integration = str(payload.get("integration_type", ""))
    if integration not in SUPPORTED_INTEGRATIONS:
        errors.append("INTEGRATION_TYPE_INVALID")
    if not str(payload.get("adapter_version", "")).strip():
        errors.append("ADAPTER_VERSION_INVALID")
    if payload.get("contract_version") != PRODUCTION_INTEGRATION_CONTRACT_VERSION:
        errors.append("CONTRACT_VERSION_INCOMPATIBLE")
    if not _is_sha256_reference(payload.get("configuration_hash")):
        errors.append("PROVIDER_ID_INVALID")
    capability_errors = validate_provider_capability(_capability_from_record(payload), request=_request_from_record(payload))
    errors.extend(_map_capability_error(error) for error in capability_errors)
    if payload.get("enabled") is not True:
        errors.append("PROVIDER_DISABLED")
    if payload.get("health_state") not in HEALTH_STATES:
        errors.append("HEALTH_OBSERVATION_INVALID")
    if payload.get("readiness_state") not in READINESS_STATES:
        errors.append("FAILED_CLOSED")
    if payload.get("failure_code") not in ("", None) and payload.get("failure_code") not in PROVIDER_FAILURE_CODES:
        errors.append("FAILED_CLOSED")
    if not _retry_policy_valid(payload.get("retry_policy")):
        errors.append("RETRY_POLICY_INVALID")
    if any(payload.get(flag) is not False for flag in _EXECUTION_FLAGS):
        errors.append("FAILED_CLOSED")
    if _has_raw_marker(payload):
        errors.append("RAW_DATA_FORBIDDEN")
    expected_hash = sha256_audit_hash({key: value for key, value in payload.items() if key != "registry_record_hash"})
    if payload.get("registry_record_hash") != expected_hash:
        errors.append("FAILED_CLOSED")
    return _ordered_unique(errors)


def register_provider(
    existing_records: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    registration: ProviderRegistration,
) -> tuple[str, tuple[dict[str, Any], ...], tuple[str, ...]]:
    records = tuple(dict(record) for record in existing_records)
    record = registration.to_dict()
    errors = validate_provider_registration(record)
    if errors:
        return "CONFIGURATION_INVALID", records, errors
    for existing in records:
        if existing.get("provider_id") == record["provider_id"] and existing.get("integration_type") == record["integration_type"]:
            if _logical_registration(existing) == _logical_registration(record):
                return "REGISTERED", records, ("DUPLICATE_REGISTRATION",)
            return "CONFIGURATION_INVALID", records, ("CONFLICTING_REGISTRATION",)
    return "REGISTERED", (*records, record), ()


def select_provider(
    records: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    *,
    integration_type: str,
    provider_id: str | None,
    tenant: str,
    policy_version: str,
    required_capabilities: tuple[str, ...],
    contract_version: str,
) -> ProviderSelectionResult:
    errors: list[str] = []
    candidates = [
        dict(record)
        for record in records
        if record.get("integration_type") == integration_type and (provider_id is None or record.get("provider_id") == provider_id)
    ]
    if integration_type not in SUPPORTED_INTEGRATIONS:
        errors.append("INTEGRATION_TYPE_INVALID")
    if not candidates:
        errors.append("PROVIDER_UNREGISTERED")
    if len(candidates) > 1 and provider_id is None:
        errors.append("AMBIGUOUS_PROVIDER")
    selected = candidates[0] if len(candidates) == 1 else None
    if selected:
        if selected.get("enabled") is not True:
            errors.append("PROVIDER_DISABLED")
        if selected.get("tenant_scope") != tenant:
            errors.append("TENANT_SCOPE_MISMATCH")
        if selected.get("policy_version_scope") != policy_version:
            errors.append("POLICY_SCOPE_MISMATCH")
        if selected.get("contract_version") != contract_version:
            errors.append("CONTRACT_VERSION_INCOMPATIBLE")
        if not set(required_capabilities).issubset(set(selected.get("supported_capabilities", ()))):
            errors.append("CAPABILITY_MISMATCH")
        if selected.get("health_state") == "UNKNOWN":
            errors.append("HEALTH_OBSERVATION_MISSING")
        elif selected.get("health_state") == "DEGRADED":
            errors.append("HEALTH_DEGRADED")
        elif selected.get("health_state") != "HEALTHY":
            errors.append("HEALTH_OBSERVATION_INVALID")
        errors.extend(validate_provider_registration(selected))
    failure = _ordered_unique(errors)
    result = "REGISTERED" if not failure else "BLOCKED"
    payload = {
        "result": result,
        "failure_code": "" if not failure else failure[0],
        "provider_record_hash": selected.get("registry_record_hash", "") if selected else "",
        "integration_type": integration_type,
        "provider_id": provider_id or "",
        "tenant": tenant,
        "policy_version": policy_version,
        "required_capabilities": list(required_capabilities),
        "contract_version": contract_version,
        **_false_execution_flags(),
    }
    return ProviderSelectionResult(result, payload["failure_code"], selected, sha256_audit_hash(payload))


def verify_health_observation(observation: HealthObservation | dict[str, Any], *, provider_record: dict[str, Any], checked_at: str) -> tuple[str, ...]:
    payload = observation.to_dict() if isinstance(observation, HealthObservation) else dict(observation)
    errors: list[str] = []
    if payload.get("schema") != PRODUCTION_PROVIDER_HEALTH_SCHEMA:
        errors.append("HEALTH_OBSERVATION_INVALID")
    expected_fields = {
        "provider_id": "provider_id",
        "integration_type": "integration_type",
        "tenant": "tenant_scope",
        "policy_version": "policy_version_scope",
    }
    for field, record_field in expected_fields.items():
        if payload.get(field) != provider_record.get(record_field):
            errors.append("HEALTH_OBSERVATION_INVALID" if field in {"provider_id", "integration_type"} else _scope_error(field))
    if payload.get("status") != "HEALTHY":
        errors.append("HEALTH_DEGRADED" if payload.get("status") == "DEGRADED" else "HEALTH_OBSERVATION_INVALID")
    if not _timestamp_order_valid(str(payload.get("observed_at", "")), str(payload.get("expires_at", ""))):
        errors.append("HEALTH_OBSERVATION_INVALID")
    if str(payload.get("expires_at", "")) <= checked_at:
        errors.append("HEALTH_EXPIRED")
    if not _is_sha256_reference(payload.get("observation_hash")) or not _is_sha256_reference(payload.get("source_reference")):
        errors.append("HEALTH_OBSERVATION_INVALID")
    if any(payload.get(flag) is not False for flag in _EXECUTION_FLAGS):
        errors.append("FAILED_CLOSED")
    if _has_raw_marker(payload):
        errors.append("RAW_DATA_FORBIDDEN")
    return _ordered_unique(errors)


def assess_controlled_activation(
    provider_record: dict[str, Any] | None,
    *,
    request: ProductionIntegrationRequest,
    health_observation: HealthObservation | dict[str, Any] | None,
    approval: HumanApprovalReference | dict[str, Any] | None,
    checked_at: str,
) -> ActivationAssessment:
    errors: list[str] = []
    record = provider_record or {}
    if not provider_record:
        errors.append("PROVIDER_UNREGISTERED")
    else:
        errors.extend(validate_provider_registration(record))
    if health_observation is None:
        errors.append("HEALTH_OBSERVATION_MISSING")
        health_hash = ""
    else:
        errors.extend(verify_health_observation(health_observation, provider_record=record, checked_at=checked_at))
        health_payload = health_observation.to_dict() if isinstance(health_observation, HealthObservation) else dict(health_observation)
        health_hash = str(health_payload.get("observation_hash", ""))
    approval_hash = ""
    if approval is None:
        errors.append("HUMAN_APPROVAL_MISSING")
    else:
        approval_payload = approval.to_dict() if isinstance(approval, HumanApprovalReference) else dict(approval)
        approval_hash = str(approval_payload.get("approval_reference_hash", ""))
        errors.extend(_approval_errors(approval_payload, record, checked_at))
    selection = select_provider(
        (record,) if record else (),
        integration_type=request.integration_name,
        provider_id=request.provider_identifier,
        tenant=request.tenant,
        policy_version=request.policy_version,
        required_capabilities=(REQUIRED_CAPABILITY_BY_INTEGRATION.get(request.integration_name, ""),),
        contract_version=PRODUCTION_INTEGRATION_CONTRACT_VERSION,
    )
    if selection.failure_code:
        errors.append(selection.failure_code)
    failure = _ordered_unique(errors)
    result = "READY_FOR_CONTROLLED_ACTIVATION" if not failure else "BLOCKED"
    payload = {
        "schema": PRODUCTION_PROVIDER_READINESS_SCHEMA,
        "result": result,
        "failure_code": "" if not failure else failure[0],
        "registry_record_hash": str(record.get("registry_record_hash", "")),
        "configuration_hash": str(record.get("configuration_hash", "")),
        "capability_hash": sha256_audit_hash(record.get("supported_capabilities", [])) if record else "",
        "health_observation_hash": health_hash,
        "approval_reference_hash": approval_hash,
        "correlation_id": request.correlation_id,
        "tenant": request.tenant,
        "policy_version": request.policy_version,
        "provider_id": request.provider_identifier,
        "integration_type": request.integration_name,
        **_false_execution_flags(),
    }
    report_hash = sha256_audit_hash(payload)
    return ActivationAssessment(
        result=result,
        failure_code=payload["failure_code"],
        registry_record_hash=payload["registry_record_hash"],
        configuration_hash=payload["configuration_hash"],
        capability_hash=payload["capability_hash"],
        health_observation_hash=payload["health_observation_hash"],
        approval_reference_hash=payload["approval_reference_hash"],
        readiness_report_hash=report_hash,
        correlation_id=request.correlation_id,
        tenant=request.tenant,
        policy_version=request.policy_version,
        provider_id=request.provider_identifier,
        integration_type=request.integration_name,
    )


def serialize_provider_registry_result(payload: Any) -> str:
    if hasattr(payload, "to_dict"):
        payload = payload.to_dict()
    if _has_raw_marker(payload):
        raise ValueError("RAW_DATA_FORBIDDEN")
    return canonical_audit_json(payload)


def _capability_from_record(record: dict[str, Any]) -> ProviderCapability:
    return ProviderCapability(
        integration_name=str(record.get("integration_type", "")),
        provider_identifier=str(record.get("provider_id", "")),
        tenant_scope=str(record.get("tenant_scope", "")),
        policy_version_scope=str(record.get("policy_version_scope", "")),
        capabilities=tuple(record.get("supported_capabilities", ())) if isinstance(record.get("supported_capabilities"), (list, tuple)) else (),
        supported_guarantees=tuple(record.get("supported_guarantees", ())) if isinstance(record.get("supported_guarantees"), (list, tuple)) else (),
        receipt_schema=str(record.get("receipt_schema", "")),
        timeout_ms=int(record.get("timeout_ms", 0)) if isinstance(record.get("timeout_ms"), int) else 0,
    )


def _request_from_record(record: dict[str, Any]) -> ProductionIntegrationRequest:
    return ProductionIntegrationRequest(
        integration_name=str(record.get("integration_type", "")),
        tenant=str(record.get("tenant_scope", "")),
        policy_version=str(record.get("policy_version_scope", "")),
        correlation_id="sha256:" + ("1" * 64),
        evidence_references=("sha256:" + ("2" * 64),),
        timeout_ms=int(record.get("timeout_ms", 0)) if isinstance(record.get("timeout_ms"), int) else 0,
        provider_identifier=str(record.get("provider_id", "")),
    )


def _map_capability_error(error: str) -> str:
    return {
        "INTEGRATION_UNKNOWN": "INTEGRATION_TYPE_INVALID",
        "PROVIDER_IDENTIFIER_MISSING": "PROVIDER_ID_INVALID",
        "PROVIDER_CAPABILITY_MISSING": "CAPABILITY_MISMATCH",
        "PROVIDER_CAPABILITY_UNSUPPORTED": "CAPABILITY_MISMATCH",
        "TENANT_MISMATCH": "TENANT_SCOPE_MISMATCH",
        "POLICY_VERSION_MISMATCH": "POLICY_SCOPE_MISMATCH",
        "TIMEOUT_INVALID": "TIMEOUT_INVALID",
        "RECEIPT_SCHEMA_INVALID": "RECEIPT_SCHEMA_INVALID",
        "UNSUPPORTED_GUARANTEE": "CAPABILITY_MISMATCH",
        "RAW_DATA_FORBIDDEN": "RAW_DATA_FORBIDDEN",
        "FAILED_CLOSED": "FAILED_CLOSED",
    }.get(error, "FAILED_CLOSED")


def _approval_errors(payload: dict[str, Any], provider_record: dict[str, Any], checked_at: str) -> list[str]:
    errors: list[str] = []
    if payload.get("schema") != PRODUCTION_PROVIDER_APPROVAL_SCHEMA or not _is_sha256_reference(payload.get("approval_reference_hash")):
        errors.append("HUMAN_APPROVAL_MISSING")
    expected_fields = {
        "provider_id": "provider_id",
        "integration_type": "integration_type",
        "tenant": "tenant_scope",
        "policy_version": "policy_version_scope",
    }
    for field, record_field in expected_fields.items():
        if payload.get(field) != provider_record.get(record_field):
            errors.append("HUMAN_APPROVAL_SCOPE_MISMATCH")
    if not _timestamp_order_valid(str(payload.get("approved_at", "")), str(payload.get("expires_at", ""))):
        errors.append("HUMAN_APPROVAL_EXPIRED")
    if str(payload.get("expires_at", "")) <= checked_at:
        errors.append("HUMAN_APPROVAL_EXPIRED")
    if any(payload.get(flag) is not False for flag in _EXECUTION_FLAGS):
        errors.append("FAILED_CLOSED")
    if _has_raw_marker(payload):
        errors.append("RAW_DATA_FORBIDDEN")
    return errors


def _scope_error(field: str) -> str:
    return "TENANT_SCOPE_MISMATCH" if field == "tenant" else "POLICY_SCOPE_MISMATCH"


def _logical_registration(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "registry_record_hash"}


def _provider_id_valid(value: Any) -> bool:
    if not isinstance(value, str) or not (3 <= len(value) <= 80):
        return False
    return all(char.islower() or char.isdigit() or char in "-_." for char in value)


def _retry_policy_valid(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("max_attempts"), int)
        and 0 <= value["max_attempts"] <= 3
        and isinstance(value.get("backoff_ms"), int)
        and 0 <= value["backoff_ms"] <= 60_000
    )


def _timestamp_order_valid(start: str, end: str) -> bool:
    return bool(start and end and start < end and start.endswith("Z") and end.endswith("Z"))


def _ordered_unique(errors: list[str]) -> tuple[str, ...]:
    return tuple(code for code in PROVIDER_FAILURE_CODES if code in errors)


def _false_execution_flags() -> dict[str, bool]:
    return {flag: False for flag in _EXECUTION_FLAGS}


def _is_sha256_reference(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def _has_raw_marker(payload: Any) -> bool:
    rendered = canonical_audit_json(payload).lower()
    return any(marker in rendered for marker in _RAW_MARKERS)
