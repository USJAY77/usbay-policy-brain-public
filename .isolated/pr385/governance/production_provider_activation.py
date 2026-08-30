from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from governance.audit_evidence import ZERO_AUDIT_CHAIN_HASH, canonical_audit_json, sha256_audit_hash
from governance.production_integration_contracts import (
    PRODUCTION_INTEGRATION_CONTRACT_VERSION,
    PRODUCTION_INTEGRATION_RECEIPT_SCHEMA,
    REQUIRED_CAPABILITY_BY_INTEGRATION,
    SUPPORTED_INTEGRATIONS,
    validate_integration_request,
)
from governance.production_provider_registry import (
    PRODUCTION_PROVIDER_APPROVAL_SCHEMA,
    PRODUCTION_PROVIDER_REGISTRY_RECORD_SCHEMA,
    PRODUCTION_PROVIDER_REGISTRY_VERSION,
    PRODUCTION_PROVIDER_READINESS_SCHEMA,
    ActivationAssessment,
    HumanApprovalReference,
    ProviderRegistration,
    assess_controlled_activation,
    validate_provider_registration,
    verify_health_observation,
)


PRODUCTION_PROVIDER_ACTIVATION_SCHEMA = "usbay.governance.production_provider_activation.v1"
PRODUCTION_PROVIDER_ACTIVATION_REQUEST_SCHEMA = PRODUCTION_PROVIDER_ACTIVATION_SCHEMA + ".request"
PRODUCTION_PROVIDER_ACTIVATION_RECEIPT_SCHEMA = PRODUCTION_PROVIDER_ACTIVATION_SCHEMA + ".simulated_receipt"
PRODUCTION_PROVIDER_ACTIVATION_PACKAGE_SCHEMA = PRODUCTION_PROVIDER_ACTIVATION_SCHEMA + ".production_decision_package"
PRODUCTION_PROVIDER_ACTIVATION_VERSION = "production-provider-activation-v1"

ACTIVATION_DECISION_STATES = (
    "ACTIVATION_REQUEST_INVALID",
    "ACTIVATION_APPROVAL_REQUIRED",
    "ACTIVATION_APPROVAL_EXPIRED",
    "ACTIVATION_SCOPE_MISMATCH",
    "ACTIVATION_HEALTH_INVALID",
    "ACTIVATION_PROVIDER_NOT_READY",
    "ACTIVATION_CONTRACT_INCOMPATIBLE",
    "ACTIVATION_DUPLICATE",
    "ACTIVATION_REPLAY_BLOCKED",
    "ACTIVATION_BLOCKED",
    "ACTIVATION_ELIGIBLE_FOR_OFFLINE_SIMULATION",
    "ACTIVATION_SIMULATION_PASSED",
    "ACTIVATION_SIMULATION_FAILED",
    "READY_FOR_HUMAN_PRODUCTION_DECISION",
)
PROHIBITED_ACTIVATION_STATES = ("ACTIVE", "ENABLED", "EXECUTING", "LIVE", "PRODUCTION_ACTIVE")
ACTIVATION_FAILURE_CODES = (
    "ACTIVATION_REQUEST_MISSING",
    "ACTIVATION_REQUEST_MALFORMED",
    "ACTIVATION_REQUEST_EXPIRED",
    "ACTIVATION_DUPLICATE",
    "ACTIVATION_CONFLICTING_REQUEST",
    "ACTIVATION_SCOPE_MISMATCH",
    "ACTIVATION_APPROVAL_REQUIRED",
    "ACTIVATION_APPROVAL_EXPIRED",
    "ACTIVATION_APPROVAL_REPLAYED",
    "ACTIVATION_APPROVAL_CONSUMED",
    "ACTIVATION_PROVIDER_NOT_READY",
    "ACTIVATION_HEALTH_INVALID",
    "ACTIVATION_CONTRACT_INCOMPATIBLE",
    "ACTIVATION_RECEIPT_SCHEMA_INVALID",
    "ACTIVATION_RECEIPT_DUPLICATE",
    "ACTIVATION_RECEIPT_REPLAYED",
    "ACTIVATION_RECEIPT_REORDERED",
    "ACTIVATION_RECEIPT_TAMPERED",
    "ACTIVATION_RAW_DATA_FORBIDDEN",
    "ACTIVATION_FAILED_CLOSED",
)
_EXECUTION_FLAGS = (
    "execution_allowed",
    "provider_execution",
    "production_activation",
    "runtime_execution",
    "deployment_execution",
    "policy_mutation",
    "network_access",
    "credentials_access",
    "live_provider_call",
)
_RAW_MARKERS = (
    "raw_payload",
    "raw_secret",
    "raw_approval",
    "approval_content",
    "provider_response",
    "private_key",
    "credential",
    "credentials",
    "secret",
    "access_token",
    "certificate_body",
    "prompt",
)


@dataclass(frozen=True)
class ActivationRequest:
    activation_request_id: str
    provider_id: str
    integration_type: str
    tenant: str
    policy_version: str
    contract_version: str
    registry_record_hash: str
    configuration_hash: str
    capability_hash: str
    health_observation_hash: str
    approval_reference_hash: str
    requested_at: str
    expires_at: str
    correlation_id: str
    requested_by_reference: str
    reason_code: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PRODUCTION_PROVIDER_ACTIVATION_REQUEST_SCHEMA,
            "activation_request_id": self.activation_request_id,
            "provider_id": self.provider_id,
            "integration_type": self.integration_type,
            "tenant": self.tenant,
            "policy_version": self.policy_version,
            "contract_version": self.contract_version,
            "registry_record_hash": self.registry_record_hash,
            "configuration_hash": self.configuration_hash,
            "capability_hash": self.capability_hash,
            "health_observation_hash": self.health_observation_hash,
            "approval_reference_hash": self.approval_reference_hash,
            "requested_at": self.requested_at,
            "expires_at": self.expires_at,
            "correlation_id": self.correlation_id,
            "requested_by_reference": self.requested_by_reference,
            "reason_code": self.reason_code,
            **_false_execution_flags(),
        }


@dataclass(frozen=True)
class ApprovalBinding:
    result: str
    failure_code: str
    approval_reference_hash: str
    activation_request_id: str
    binding_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "failure_code": self.failure_code,
            "approval_reference_hash": self.approval_reference_hash,
            "activation_request_id": self.activation_request_id,
            "binding_hash": self.binding_hash,
            **_false_execution_flags(),
        }


@dataclass(frozen=True)
class OfflineSimulationDecision:
    result: str
    failure_code: str
    simulation_id: str
    activation_request_id: str
    provider_id: str
    integration_type: str
    tenant: str
    policy_version: str
    readiness_report_hash: str
    simulation_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PRODUCTION_PROVIDER_ACTIVATION_SCHEMA + ".simulation",
            "result": self.result,
            "failure_code": self.failure_code,
            "simulation_id": self.simulation_id,
            "activation_request_id": self.activation_request_id,
            "provider_id": self.provider_id,
            "integration_type": self.integration_type,
            "tenant": self.tenant,
            "policy_version": self.policy_version,
            "readiness_report_hash": self.readiness_report_hash,
            "simulation_hash": self.simulation_hash,
            **_false_execution_flags(),
        }


@dataclass(frozen=True)
class SimulatedReceiptEnvelope:
    simulated_receipt_id: str
    simulation_id: str
    activation_request_id: str
    provider_id: str
    integration_type: str
    tenant: str
    policy_version: str
    contract_version: str
    registry_record_hash: str
    readiness_report_hash: str
    approval_reference_hash: str
    simulated_result: str
    failure_code: str
    issued_at: str
    expires_at: str
    correlation_id: str
    receipt_hash: str
    previous_receipt_hash: str
    simulation_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PRODUCTION_PROVIDER_ACTIVATION_RECEIPT_SCHEMA,
            "simulated_receipt_id": self.simulated_receipt_id,
            "simulation_id": self.simulation_id,
            "activation_request_id": self.activation_request_id,
            "provider_id": self.provider_id,
            "integration_type": self.integration_type,
            "tenant": self.tenant,
            "policy_version": self.policy_version,
            "contract_version": self.contract_version,
            "registry_record_hash": self.registry_record_hash,
            "readiness_report_hash": self.readiness_report_hash,
            "approval_reference_hash": self.approval_reference_hash,
            "simulated_result": self.simulated_result,
            "failure_code": self.failure_code,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "correlation_id": self.correlation_id,
            "receipt_hash": self.receipt_hash,
            "previous_receipt_hash": self.previous_receipt_hash,
            "simulation_only": self.simulation_only,
            **_false_execution_flags(),
        }


@dataclass(frozen=True)
class ReceiptChainVerification:
    valid: bool
    failure_code: str
    chain_hash: str
    receipt_count: int
    terminal_receipt_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "failure_code": self.failure_code,
            "chain_hash": self.chain_hash,
            "receipt_count": self.receipt_count,
            "terminal_receipt_hash": self.terminal_receipt_hash,
            **_false_execution_flags(),
        }


@dataclass(frozen=True)
class ProductionDecisionPackage:
    activation_request_reference: str
    provider_registry_reference: str
    readiness_evidence_reference: str
    health_observation_reference: str
    human_approval_reference: str
    simulation_receipt_reference: str
    simulation_chain_reference: str
    rollback_plan_reference: str
    unresolved_risks: tuple[str, ...]
    final_package_hash: str
    result: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PRODUCTION_PROVIDER_ACTIVATION_PACKAGE_SCHEMA,
            "activation_request_reference": self.activation_request_reference,
            "provider_registry_reference": self.provider_registry_reference,
            "readiness_evidence_reference": self.readiness_evidence_reference,
            "health_observation_reference": self.health_observation_reference,
            "human_approval_reference": self.human_approval_reference,
            "simulation_receipt_reference": self.simulation_receipt_reference,
            "simulation_chain_reference": self.simulation_chain_reference,
            "rollback_plan_reference": self.rollback_plan_reference,
            "unresolved_risks": list(self.unresolved_risks),
            "final_package_hash": self.final_package_hash,
            "result": self.result,
            **_false_execution_flags(),
        }


def production_provider_activation_schema() -> dict[str, Any]:
    return {
        "schema": PRODUCTION_PROVIDER_ACTIVATION_SCHEMA,
        "request_schema": PRODUCTION_PROVIDER_ACTIVATION_REQUEST_SCHEMA,
        "receipt_schema": PRODUCTION_PROVIDER_ACTIVATION_RECEIPT_SCHEMA,
        "package_schema": PRODUCTION_PROVIDER_ACTIVATION_PACKAGE_SCHEMA,
        "version": PRODUCTION_PROVIDER_ACTIVATION_VERSION,
        "supported_integrations": list(SUPPORTED_INTEGRATIONS),
        "decision_states": list(ACTIVATION_DECISION_STATES),
        "prohibited_states": list(PROHIBITED_ACTIVATION_STATES),
        "failure_codes": list(ACTIVATION_FAILURE_CODES),
        "payload_policy": "hash-only",
        "simulation_only": True,
        **_false_execution_flags(),
    }


def validate_activation_request(
    request: ActivationRequest | dict[str, Any] | None,
    *,
    provider_record: dict[str, Any],
    readiness_assessment: ActivationAssessment | dict[str, Any],
    checked_at: str,
    existing_requests: tuple[dict[str, Any], ...] | list[dict[str, Any]] = (),
) -> tuple[str, ...]:
    if request is None:
        return ("ACTIVATION_REQUEST_MISSING",)
    payload = request.to_dict() if isinstance(request, ActivationRequest) else dict(request)
    readiness = readiness_assessment.to_dict() if isinstance(readiness_assessment, ActivationAssessment) else dict(readiness_assessment)
    errors: list[str] = []
    if payload.get("schema") != PRODUCTION_PROVIDER_ACTIVATION_REQUEST_SCHEMA:
        errors.append("ACTIVATION_REQUEST_MALFORMED")
    if not _is_sha256_reference(payload.get("activation_request_id")):
        errors.append("ACTIVATION_REQUEST_MALFORMED")
    if payload.get("integration_type") not in SUPPORTED_INTEGRATIONS:
        errors.append("ACTIVATION_REQUEST_MALFORMED")
    if payload.get("contract_version") != PRODUCTION_INTEGRATION_CONTRACT_VERSION:
        errors.append("ACTIVATION_CONTRACT_INCOMPATIBLE")
    if payload.get("provider_id") != provider_record.get("provider_id"):
        errors.append("ACTIVATION_SCOPE_MISMATCH")
    for field, record_field in (
        ("integration_type", "integration_type"),
        ("tenant", "tenant_scope"),
        ("policy_version", "policy_version_scope"),
        ("registry_record_hash", "registry_record_hash"),
        ("configuration_hash", "configuration_hash"),
    ):
        if payload.get(field) != provider_record.get(record_field):
            errors.append("ACTIVATION_SCOPE_MISMATCH")
    for field in ("capability_hash", "health_observation_hash", "approval_reference_hash", "correlation_id"):
        if not _is_sha256_reference(payload.get(field)):
            errors.append("ACTIVATION_REQUEST_MALFORMED")
        if payload.get(field) != readiness.get(field):
            errors.append("ACTIVATION_SCOPE_MISMATCH")
    if payload.get("readiness_report_hash") is not None:
        errors.append("ACTIVATION_REQUEST_MALFORMED")
    if readiness.get("result") != "READY_FOR_CONTROLLED_ACTIVATION":
        errors.append("ACTIVATION_PROVIDER_NOT_READY")
    if readiness.get("registry_record_hash") != payload.get("registry_record_hash"):
        errors.append("ACTIVATION_SCOPE_MISMATCH")
    if not _timestamp_order_valid(str(payload.get("requested_at", "")), str(payload.get("expires_at", ""))):
        errors.append("ACTIVATION_REQUEST_MALFORMED")
    if str(payload.get("expires_at", "")) <= checked_at:
        errors.append("ACTIVATION_REQUEST_EXPIRED")
    if not _is_sha256_reference(payload.get("requested_by_reference")):
        errors.append("ACTIVATION_REQUEST_MALFORMED")
    if not _label_valid(payload.get("reason_code")):
        errors.append("ACTIVATION_REQUEST_MALFORMED")
    if any(payload.get(flag) is not False for flag in _EXECUTION_FLAGS):
        errors.append("ACTIVATION_FAILED_CLOSED")
    if _has_raw_marker(payload):
        errors.append("ACTIVATION_RAW_DATA_FORBIDDEN")
    for existing in existing_requests:
        if not isinstance(existing, dict):
            errors.append("ACTIVATION_REQUEST_MALFORMED")
            continue
        if existing.get("activation_request_id") == payload.get("activation_request_id"):
            if _logical_request(existing) == _logical_request(payload):
                errors.append("ACTIVATION_DUPLICATE")
            else:
                errors.append("ACTIVATION_CONFLICTING_REQUEST")
        elif existing.get("approval_reference_hash") == payload.get("approval_reference_hash"):
            errors.append("ACTIVATION_APPROVAL_REPLAYED")
    return _ordered_unique(errors)


def bind_human_approval(
    request: ActivationRequest | dict[str, Any],
    approval: HumanApprovalReference | dict[str, Any] | None,
    *,
    checked_at: str,
    consumed_approval_hashes: tuple[str, ...] | list[str] = (),
    replayed_approval_hashes: tuple[str, ...] | list[str] = (),
    approval_version: str = PRODUCTION_PROVIDER_REGISTRY_VERSION,
) -> ApprovalBinding:
    payload = request.to_dict() if isinstance(request, ActivationRequest) else dict(request)
    errors: list[str] = []
    approval_hash = ""
    if approval is None:
        errors.append("ACTIVATION_APPROVAL_REQUIRED")
    else:
        approval_payload = approval.to_dict() if isinstance(approval, HumanApprovalReference) else dict(approval)
        approval_hash = str(approval_payload.get("approval_reference_hash", ""))
        if approval_payload.get("schema") != PRODUCTION_PROVIDER_APPROVAL_SCHEMA or not _is_sha256_reference(approval_hash):
            errors.append("ACTIVATION_APPROVAL_REQUIRED")
        for field in ("provider_id", "integration_type", "tenant", "policy_version"):
            if approval_payload.get(field) != payload.get(field):
                errors.append("ACTIVATION_SCOPE_MISMATCH")
        if approval_hash != payload.get("approval_reference_hash"):
            errors.append("ACTIVATION_SCOPE_MISMATCH")
        if not _timestamp_order_valid(str(approval_payload.get("approved_at", "")), str(approval_payload.get("expires_at", ""))):
            errors.append("ACTIVATION_APPROVAL_EXPIRED")
        if str(approval_payload.get("expires_at", "")) <= checked_at:
            errors.append("ACTIVATION_APPROVAL_EXPIRED")
        if any(approval_payload.get(flag) is not False for flag in _registry_execution_flags()):
            errors.append("ACTIVATION_FAILED_CLOSED")
        if _has_raw_marker(approval_payload):
            errors.append("ACTIVATION_RAW_DATA_FORBIDDEN")
    if approval_hash in set(replayed_approval_hashes):
        errors.append("ACTIVATION_APPROVAL_REPLAYED")
    if approval_hash in set(consumed_approval_hashes):
        errors.append("ACTIVATION_APPROVAL_CONSUMED")
    if approval_version != PRODUCTION_PROVIDER_REGISTRY_VERSION:
        errors.append("ACTIVATION_CONTRACT_INCOMPATIBLE")
    failure = _ordered_unique(errors)
    result = "ACTIVATION_ELIGIBLE_FOR_OFFLINE_SIMULATION" if not failure else _state_for_failure(failure[0])
    body = {
        "result": result,
        "failure_code": "" if not failure else failure[0],
        "approval_reference_hash": approval_hash,
        "activation_request_id": payload.get("activation_request_id", ""),
        **_false_execution_flags(),
    }
    return ApprovalBinding(
        result=result,
        failure_code=body["failure_code"],
        approval_reference_hash=approval_hash,
        activation_request_id=str(payload.get("activation_request_id", "")),
        binding_hash=sha256_audit_hash(body),
    )


def run_offline_activation_simulation(
    request: ActivationRequest | dict[str, Any],
    *,
    provider_record: dict[str, Any],
    integration_request: Any,
    health_observation: dict[str, Any],
    approval: HumanApprovalReference | dict[str, Any] | None,
    checked_at: str,
    existing_requests: tuple[dict[str, Any], ...] | list[dict[str, Any]] = (),
    consumed_approval_hashes: tuple[str, ...] | list[str] = (),
    replayed_approval_hashes: tuple[str, ...] | list[str] = (),
) -> OfflineSimulationDecision:
    request_payload = request.to_dict() if isinstance(request, ActivationRequest) else dict(request)
    readiness = assess_controlled_activation(
        provider_record,
        request=integration_request,
        health_observation=health_observation,
        approval=approval,
        checked_at=checked_at,
    )
    errors = list(
        validate_activation_request(
            request_payload,
            provider_record=provider_record,
            readiness_assessment=readiness,
            checked_at=checked_at,
            existing_requests=existing_requests,
        )
    )
    binding = bind_human_approval(
        request_payload,
        approval,
        checked_at=checked_at,
        consumed_approval_hashes=consumed_approval_hashes,
        replayed_approval_hashes=replayed_approval_hashes,
    )
    if binding.failure_code:
        errors.append(binding.failure_code)
    errors.extend(_simulation_contract_errors(provider_record, integration_request, health_observation, checked_at))
    failure = _ordered_unique(errors)
    result = "ACTIVATION_SIMULATION_PASSED" if not failure else "ACTIVATION_SIMULATION_FAILED"
    body = {
        "schema": PRODUCTION_PROVIDER_ACTIVATION_SCHEMA + ".simulation",
        "result": result,
        "failure_code": "" if not failure else failure[0],
        "activation_request_id": request_payload.get("activation_request_id", ""),
        "provider_id": request_payload.get("provider_id", ""),
        "integration_type": request_payload.get("integration_type", ""),
        "tenant": request_payload.get("tenant", ""),
        "policy_version": request_payload.get("policy_version", ""),
        "readiness_report_hash": readiness.readiness_report_hash,
        **_false_execution_flags(),
    }
    simulation_hash = sha256_audit_hash(body)
    return OfflineSimulationDecision(
        result=result,
        failure_code=body["failure_code"],
        simulation_id=simulation_hash,
        activation_request_id=str(request_payload.get("activation_request_id", "")),
        provider_id=str(request_payload.get("provider_id", "")),
        integration_type=str(request_payload.get("integration_type", "")),
        tenant=str(request_payload.get("tenant", "")),
        policy_version=str(request_payload.get("policy_version", "")),
        readiness_report_hash=readiness.readiness_report_hash,
        simulation_hash=simulation_hash,
    )


def build_simulated_receipt(
    simulation: OfflineSimulationDecision,
    request: ActivationRequest | dict[str, Any],
    *,
    provider_record: dict[str, Any],
    approval_reference_hash: str,
    issued_at: str,
    expires_at: str,
    previous_receipt_hash: str = ZERO_AUDIT_CHAIN_HASH,
) -> SimulatedReceiptEnvelope:
    payload = request.to_dict() if isinstance(request, ActivationRequest) else dict(request)
    body = {
        "schema": PRODUCTION_PROVIDER_ACTIVATION_RECEIPT_SCHEMA,
        "simulated_receipt_id": "",
        "simulation_id": simulation.simulation_id,
        "activation_request_id": payload.get("activation_request_id", ""),
        "provider_id": payload.get("provider_id", ""),
        "integration_type": payload.get("integration_type", ""),
        "tenant": payload.get("tenant", ""),
        "policy_version": payload.get("policy_version", ""),
        "contract_version": payload.get("contract_version", ""),
        "registry_record_hash": payload.get("registry_record_hash", ""),
        "readiness_report_hash": simulation.readiness_report_hash,
        "approval_reference_hash": approval_reference_hash,
        "simulated_result": simulation.result,
        "failure_code": simulation.failure_code,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "correlation_id": payload.get("correlation_id", ""),
        "previous_receipt_hash": previous_receipt_hash,
        "simulation_only": True,
        **_false_execution_flags(),
    }
    simulated_receipt_id = sha256_audit_hash({**body, "schema": PRODUCTION_PROVIDER_ACTIVATION_RECEIPT_SCHEMA + ".id"})
    receipt_hash = sha256_audit_hash({**body, "simulated_receipt_id": simulated_receipt_id})
    receipt = SimulatedReceiptEnvelope(
        simulated_receipt_id=simulated_receipt_id,
        simulation_id=simulation.simulation_id,
        activation_request_id=str(payload.get("activation_request_id", "")),
        provider_id=str(payload.get("provider_id", "")),
        integration_type=str(payload.get("integration_type", "")),
        tenant=str(payload.get("tenant", "")),
        policy_version=str(payload.get("policy_version", "")),
        contract_version=str(payload.get("contract_version", "")),
        registry_record_hash=str(provider_record.get("registry_record_hash", payload.get("registry_record_hash", ""))),
        readiness_report_hash=simulation.readiness_report_hash,
        approval_reference_hash=approval_reference_hash,
        simulated_result=simulation.result,
        failure_code=simulation.failure_code,
        issued_at=issued_at,
        expires_at=expires_at,
        correlation_id=str(payload.get("correlation_id", "")),
        receipt_hash=receipt_hash,
        previous_receipt_hash=previous_receipt_hash,
    )
    errors = verify_simulated_receipt(receipt.to_dict(), request=payload, previous_receipt_hash=previous_receipt_hash)
    if errors:
        raise ValueError(errors[0])
    return receipt


def verify_simulated_receipt(
    receipt: SimulatedReceiptEnvelope | dict[str, Any],
    *,
    request: ActivationRequest | dict[str, Any],
    previous_receipt_hash: str,
) -> tuple[str, ...]:
    payload = receipt.to_dict() if isinstance(receipt, SimulatedReceiptEnvelope) else dict(receipt)
    request_payload = request.to_dict() if isinstance(request, ActivationRequest) else dict(request)
    errors: list[str] = []
    if payload.get("schema") != PRODUCTION_PROVIDER_ACTIVATION_RECEIPT_SCHEMA:
        errors.append("ACTIVATION_RECEIPT_SCHEMA_INVALID")
    for field in (
        "activation_request_id",
        "provider_id",
        "integration_type",
        "tenant",
        "policy_version",
        "contract_version",
        "registry_record_hash",
        "approval_reference_hash",
        "correlation_id",
    ):
        if payload.get(field) != request_payload.get(field):
            errors.append("ACTIVATION_RECEIPT_SCHEMA_INVALID")
    if payload.get("simulated_result") not in ("ACTIVATION_SIMULATION_PASSED", "ACTIVATION_SIMULATION_FAILED"):
        errors.append("ACTIVATION_RECEIPT_SCHEMA_INVALID")
    if payload.get("simulated_result") == "ACTIVATION_SIMULATION_FAILED" and not payload.get("failure_code"):
        errors.append("ACTIVATION_FAILED_CLOSED")
    if payload.get("simulation_only") is not True:
        errors.append("ACTIVATION_FAILED_CLOSED")
    if payload.get("previous_receipt_hash") != previous_receipt_hash or not _is_sha256_reference(previous_receipt_hash):
        errors.append("ACTIVATION_RECEIPT_REORDERED")
    if not _timestamp_order_valid(str(payload.get("issued_at", "")), str(payload.get("expires_at", ""))):
        errors.append("ACTIVATION_RECEIPT_SCHEMA_INVALID")
    if not all(_is_sha256_reference(payload.get(field)) for field in ("simulated_receipt_id", "simulation_id", "readiness_report_hash")):
        errors.append("ACTIVATION_RECEIPT_SCHEMA_INVALID")
    if any(payload.get(flag) is not False for flag in _EXECUTION_FLAGS):
        errors.append("ACTIVATION_FAILED_CLOSED")
    if _has_raw_marker(payload):
        errors.append("ACTIVATION_RAW_DATA_FORBIDDEN")
    expected_hash = sha256_audit_hash({key: value for key, value in payload.items() if key != "receipt_hash"})
    if payload.get("receipt_hash") != expected_hash:
        errors.append("ACTIVATION_RECEIPT_TAMPERED")
    return _ordered_unique(errors)


def verify_receipt_chain(receipts: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> ReceiptChainVerification:
    errors: list[str] = []
    previous_hash = ZERO_AUDIT_CHAIN_HASH
    seen_receipts: set[str] = set()
    seen_requests: set[str] = set()
    tenant = policy_version = provider_id = integration_type = None
    terminal_hash = ZERO_AUDIT_CHAIN_HASH
    for receipt in receipts:
        if not isinstance(receipt, dict):
            errors.append("ACTIVATION_RECEIPT_SCHEMA_INVALID")
            continue
        receipt_hash = str(receipt.get("receipt_hash", ""))
        if receipt_hash in seen_receipts:
            errors.append("ACTIVATION_RECEIPT_DUPLICATE")
        seen_receipts.add(receipt_hash)
        request_id = str(receipt.get("activation_request_id", ""))
        if request_id in seen_requests:
            errors.append("ACTIVATION_RECEIPT_REPLAYED")
        seen_requests.add(request_id)
        if receipt.get("previous_receipt_hash") != previous_hash:
            errors.append("ACTIVATION_RECEIPT_REORDERED")
        for field, value in (
            ("tenant", tenant),
            ("policy_version", policy_version),
            ("provider_id", provider_id),
            ("integration_type", integration_type),
        ):
            if value is None:
                continue
            if receipt.get(field) != value:
                errors.append("ACTIVATION_SCOPE_MISMATCH")
        tenant = tenant or receipt.get("tenant")
        policy_version = policy_version or receipt.get("policy_version")
        provider_id = provider_id or receipt.get("provider_id")
        integration_type = integration_type or receipt.get("integration_type")
        expected_hash = sha256_audit_hash({key: value for key, value in receipt.items() if key != "receipt_hash"})
        if receipt_hash != expected_hash:
            errors.append("ACTIVATION_RECEIPT_TAMPERED")
        if any(receipt.get(flag) is not False for flag in _EXECUTION_FLAGS):
            errors.append("ACTIVATION_FAILED_CLOSED")
        if _has_raw_marker(receipt):
            errors.append("ACTIVATION_RAW_DATA_FORBIDDEN")
        previous_hash = receipt_hash
        terminal_hash = receipt_hash
    failure = _ordered_unique(errors)
    body = {
        "valid": not failure,
        "failure_code": "" if not failure else failure[0],
        "receipt_hashes": [str(receipt.get("receipt_hash", "")) for receipt in receipts if isinstance(receipt, dict)],
        "terminal_receipt_hash": terminal_hash,
        **_false_execution_flags(),
    }
    return ReceiptChainVerification(
        valid=not failure,
        failure_code=body["failure_code"],
        chain_hash=sha256_audit_hash(body),
        receipt_count=len(receipts),
        terminal_receipt_hash=terminal_hash,
    )


def build_production_decision_package(
    request: ActivationRequest | dict[str, Any],
    *,
    provider_record: dict[str, Any],
    readiness_assessment: ActivationAssessment | dict[str, Any],
    health_observation: dict[str, Any],
    approval: HumanApprovalReference | dict[str, Any],
    receipt: SimulatedReceiptEnvelope | dict[str, Any],
    chain: ReceiptChainVerification,
    rollback_plan_reference: str,
    unresolved_risks: tuple[str, ...] = (),
) -> ProductionDecisionPackage:
    request_payload = request.to_dict() if isinstance(request, ActivationRequest) else dict(request)
    readiness = readiness_assessment.to_dict() if isinstance(readiness_assessment, ActivationAssessment) else dict(readiness_assessment)
    approval_payload = approval.to_dict() if isinstance(approval, HumanApprovalReference) else dict(approval)
    receipt_payload = receipt.to_dict() if isinstance(receipt, SimulatedReceiptEnvelope) else dict(receipt)
    risks = tuple(sorted(unresolved_risks))
    result = "READY_FOR_HUMAN_PRODUCTION_DECISION"
    if (
        readiness.get("result") != "READY_FOR_CONTROLLED_ACTIVATION"
        or receipt_payload.get("simulated_result") != "ACTIVATION_SIMULATION_PASSED"
        or not chain.valid
        or not _is_sha256_reference(rollback_plan_reference)
        or _has_raw_marker((request_payload, provider_record, readiness, health_observation, approval_payload, receipt_payload, risks))
    ):
        result = "ACTIVATION_BLOCKED"
        risks = tuple(sorted((*risks, "PRODUCTION_DECISION_PACKAGE_INCOMPLETE")))
    body = {
        "schema": PRODUCTION_PROVIDER_ACTIVATION_PACKAGE_SCHEMA,
        "activation_request_reference": request_payload.get("activation_request_id", ""),
        "provider_registry_reference": provider_record.get("registry_record_hash", ""),
        "readiness_evidence_reference": readiness.get("readiness_report_hash", ""),
        "health_observation_reference": health_observation.get("observation_hash", ""),
        "human_approval_reference": approval_payload.get("approval_reference_hash", ""),
        "simulation_receipt_reference": receipt_payload.get("receipt_hash", ""),
        "simulation_chain_reference": chain.chain_hash,
        "rollback_plan_reference": rollback_plan_reference,
        "unresolved_risks": list(risks),
        "result": result,
        **_false_execution_flags(),
    }
    return ProductionDecisionPackage(
        activation_request_reference=str(body["activation_request_reference"]),
        provider_registry_reference=str(body["provider_registry_reference"]),
        readiness_evidence_reference=str(body["readiness_evidence_reference"]),
        health_observation_reference=str(body["health_observation_reference"]),
        human_approval_reference=str(body["human_approval_reference"]),
        simulation_receipt_reference=str(body["simulation_receipt_reference"]),
        simulation_chain_reference=chain.chain_hash,
        rollback_plan_reference=rollback_plan_reference,
        unresolved_risks=risks,
        final_package_hash=sha256_audit_hash(body),
        result=result,
    )


def serialize_provider_activation_result(payload: Any) -> str:
    if hasattr(payload, "to_dict"):
        payload = payload.to_dict()
    if _has_raw_marker(payload):
        raise ValueError("ACTIVATION_RAW_DATA_FORBIDDEN")
    return canonical_audit_json(payload)


def _simulation_contract_errors(provider_record: dict[str, Any], integration_request: Any, health_observation: dict[str, Any], checked_at: str) -> tuple[str, ...]:
    errors: list[str] = []
    errors.extend(_map_registry_error(error) for error in validate_provider_registration(provider_record))
    errors.extend(_map_contract_error(error) for error in validate_integration_request(integration_request))
    errors.extend(_map_registry_error(error) for error in verify_health_observation(health_observation, provider_record=provider_record, checked_at=checked_at))
    if provider_record.get("receipt_schema") != PRODUCTION_INTEGRATION_RECEIPT_SCHEMA:
        errors.append("ACTIVATION_RECEIPT_SCHEMA_INVALID")
    required = REQUIRED_CAPABILITY_BY_INTEGRATION.get(provider_record.get("integration_type", ""), "")
    if required not in tuple(provider_record.get("supported_capabilities", ())):
        errors.append("ACTIVATION_PROVIDER_NOT_READY")
    return _ordered_unique(errors)


def _map_registry_error(error: str) -> str:
    return {
        "CONTRACT_VERSION_INCOMPATIBLE": "ACTIVATION_CONTRACT_INCOMPATIBLE",
        "TENANT_SCOPE_MISMATCH": "ACTIVATION_SCOPE_MISMATCH",
        "POLICY_SCOPE_MISMATCH": "ACTIVATION_SCOPE_MISMATCH",
        "HUMAN_APPROVAL_MISSING": "ACTIVATION_APPROVAL_REQUIRED",
        "HUMAN_APPROVAL_EXPIRED": "ACTIVATION_APPROVAL_EXPIRED",
        "HUMAN_APPROVAL_SCOPE_MISMATCH": "ACTIVATION_SCOPE_MISMATCH",
        "HEALTH_OBSERVATION_MISSING": "ACTIVATION_HEALTH_INVALID",
        "HEALTH_OBSERVATION_INVALID": "ACTIVATION_HEALTH_INVALID",
        "HEALTH_EXPIRED": "ACTIVATION_HEALTH_INVALID",
        "HEALTH_DEGRADED": "ACTIVATION_HEALTH_INVALID",
        "RECEIPT_SCHEMA_INVALID": "ACTIVATION_RECEIPT_SCHEMA_INVALID",
        "RAW_DATA_FORBIDDEN": "ACTIVATION_RAW_DATA_FORBIDDEN",
        "FAILED_CLOSED": "ACTIVATION_FAILED_CLOSED",
    }.get(error, "ACTIVATION_PROVIDER_NOT_READY")


def _map_contract_error(error: str) -> str:
    return {
        "INTEGRATION_UNKNOWN": "ACTIVATION_REQUEST_MALFORMED",
        "TENANT_MISMATCH": "ACTIVATION_SCOPE_MISMATCH",
        "POLICY_VERSION_MISMATCH": "ACTIVATION_SCOPE_MISMATCH",
        "TIMEOUT_INVALID": "ACTIVATION_REQUEST_MALFORMED",
        "RECEIPT_SCHEMA_INVALID": "ACTIVATION_RECEIPT_SCHEMA_INVALID",
        "RAW_DATA_FORBIDDEN": "ACTIVATION_RAW_DATA_FORBIDDEN",
        "FAILED_CLOSED": "ACTIVATION_FAILED_CLOSED",
    }.get(error, "ACTIVATION_REQUEST_MALFORMED")


def _state_for_failure(failure_code: str) -> str:
    return {
        "ACTIVATION_APPROVAL_REQUIRED": "ACTIVATION_APPROVAL_REQUIRED",
        "ACTIVATION_APPROVAL_EXPIRED": "ACTIVATION_APPROVAL_EXPIRED",
        "ACTIVATION_SCOPE_MISMATCH": "ACTIVATION_SCOPE_MISMATCH",
        "ACTIVATION_PROVIDER_NOT_READY": "ACTIVATION_PROVIDER_NOT_READY",
        "ACTIVATION_HEALTH_INVALID": "ACTIVATION_HEALTH_INVALID",
        "ACTIVATION_CONTRACT_INCOMPATIBLE": "ACTIVATION_CONTRACT_INCOMPATIBLE",
        "ACTIVATION_DUPLICATE": "ACTIVATION_DUPLICATE",
        "ACTIVATION_APPROVAL_REPLAYED": "ACTIVATION_REPLAY_BLOCKED",
        "ACTIVATION_APPROVAL_CONSUMED": "ACTIVATION_REPLAY_BLOCKED",
    }.get(failure_code, "ACTIVATION_BLOCKED")


def _logical_request(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "activation_request_hash"}


def _ordered_unique(errors: list[str]) -> tuple[str, ...]:
    return tuple(code for code in ACTIVATION_FAILURE_CODES if code in errors)


def _false_execution_flags() -> dict[str, bool]:
    return {flag: False for flag in _EXECUTION_FLAGS}


def _registry_execution_flags() -> tuple[str, ...]:
    return tuple(flag for flag in _EXECUTION_FLAGS if flag != "credentials_access" and flag != "live_provider_call")


def _timestamp_order_valid(start: str, end: str) -> bool:
    return bool(start and end and start < end and start.endswith("Z") and end.endswith("Z"))


def _label_valid(value: Any) -> bool:
    return isinstance(value, str) and 3 <= len(value) <= 80 and all(char.isupper() or char.isdigit() or char in "_-" for char in value)


def _is_sha256_reference(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def _has_raw_marker(payload: Any) -> bool:
    rendered = canonical_audit_json(_without_execution_flags(payload)).lower()
    return any(marker in rendered for marker in _RAW_MARKERS)


def _without_execution_flags(payload: Any) -> Any:
    if isinstance(payload, dict):
        return {key: _without_execution_flags(value) for key, value in payload.items() if key not in _EXECUTION_FLAGS}
    if isinstance(payload, (list, tuple)):
        return [_without_execution_flags(item) for item in payload]
    return payload
