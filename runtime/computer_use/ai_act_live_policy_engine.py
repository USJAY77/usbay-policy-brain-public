from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence, Union

from governance.hashing import ZERO_SHA256_REFERENCE, is_sha256_reference, sha256_reference
from runtime import policy_validator
from security.decision_evidence_consumption_store import (
    FIRST_CONSUMPTION,
    DecisionEvidenceConsumptionStore,
    default_consumption_store,
)


ALLOW = "ALLOW"
BLOCK = "BLOCK"

SCHEMA_VERSION = "usbay.ai_act_live_policy_engine.v1"
DECISION_TRACE_SCHEMA_VERSION = "usbay.ai_act_live_policy_engine.decision_trace.v1"
DECISION_CONSUMPTION_SCHEMA_VERSION = "usbay.ai_act_live_policy_engine.decision_consumption.v1"
DECISION_REPLAY_SCHEMA_VERSION = "usbay.ai_act_live_policy_engine.decision_replay.v1"
EXECUTION_AUTHORIZATION_SCHEMA_VERSION = "usbay.ai_act_live_policy_engine.execution_authorization.v1"
SUPPORTED_RULE_OPERATOR = "equals"
SUPPORTED_RULE_EFFECTS = frozenset({ALLOW, BLOCK})
SUPPORTED_OBLIGATION_TYPES = frozenset(
    {
        "human_review_required",
        "approval_required",
        "evidence_required",
        "purpose_binding_required",
        "execution_contract_required",
        "jurisdiction_constraint",
        "data_minimization_required",
    }
)
SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "body",
        "content",
        "credential",
        "credentials",
        "customer_data",
        "password",
        "payload",
        "personal_data",
        "private_key",
        "prompt",
        "prompts",
        "provider_response",
        "raw",
        "raw_payload",
        "secret",
        "sensitive_data",
        "token",
    }
)

REQUIRED_REQUEST_FIELDS = frozenset(
    {
        "request_id",
        "correlation_id",
        "tenant_id",
        "environment",
        "actor_id",
        "policy_id",
        "policy_version",
        "policy_hash",
        "input_metadata",
    }
)


@dataclass(frozen=True)
class PolicyAuthority:
    policy_id: str
    policy_version: str
    policy_hash: str
    approved: bool
    policy_document: Mapping[str, Any]
    source: str = "runtime.policy_validator"
    approval_evidence_present: bool = True
    approval_evidence_valid: bool = True
    revoked: bool = False
    superseded: bool = False
    superseded_by_policy_version: str | None = None
    ambiguous: bool = False
    authority_available: bool = True
    authority_state: str = "CURRENT"
    authority_state_reference: str | None = None
    applicability: Mapping[str, Any] | None = None
    applicability_available: bool = True
    applicability_ambiguous: bool = False


@dataclass(frozen=True)
class LivePolicyEvaluation:
    decision: str
    reason_code: str
    decision_id: str
    timestamp: str
    policy_id: str | None
    policy_version: str | None
    policy_hash: str | None
    correlation_id: str | None
    evidence: Mapping[str, Any]
    execution_authorized: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    deployment_authorized: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


PolicyAuthorityLoader = Callable[[], Union[PolicyAuthority, Mapping[str, Any]]]
Clock = Callable[[], str]


def evaluate_live_policy(
    request: Mapping[str, Any] | None,
    *,
    policy_authority_loader: PolicyAuthorityLoader | None = None,
    previous_evidence_hash: str = ZERO_SHA256_REFERENCE,
    clock: Clock | None = None,
) -> LivePolicyEvaluation:
    """Evaluate approved policy metadata and emit immutable hash-only evidence.

    This function does not create, modify, approve, relax, promote, or execute
    policy. It returns only ALLOW or BLOCK; ALLOW means the request may continue
    to the next governed boundary and never authorizes runtime execution.
    """

    timestamp = _timestamp(clock)
    try:
        return _evaluate_live_policy(
            request,
            policy_authority_loader=policy_authority_loader or load_human_approved_policy_authority,
            previous_evidence_hash=previous_evidence_hash,
            timestamp=timestamp,
        )
    except Exception:
        return _blocked(
            request,
            reason_code="POLICY_EVALUATION_EXCEPTION",
            timestamp=timestamp,
            policy_id=None,
            policy_version=None,
            policy_hash=None,
            previous_evidence_hash=_safe_previous_hash(previous_evidence_hash),
        )


def consume_decision_evidence(
    request: Mapping[str, Any] | None,
    decision_evidence: Mapping[str, Any] | None,
    *,
    policy_authority_loader: PolicyAuthorityLoader | None = None,
    consumption_store: DecisionEvidenceConsumptionStore | None = None,
    previous_evidence_hash: str = ZERO_SHA256_REFERENCE,
    clock: Clock | None = None,
) -> LivePolicyEvaluation:
    """Validate historical ALLOW evidence against current authority.

    Decision evidence is not execution authority. This gate proves that a
    previously emitted ALLOW remains authentic, bound to the current governed
    request, and supported by current policy authority before a downstream
    governed execution boundary may consider it. The returned ALLOW still does
    not execute anything and keeps execution flags false.
    """

    timestamp = _timestamp(clock)
    try:
        return _consume_decision_evidence(
            request,
            decision_evidence,
            policy_authority_loader=policy_authority_loader or load_human_approved_policy_authority,
            consumption_store=consumption_store or default_consumption_store(),
            previous_evidence_hash=_safe_previous_hash(previous_evidence_hash),
            timestamp=timestamp,
        )
    except Exception:
        return _blocked(
            request,
            reason_code="DECISION_EVIDENCE_CONSUMPTION_EXCEPTION",
            timestamp=timestamp,
            policy_id=_request_field(request, "policy_id"),
            policy_version=_request_field(request, "policy_version"),
            policy_hash=_request_field(request, "policy_hash"),
            previous_evidence_hash=_safe_previous_hash(previous_evidence_hash),
        )


def create_governed_execution_authorization(
    request: Mapping[str, Any] | None,
    consumed_decision: LivePolicyEvaluation | Mapping[str, Any] | None,
    execution_contract: Mapping[str, Any] | None,
    *,
    previous_evidence_hash: str = ZERO_SHA256_REFERENCE,
    clock: Clock | None = None,
) -> LivePolicyEvaluation:
    """Create a bounded non-executing authorization for one downstream action."""

    timestamp = _timestamp(clock)
    try:
        return _create_governed_execution_authorization(
            request,
            consumed_decision,
            execution_contract,
            previous_evidence_hash=_safe_previous_hash(previous_evidence_hash),
            timestamp=timestamp,
        )
    except Exception:
        return _blocked(
            request,
            reason_code="EXEC_AUTH_VERIFIER_UNAVAILABLE",
            timestamp=timestamp,
            policy_id=_request_field(request, "policy_id"),
            policy_version=_request_field(request, "policy_version"),
            policy_hash=_request_field(request, "policy_hash"),
            previous_evidence_hash=_safe_previous_hash(previous_evidence_hash),
        )


def validate_governed_execution_authorization(
    authorization: Mapping[str, Any] | None,
    request: Mapping[str, Any] | None,
    execution_contract: Mapping[str, Any] | None,
    *,
    consumed_decision_evidence_hash: str | None = None,
    clock: Clock | None = None,
) -> str | None:
    """Return None when authorization exactly matches this request and action."""

    try:
        return _validate_governed_execution_authorization(
            authorization,
            request,
            execution_contract,
            consumed_decision_evidence_hash=consumed_decision_evidence_hash,
            timestamp=_timestamp(clock),
        )
    except Exception:
        return "EXEC_AUTH_VERIFIER_UNAVAILABLE"


def load_human_approved_policy_authority() -> PolicyAuthority:
    """Load the repository's existing signed, human-approved policy source."""

    policy_validator.validate_required_files()
    policy_validator.validate_policy_json()
    policy_validator.validate_sha256()
    policy_validator.validate_signature()
    metadata = policy_validator.load_policy_metadata()
    policy_validator.validate_approval_artifacts(
        policy_hash=metadata["policy_hash"],
        policy_version=metadata["policy_version"],
    )
    policy = metadata["policy"]
    return PolicyAuthority(
        policy_id=_policy_id(policy),
        policy_version=metadata["policy_version"],
        policy_hash="sha256:" + metadata["policy_hash"],
        approved=True,
        policy_document=policy,
        authority_state_reference=sha256_reference(
            {
                "source": "runtime.policy_validator",
                "policy_id": _policy_id(policy),
                "policy_version": metadata["policy_version"],
                "policy_hash": "sha256:" + metadata["policy_hash"],
                "approval_evidence_valid": True,
                "authority_state": "CURRENT",
            }
        ),
    )


def _consume_decision_evidence(
    request: Mapping[str, Any] | None,
    decision_evidence: Mapping[str, Any] | None,
    *,
    policy_authority_loader: PolicyAuthorityLoader,
    consumption_store: DecisionEvidenceConsumptionStore,
    previous_evidence_hash: str,
    timestamp: str,
) -> LivePolicyEvaluation:
    if not isinstance(decision_evidence, Mapping):
        return _decision_consumption_block(
            request,
            reason_code="DECISION_EVIDENCE_MISSING",
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    if _contains_sensitive_data(decision_evidence):
        return _decision_consumption_block(
            request,
            reason_code="DECISION_EVIDENCE_MALFORMED",
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    evidence_error = _validate_decision_evidence_integrity(decision_evidence)
    if evidence_error:
        return _decision_consumption_block(
            request,
            reason_code=evidence_error,
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    if decision_evidence.get("result") != ALLOW:
        return _decision_consumption_block(
            request,
            reason_code="DECISION_NOT_ALLOW",
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )

    request_error = _validate_request(request)
    if request_error:
        return _decision_consumption_block(
            request,
            reason_code="DECISION_EVIDENCE_MALFORMED",
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    binding_error = _validate_decision_evidence_binding(decision_evidence, request)
    if binding_error:
        return _decision_consumption_block(
            request,
            reason_code=binding_error,
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )

    authority = _coerce_policy_authority(policy_authority_loader())
    authority_error = _validate_policy_authority(authority, request)
    if authority_error:
        return _decision_consumption_block(
            request,
            reason_code=_decision_authority_reason(authority_error),
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    policy_error = _validate_supported_policy(authority.policy_document)
    if policy_error:
        return _decision_consumption_block(
            request,
            reason_code="DECISION_AUTHORITY_INVALID",
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )

    applicability_error, applicability_evidence = _validate_applicability_and_effectivity(
        authority,
        request,
        timestamp,
    )
    if applicability_error:
        return _decision_consumption_block(
            request,
            reason_code=_decision_applicability_reason(applicability_error),
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    applicability_binding_error = _validate_applicability_consumption_binding(
        decision_evidence,
        applicability_evidence,
    )
    if applicability_binding_error:
        return _decision_consumption_block(
            request,
            reason_code=applicability_binding_error,
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )

    obligation_error, obligation_evidence = _validate_policy_obligations(
        authority,
        request,
        timestamp,
    )
    if obligation_error:
        return _decision_consumption_block(
            request,
            reason_code=_decision_obligation_reason(obligation_error),
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    obligation_binding_error = _validate_obligation_consumption_binding(
        decision_evidence,
        obligation_evidence,
    )
    if obligation_binding_error:
        return _decision_consumption_block(
            request,
            reason_code=obligation_binding_error,
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )

    if decision_evidence.get("authority_state_reference") != _authority_state_reference(authority):
        return _decision_consumption_block(
            request,
            reason_code="DECISION_AUTHORITY_INVALID",
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    if _decision_evidence_expired(decision_evidence, timestamp):
        return _decision_consumption_block(
            request,
            reason_code="DECISION_EVIDENCE_EXPIRED",
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )

    rules = authority.policy_document["ai_act_live_policy_engine"]["rules"]
    matches = _matching_rule_effects(rules, request["input_metadata"])
    if not matches or len(matches) > 1 and len({effect for _, effect in matches}) > 1:
        return _decision_consumption_block(
            request,
            reason_code="DECISION_POLICY_STALE",
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    rule_id, effect = matches[0]
    if effect != ALLOW or decision_evidence.get("matched_rule_id") != rule_id:
        return _decision_consumption_block(
            request,
            reason_code="DECISION_POLICY_STALE",
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )

    replay_key = _decision_consumption_replay_key(
        request=request,
        decision_evidence=decision_evidence,
        authority=authority,
        applicability_evidence=applicability_evidence,
        obligation_evidence=obligation_evidence,
    )
    replay_key_hash = sha256_reference({"replay_key": replay_key})
    retention_seconds = _decision_consumption_retention_seconds(decision_evidence, timestamp)
    if retention_seconds is None:
        return _decision_consumption_block(
            request,
            reason_code="INVALID_REPLAY_KEY",
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
            replay_evidence=_replay_evidence(
                result="INVALID_REPLAY_KEY",
                replay_key_hash=replay_key_hash,
                decision_evidence=decision_evidence,
                request=request,
                store_type=getattr(consumption_store, "store_type", "unknown"),
                timestamp=timestamp,
            ),
        )
    consumption = consumption_store.consume_if_unused(
        replay_key,
        replay_key_hash=replay_key_hash,
        consumed_decision_evidence_hash=decision_evidence["current_evidence_hash"],
        retention_seconds=retention_seconds,
        consumed_at=timestamp,
    )
    replay_evidence = _replay_evidence(
        result=consumption.result,
        replay_key_hash=replay_key_hash,
        decision_evidence=decision_evidence,
        request=request,
        store_type=consumption.store_type,
        timestamp=timestamp,
        retention_seconds=retention_seconds,
    )
    if consumption.result != FIRST_CONSUMPTION:
        return _decision_consumption_block(
            request,
            reason_code=consumption.reason_code,
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
            replay_evidence=replay_evidence,
        )

    return _allowed(
        request,
        reason_code="DECISION_EVIDENCE_CONSUMED",
        timestamp=timestamp,
        policy_id=authority.policy_id,
        policy_version=authority.policy_version,
        policy_hash=authority.policy_hash,
        previous_evidence_hash=decision_evidence["current_evidence_hash"],
        matched_rule_id=rule_id,
        approved_policy_version=authority.policy_version,
        approved_policy_hash=authority.policy_hash,
        authority_verification_result="DECISION_EVIDENCE_CONSUMPTION_VERIFIED",
        authority_state_reference=_authority_state_reference(authority),
        applicability_evidence={
            **applicability_evidence,
            "decision_consumption_schema_version": DECISION_CONSUMPTION_SCHEMA_VERSION,
            "consumed_decision_evidence_hash": decision_evidence["current_evidence_hash"],
            "consumption_attempt_reference": sha256_reference(
                {
                    "request_hash": _request_hash(request),
                    "correlation_id": _request_field(request, "correlation_id"),
                    "decision_evidence_hash": decision_evidence["current_evidence_hash"],
                    "timestamp": timestamp,
                },
                default_to_str=True,
            ),
            **replay_evidence,
        },
        obligation_evidence=obligation_evidence,
    )


def _evaluate_live_policy(
    request: Mapping[str, Any] | None,
    *,
    policy_authority_loader: PolicyAuthorityLoader,
    previous_evidence_hash: str,
    timestamp: str,
) -> LivePolicyEvaluation:
    previous_hash = _safe_previous_hash(previous_evidence_hash)
    request_error = _validate_request(request)
    if request_error:
        return _blocked(
            request,
            reason_code=request_error,
            timestamp=timestamp,
            policy_id=_request_field(request, "policy_id"),
            policy_version=_request_field(request, "policy_version"),
            policy_hash=_request_field(request, "policy_hash"),
            previous_evidence_hash=previous_hash,
            approved_policy_version=None,
            approved_policy_hash=None,
            authority_verification_result="NOT_EVALUATED",
            authority_state_reference=ZERO_SHA256_REFERENCE,
        )

    authority = _coerce_policy_authority(policy_authority_loader())
    authority_error = _validate_policy_authority(authority, request)
    if authority_error:
        return _blocked(
            request,
            reason_code=authority_error,
            timestamp=timestamp,
            policy_id=authority.policy_id or _request_field(request, "policy_id"),
            policy_version=authority.policy_version or _request_field(request, "policy_version"),
            policy_hash=authority.policy_hash or _request_field(request, "policy_hash"),
            previous_evidence_hash=previous_hash,
            approved_policy_version=authority.policy_version or None,
            approved_policy_hash=authority.policy_hash or None,
            authority_verification_result=authority_error,
            authority_state_reference=_authority_state_reference(authority),
        )

    policy_error = _validate_supported_policy(authority.policy_document)
    if policy_error:
        return _blocked(
            request,
            reason_code=policy_error,
            timestamp=timestamp,
            policy_id=authority.policy_id,
            policy_version=authority.policy_version,
            policy_hash=authority.policy_hash,
            previous_evidence_hash=previous_hash,
            approved_policy_version=authority.policy_version,
            approved_policy_hash=authority.policy_hash,
            authority_verification_result=policy_error,
            authority_state_reference=_authority_state_reference(authority),
        )

    applicability_error, applicability_evidence = _validate_applicability_and_effectivity(
        authority,
        request,
        timestamp,
    )
    if applicability_error:
        return _blocked(
            request,
            reason_code=applicability_error,
            timestamp=timestamp,
            policy_id=authority.policy_id,
            policy_version=authority.policy_version,
            policy_hash=authority.policy_hash,
            previous_evidence_hash=previous_hash,
            approved_policy_version=authority.policy_version,
            approved_policy_hash=authority.policy_hash,
            authority_verification_result="POLICY_AUTHORITY_VERIFIED",
            authority_state_reference=_authority_state_reference(authority),
            applicability_evidence=applicability_evidence,
        )

    obligation_error, obligation_evidence = _validate_policy_obligations(
        authority,
        request,
        timestamp,
    )
    if obligation_error:
        return _blocked(
            request,
            reason_code=obligation_error,
            timestamp=timestamp,
            policy_id=authority.policy_id,
            policy_version=authority.policy_version,
            policy_hash=authority.policy_hash,
            previous_evidence_hash=previous_hash,
            approved_policy_version=authority.policy_version,
            approved_policy_hash=authority.policy_hash,
            authority_verification_result="POLICY_AUTHORITY_VERIFIED",
            authority_state_reference=_authority_state_reference(authority),
            applicability_evidence=applicability_evidence,
            obligation_evidence=obligation_evidence,
        )

    rules = authority.policy_document["ai_act_live_policy_engine"]["rules"]
    matches = _matching_rule_effects(rules, request["input_metadata"])
    if len(matches) > 1 and len({effect for _, effect in matches}) > 1:
        return _blocked(
            request,
            reason_code="AMBIGUOUS_POLICY_DECISION",
            timestamp=timestamp,
            policy_id=authority.policy_id,
            policy_version=authority.policy_version,
            policy_hash=authority.policy_hash,
            previous_evidence_hash=previous_hash,
            approved_policy_version=authority.policy_version,
            approved_policy_hash=authority.policy_hash,
            authority_verification_result="POLICY_AUTHORITY_VERIFIED",
            authority_state_reference=_authority_state_reference(authority),
            applicability_evidence=applicability_evidence,
            obligation_evidence=obligation_evidence,
        )
    if not matches:
        return _blocked(
            request,
            reason_code="POLICY_CONDITION_NOT_SATISFIED",
            timestamp=timestamp,
            policy_id=authority.policy_id,
            policy_version=authority.policy_version,
            policy_hash=authority.policy_hash,
            previous_evidence_hash=previous_hash,
            approved_policy_version=authority.policy_version,
            approved_policy_hash=authority.policy_hash,
            authority_verification_result="POLICY_AUTHORITY_VERIFIED",
            authority_state_reference=_authority_state_reference(authority),
            applicability_evidence=applicability_evidence,
            obligation_evidence=obligation_evidence,
        )

    rule_id, effect = matches[0]
    if effect != ALLOW:
        return _blocked(
            request,
            reason_code="POLICY_RULE_BLOCKED",
            timestamp=timestamp,
            policy_id=authority.policy_id,
            policy_version=authority.policy_version,
            policy_hash=authority.policy_hash,
            previous_evidence_hash=previous_hash,
            matched_rule_id=rule_id,
            approved_policy_version=authority.policy_version,
            approved_policy_hash=authority.policy_hash,
            authority_verification_result="POLICY_AUTHORITY_VERIFIED",
            authority_state_reference=_authority_state_reference(authority),
            applicability_evidence=applicability_evidence,
            obligation_evidence=obligation_evidence,
        )

    return _allowed(
        request,
        reason_code="POLICY_RULE_ALLOWED",
        timestamp=timestamp,
        policy_id=authority.policy_id,
        policy_version=authority.policy_version,
        policy_hash=authority.policy_hash,
        previous_evidence_hash=previous_hash,
        matched_rule_id=rule_id,
        approved_policy_version=authority.policy_version,
        approved_policy_hash=authority.policy_hash,
        authority_verification_result="POLICY_AUTHORITY_VERIFIED",
        authority_state_reference=_authority_state_reference(authority),
        applicability_evidence=applicability_evidence,
        obligation_evidence=obligation_evidence,
    )


def _create_governed_execution_authorization(
    request: Mapping[str, Any] | None,
    consumed_decision: LivePolicyEvaluation | Mapping[str, Any] | None,
    execution_contract: Mapping[str, Any] | None,
    *,
    previous_evidence_hash: str,
    timestamp: str,
) -> LivePolicyEvaluation:
    if not isinstance(request, Mapping):
        return _execution_authorization_block(
            request,
            reason_code="EXEC_AUTH_MALFORMED",
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    request_error = _validate_request(request)
    if request_error:
        return _execution_authorization_block(
            request,
            reason_code="EXEC_AUTH_MALFORMED",
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    if _execution_contract_contains_sensitive_data(execution_contract):
        return _execution_authorization_block(
            request,
            reason_code="EXEC_AUTH_MALFORMED",
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    decision_payload = consumed_decision.evidence if isinstance(consumed_decision, LivePolicyEvaluation) else consumed_decision
    decision_error = _validate_consumed_allow_decision(consumed_decision, decision_payload)
    if decision_error:
        return _execution_authorization_block(
            request,
            reason_code=decision_error,
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    if not isinstance(decision_payload, Mapping):
        return _execution_authorization_block(
            request,
            reason_code="EXEC_AUTH_DECISION_LINK_INVALID",
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    binding_error = _validate_decision_evidence_binding(decision_payload, request)
    if binding_error:
        return _execution_authorization_block(
            request,
            reason_code="EXEC_AUTH_DECISION_LINK_INVALID",
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    contract_error = _validate_execution_contract(execution_contract)
    if contract_error:
        return _execution_authorization_block(
            request,
            reason_code=contract_error,
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    if not isinstance(execution_contract, Mapping):
        return _execution_authorization_block(
            request,
            reason_code="EXEC_AUTH_MALFORMED",
            timestamp=timestamp,
            previous_evidence_hash=previous_evidence_hash,
        )
    authorization = _execution_authorization_payload(
        request=request,
        decision_evidence=decision_payload,
        execution_contract=execution_contract,
        timestamp=timestamp,
    )
    return _allowed(
        request,
        reason_code="EXEC_AUTH_CREATED",
        timestamp=timestamp,
        policy_id=_request_field(request, "policy_id"),
        policy_version=_request_field(request, "policy_version"),
        policy_hash=_request_field(request, "policy_hash"),
        previous_evidence_hash=previous_evidence_hash,
        approved_policy_version=_request_field(request, "policy_version"),
        approved_policy_hash=_request_field(request, "policy_hash"),
        authority_verification_result="EXEC_AUTH_CREATED",
        authority_state_reference=decision_payload.get("authority_state_reference", ZERO_SHA256_REFERENCE),
        applicability_evidence=authorization,
    )


def _execution_authorization_block(
    request: Mapping[str, Any] | None,
    *,
    reason_code: str,
    timestamp: str,
    previous_evidence_hash: str,
) -> LivePolicyEvaluation:
    evidence = {
        "execution_authorization_schema_version": EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
        "execution_authorization_result": "BLOCK",
        "execution_authorization_validation_result": reason_code,
        "execution_authorization_hash": ZERO_SHA256_REFERENCE,
    }
    return _blocked(
        request,
        reason_code=reason_code,
        timestamp=timestamp,
        policy_id=_request_field(request, "policy_id"),
        policy_version=_request_field(request, "policy_version"),
        policy_hash=_request_field(request, "policy_hash"),
        previous_evidence_hash=previous_evidence_hash,
        authority_verification_result=reason_code,
        authority_state_reference=ZERO_SHA256_REFERENCE,
        applicability_evidence=evidence,
    )


def _validate_consumed_allow_decision(
    consumed_decision: LivePolicyEvaluation | Mapping[str, Any] | None,
    evidence: Mapping[str, Any] | None,
) -> str | None:
    if isinstance(consumed_decision, LivePolicyEvaluation):
        if consumed_decision.decision != ALLOW or consumed_decision.reason_code != "DECISION_EVIDENCE_CONSUMED":
            return "EXEC_AUTH_DECISION_LINK_INVALID"
    if not isinstance(evidence, Mapping):
        return "EXEC_AUTH_DECISION_LINK_INVALID"
    if evidence.get("result") != ALLOW or evidence.get("reason_code") != "DECISION_EVIDENCE_CONSUMED":
        return "EXEC_AUTH_DECISION_LINK_INVALID"
    if evidence.get("decision_replay_result") != FIRST_CONSUMPTION:
        return "EXEC_AUTH_REUSED"
    if not is_sha256_reference(evidence.get("consumed_decision_evidence_hash")):
        return "EXEC_AUTH_DECISION_LINK_INVALID"
    if _validate_decision_evidence_integrity(evidence):
        return "EXEC_AUTH_TAMPERED"
    return None


def _validate_execution_contract(contract: Mapping[str, Any] | None) -> str | None:
    if not isinstance(contract, Mapping):
        return "EXEC_AUTH_MISSING"
    required = {
        "subject_id": "EXEC_AUTH_SUBJECT_MISMATCH",
        "agent_id": "EXEC_AUTH_SUBJECT_MISMATCH",
        "action_id": "EXEC_AUTH_ACTION_MISMATCH",
        "tool_id": "EXEC_AUTH_ACTION_MISMATCH",
        "resource_id": "EXEC_AUTH_RESOURCE_MISMATCH",
        "target_id": "EXEC_AUTH_RESOURCE_MISMATCH",
        "parameter_hash": "EXEC_AUTH_PARAMETER_MISMATCH",
        "purpose": "EXEC_AUTH_PURPOSE_MISMATCH",
        "expires_at": "EXEC_AUTH_EXPIRED",
        "authorization_nonce": "EXEC_AUTH_MALFORMED",
    }
    for field, reason in required.items():
        value = contract.get(field)
        if not isinstance(value, str) or not value:
            return reason
    if not is_sha256_reference(contract.get("parameter_hash")):
        return "EXEC_AUTH_PARAMETER_MISMATCH"
    return None


def _execution_contract_contains_sensitive_data(contract: Mapping[str, Any] | None) -> bool:
    if not isinstance(contract, Mapping):
        return False
    for key, value in contract.items():
        if key == "authorization_nonce":
            if not isinstance(value, str) or not value:
                return True
            continue
        if _contains_sensitive_data({key: value}):
            return True
    return False


def _execution_authorization_contains_sensitive_data(authorization: Mapping[str, Any]) -> bool:
    allowed_authorization_fields = {
        "execution_authorization_schema_version",
        "execution_authorization_result",
        "execution_authorization_validation_result",
        "authorization_id",
        "authorization_nonce_hash",
        "execution_authorization_hash",
    }
    for key, value in authorization.items():
        if key in allowed_authorization_fields:
            if isinstance(value, Mapping) or isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
                return True
            continue
        if _contains_sensitive_data({key: value}):
            return True
    return False


def _execution_authorization_payload(
    *,
    request: Mapping[str, Any],
    decision_evidence: Mapping[str, Any],
    execution_contract: Mapping[str, Any],
    timestamp: str,
) -> dict[str, Any]:
    payload = {
        "execution_authorization_schema_version": EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
        "execution_authorization_result": "ALLOW",
        "execution_authorization_validation_result": "EXEC_AUTH_VALID",
        "authorization_id": "exec-auth-" + sha256_reference(
            {
                "request_hash": _request_hash(request),
                "decision_evidence_hash": decision_evidence.get("consumed_decision_evidence_hash"),
                "authorization_nonce": execution_contract.get("authorization_nonce"),
            },
            default_to_str=True,
        ).removeprefix("sha256:")[:24],
        "consumed_decision_id": decision_evidence.get("decision_id"),
        "decision_evidence_hash": decision_evidence.get("consumed_decision_evidence_hash"),
        "decision_consumption_evidence_hash": decision_evidence.get("current_evidence_hash"),
        "decision_replay_evidence_hash": decision_evidence.get("decision_replay_evidence_hash"),
        "decision_replay_result": decision_evidence.get("decision_replay_result"),
        "correlation_id": request.get("correlation_id"),
        "request_hash": _request_hash(request),
        "policy_id": request.get("policy_id"),
        "policy_version": request.get("policy_version"),
        "policy_hash": request.get("policy_hash"),
        "human_policy_authority_reference": decision_evidence.get("authority_state_reference"),
        "subject_id": execution_contract.get("subject_id"),
        "agent_id": execution_contract.get("agent_id"),
        "action_id": execution_contract.get("action_id"),
        "tool_id": execution_contract.get("tool_id"),
        "resource_id": execution_contract.get("resource_id"),
        "target_id": execution_contract.get("target_id"),
        "parameter_hash": execution_contract.get("parameter_hash"),
        "purpose": execution_contract.get("purpose"),
        "issued_at": timestamp,
        "expires_at": execution_contract.get("expires_at"),
        "authorization_nonce_hash": sha256_reference({"authorization_nonce": execution_contract.get("authorization_nonce")}),
    }
    payload["execution_authorization_hash"] = sha256_reference(_execution_authorization_hash_payload(payload), default_to_str=True)
    return payload


def _execution_authorization_hash_payload(authorization: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "execution_authorization_schema_version": authorization.get("execution_authorization_schema_version"),
        "execution_authorization_result": authorization.get("execution_authorization_result"),
        "execution_authorization_validation_result": authorization.get("execution_authorization_validation_result"),
        "authorization_id": authorization.get("authorization_id"),
        "consumed_decision_id": authorization.get("consumed_decision_id"),
        "decision_evidence_hash": authorization.get("decision_evidence_hash"),
        "decision_consumption_evidence_hash": authorization.get("decision_consumption_evidence_hash"),
        "decision_replay_evidence_hash": authorization.get("decision_replay_evidence_hash"),
        "decision_replay_result": authorization.get("decision_replay_result"),
        "correlation_id": authorization.get("correlation_id"),
        "request_hash": authorization.get("request_hash"),
        "policy_id": authorization.get("policy_id"),
        "policy_version": authorization.get("policy_version"),
        "policy_hash": authorization.get("policy_hash"),
        "human_policy_authority_reference": authorization.get("human_policy_authority_reference"),
        "subject_id": authorization.get("subject_id"),
        "agent_id": authorization.get("agent_id"),
        "action_id": authorization.get("action_id"),
        "tool_id": authorization.get("tool_id"),
        "resource_id": authorization.get("resource_id"),
        "target_id": authorization.get("target_id"),
        "parameter_hash": authorization.get("parameter_hash"),
        "purpose": authorization.get("purpose"),
        "issued_at": authorization.get("issued_at"),
        "expires_at": authorization.get("expires_at"),
        "authorization_nonce_hash": authorization.get("authorization_nonce_hash"),
    }


def _validate_governed_execution_authorization(
    authorization: Mapping[str, Any] | None,
    request: Mapping[str, Any] | None,
    execution_contract: Mapping[str, Any] | None,
    *,
    consumed_decision_evidence_hash: str | None,
    timestamp: str,
) -> str | None:
    if not isinstance(authorization, Mapping):
        return "EXEC_AUTH_MISSING"
    if _execution_authorization_contains_sensitive_data(authorization):
        return "EXEC_AUTH_MALFORMED"
    required = {
        "execution_authorization_schema_version",
        "execution_authorization_result",
        "execution_authorization_validation_result",
        "authorization_id",
        "consumed_decision_id",
        "decision_evidence_hash",
        "decision_consumption_evidence_hash",
        "decision_replay_result",
        "correlation_id",
        "request_hash",
        "policy_id",
        "policy_version",
        "policy_hash",
        "human_policy_authority_reference",
        "subject_id",
        "agent_id",
        "action_id",
        "tool_id",
        "resource_id",
        "target_id",
        "parameter_hash",
        "purpose",
        "issued_at",
        "expires_at",
        "authorization_nonce_hash",
        "execution_authorization_hash",
    }
    if any(field not in authorization for field in required):
        return "EXEC_AUTH_MALFORMED"
    if authorization.get("execution_authorization_schema_version") != EXECUTION_AUTHORIZATION_SCHEMA_VERSION:
        return "EXEC_AUTH_MALFORMED"
    if authorization.get("execution_authorization_result") != "ALLOW":
        return "EXEC_AUTH_DECISION_LINK_INVALID"
    if authorization.get("execution_authorization_validation_result") != "EXEC_AUTH_VALID":
        return "EXEC_AUTH_DECISION_LINK_INVALID"
    if authorization.get("decision_replay_result") != FIRST_CONSUMPTION:
        return "EXEC_AUTH_REUSED"
    if not isinstance(request, Mapping) or _validate_request(request):
        return "EXEC_AUTH_MALFORMED"
    if authorization.get("request_hash") != _request_hash(request):
        return "EXEC_AUTH_DECISION_LINK_INVALID"
    if authorization.get("correlation_id") != request.get("correlation_id"):
        return "EXEC_AUTH_DECISION_LINK_INVALID"
    for field in ("policy_id", "policy_version", "policy_hash"):
        if authorization.get(field) != request.get(field):
            return "EXEC_AUTH_POLICY_LINK_INVALID"
    if consumed_decision_evidence_hash is not None and authorization.get("decision_evidence_hash") != consumed_decision_evidence_hash:
        return "EXEC_AUTH_DECISION_LINK_INVALID"
    contract_error = _validate_execution_contract(execution_contract)
    if contract_error:
        return contract_error
    if not isinstance(execution_contract, Mapping):
        return "EXEC_AUTH_MISSING"
    comparisons = (
        ("subject_id", "EXEC_AUTH_SUBJECT_MISMATCH"),
        ("agent_id", "EXEC_AUTH_SUBJECT_MISMATCH"),
        ("action_id", "EXEC_AUTH_ACTION_MISMATCH"),
        ("tool_id", "EXEC_AUTH_ACTION_MISMATCH"),
        ("resource_id", "EXEC_AUTH_RESOURCE_MISMATCH"),
        ("target_id", "EXEC_AUTH_RESOURCE_MISMATCH"),
        ("parameter_hash", "EXEC_AUTH_PARAMETER_MISMATCH"),
        ("purpose", "EXEC_AUTH_PURPOSE_MISMATCH"),
        ("expires_at", "EXEC_AUTH_EXPIRED"),
    )
    for field, reason in comparisons:
        if authorization.get(field) != execution_contract.get(field):
            return reason
    expires_at, expires_error = _parse_utc_timestamp(str(authorization.get("expires_at")), "expires_at")
    evaluated_at, evaluated_error = _parse_utc_timestamp(timestamp, "evaluation")
    if expires_error or evaluated_error or expires_at is None or evaluated_at is None or evaluated_at >= expires_at:
        return "EXEC_AUTH_EXPIRED"
    auth_hash = authorization.get("execution_authorization_hash")
    if auth_hash != sha256_reference(_execution_authorization_hash_payload(authorization), default_to_str=True):
        return "EXEC_AUTH_TAMPERED"
    if not all(
        is_sha256_reference(authorization.get(field))
        for field in (
            "decision_evidence_hash",
            "decision_consumption_evidence_hash",
            "request_hash",
            "policy_hash",
            "human_policy_authority_reference",
            "parameter_hash",
            "authorization_nonce_hash",
        )
    ):
        return "EXEC_AUTH_MALFORMED"
    return None


def _allowed(
    request: Mapping[str, Any] | None,
    *,
    reason_code: str,
    timestamp: str,
    policy_id: str | None,
    policy_version: str | None,
    policy_hash: str | None,
    previous_evidence_hash: str,
    matched_rule_id: str | None = None,
    approved_policy_version: str | None = None,
    approved_policy_hash: str | None = None,
    authority_verification_result: str = "NOT_EVALUATED",
    authority_state_reference: str = ZERO_SHA256_REFERENCE,
    applicability_evidence: Mapping[str, Any] | None = None,
    obligation_evidence: Mapping[str, Any] | None = None,
) -> LivePolicyEvaluation:
    return _decision(
        ALLOW,
        request,
        reason_code=reason_code,
        timestamp=timestamp,
        policy_id=policy_id,
        policy_version=policy_version,
        policy_hash=policy_hash,
        previous_evidence_hash=previous_evidence_hash,
        matched_rule_id=matched_rule_id,
        approved_policy_version=approved_policy_version,
        approved_policy_hash=approved_policy_hash,
        authority_verification_result=authority_verification_result,
        authority_state_reference=authority_state_reference,
        applicability_evidence=applicability_evidence,
        obligation_evidence=obligation_evidence,
    )


def _blocked(
    request: Mapping[str, Any] | None,
    *,
    reason_code: str,
    timestamp: str,
    policy_id: str | None,
    policy_version: str | None,
    policy_hash: str | None,
    previous_evidence_hash: str,
    matched_rule_id: str | None = None,
    approved_policy_version: str | None = None,
    approved_policy_hash: str | None = None,
    authority_verification_result: str = "NOT_EVALUATED",
    authority_state_reference: str = ZERO_SHA256_REFERENCE,
    applicability_evidence: Mapping[str, Any] | None = None,
    obligation_evidence: Mapping[str, Any] | None = None,
) -> LivePolicyEvaluation:
    return _decision(
        BLOCK,
        request,
        reason_code=reason_code,
        timestamp=timestamp,
        policy_id=policy_id,
        policy_version=policy_version,
        policy_hash=policy_hash,
        previous_evidence_hash=previous_evidence_hash,
        matched_rule_id=matched_rule_id,
        approved_policy_version=approved_policy_version,
        approved_policy_hash=approved_policy_hash,
        authority_verification_result=authority_verification_result,
        authority_state_reference=authority_state_reference,
        applicability_evidence=applicability_evidence,
        obligation_evidence=obligation_evidence,
    )


def _decision(
    decision: str,
    request: Mapping[str, Any] | None,
    *,
    reason_code: str,
    timestamp: str,
    policy_id: str | None,
    policy_version: str | None,
    policy_hash: str | None,
    previous_evidence_hash: str,
    matched_rule_id: str | None,
    approved_policy_version: str | None,
    approved_policy_hash: str | None,
    authority_verification_result: str,
    authority_state_reference: str,
    applicability_evidence: Mapping[str, Any] | None = None,
    obligation_evidence: Mapping[str, Any] | None = None,
) -> LivePolicyEvaluation:
    correlation_id = _request_field(request, "correlation_id")
    applicability = {
        "applicability_verification_result": "NOT_EVALUATED",
        "matched_jurisdiction_reference": ZERO_SHA256_REFERENCE,
        "matched_policy_scope_reference": ZERO_SHA256_REFERENCE,
        "matched_use_case_reference": ZERO_SHA256_REFERENCE,
        "policy_effective_from": None,
        "policy_effective_until": None,
        "evaluation_timestamp": timestamp,
    }
    if applicability_evidence is not None:
        applicability.update(applicability_evidence)
    obligations = {
        "obligation_verification_result": "NOT_EVALUATED",
        "obligations_evaluated_count": 0,
        "required_obligation_references": [],
        "satisfied_obligation_references": [],
        "obligation_state_reference": ZERO_SHA256_REFERENCE,
    }
    if obligation_evidence is not None:
        obligations.update(obligation_evidence)
    decision_trace = _decision_trace(
        decision=decision,
        reason_code=reason_code,
        request=request,
        timestamp=timestamp,
        policy_id=policy_id,
        policy_version=policy_version,
        policy_hash=policy_hash,
        previous_evidence_hash=previous_evidence_hash,
        authority_verification_result=authority_verification_result,
        authority_state_reference=authority_state_reference,
        applicability=applicability,
        obligations=obligations,
    )
    base = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": timestamp,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "policy_hash": policy_hash,
        "requested_policy_version": _request_field(request, "policy_version"),
        "approved_policy_version": approved_policy_version,
        "requested_policy_hash": _request_field(request, "policy_hash"),
        "approved_policy_hash": approved_policy_hash,
        "authority_verification_result": authority_verification_result,
        "authority_state_reference": authority_state_reference,
        **applicability,
        **obligations,
        **decision_trace,
        "result": decision,
        "reason_code": reason_code,
        "correlation_id": correlation_id,
        "request_hash": _request_hash(request),
        "input_metadata_hash": _input_hash(request),
        "matched_rule_id": matched_rule_id,
        "previous_evidence_hash": previous_evidence_hash,
        "decision_evidence_valid_until": applicability.get("policy_effective_until"),
        "evidence_mode": "hash-only-redacted",
        "hash_algorithm": "sha256",
        "redacted": True,
        "execution_authorized": False,
        "provider_execution": False,
        "production_activation": False,
        "deployment_authorized": False,
    }
    decision_id = "ai-act-live-policy-" + sha256_reference(base).removeprefix("sha256:")[:24]
    evidence_payload = {**base, "decision_id": decision_id}
    current_evidence_hash = sha256_reference(evidence_payload)
    evidence = {**evidence_payload, "current_evidence_hash": current_evidence_hash}
    return LivePolicyEvaluation(
        decision=decision,
        reason_code=reason_code,
        decision_id=decision_id,
        timestamp=timestamp,
        policy_id=policy_id,
        policy_version=policy_version,
        policy_hash=policy_hash,
        correlation_id=correlation_id,
        evidence=evidence,
    )


def _decision_trace(
    *,
    decision: str,
    reason_code: str,
    request: Mapping[str, Any] | None,
    timestamp: str,
    policy_id: str | None,
    policy_version: str | None,
    policy_hash: str | None,
    previous_evidence_hash: str,
    authority_verification_result: str,
    authority_state_reference: str,
    applicability: Mapping[str, Any],
    obligations: Mapping[str, Any],
) -> dict[str, Any]:
    authority_trace = sha256_reference(
        {
            "authority_verification_result": authority_verification_result,
            "authority_state_reference": authority_state_reference,
        },
        default_to_str=True,
    )
    applicability_trace = sha256_reference(
        {
            "applicability_verification_result": applicability.get("applicability_verification_result"),
            "matched_jurisdiction_reference": applicability.get("matched_jurisdiction_reference"),
            "matched_policy_scope_reference": applicability.get("matched_policy_scope_reference"),
            "matched_use_case_reference": applicability.get("matched_use_case_reference"),
        },
        default_to_str=True,
    )
    temporal_trace = sha256_reference(
        {
            "applicability_verification_result": applicability.get("applicability_verification_result"),
            "policy_effective_from": applicability.get("policy_effective_from"),
            "policy_effective_until": applicability.get("policy_effective_until"),
            "evaluation_timestamp": timestamp,
        },
        default_to_str=True,
    )
    obligation_trace = sha256_reference(
        {
            "obligation_verification_result": obligations.get("obligation_verification_result"),
            "required_obligation_references": obligations.get("required_obligation_references"),
            "satisfied_obligation_references": obligations.get("satisfied_obligation_references"),
            "obligation_state_reference": obligations.get("obligation_state_reference"),
        },
        default_to_str=True,
    )
    execution_precondition_trace = sha256_reference(
        {
            "obligation_verification_result": obligations.get("obligation_verification_result"),
            "obligation_state_reference": obligations.get("obligation_state_reference"),
        },
        default_to_str=True,
    )
    trace = {
        "decision_trace_schema_version": DECISION_TRACE_SCHEMA_VERSION,
        "decision_trace_result_reference": sha256_reference({"decision": decision, "reason_code": reason_code}),
        "decision_trace_request_reference": _request_hash(request),
        "decision_trace_correlation_reference": sha256_reference({"correlation_id": _request_field(request, "correlation_id")}),
        "decision_trace_policy_reference": sha256_reference(
            {
                "policy_id": policy_id,
                "policy_version": policy_version,
                "policy_hash": policy_hash,
            },
            default_to_str=True,
        ),
        "decision_trace_previous_evidence_hash": previous_evidence_hash,
        "authority_trace_reference": authority_trace,
        "applicability_trace_reference": applicability_trace,
        "temporal_effectivity_trace_reference": temporal_trace,
        "obligation_trace_reference": obligation_trace,
        "execution_precondition_trace_reference": execution_precondition_trace,
    }
    trace["decision_trace_hash"] = sha256_reference(trace, default_to_str=True)
    return trace


def _decision_consumption_block(
    request: Mapping[str, Any] | None,
    *,
    reason_code: str,
    timestamp: str,
    previous_evidence_hash: str,
    replay_evidence: Mapping[str, Any] | None = None,
) -> LivePolicyEvaluation:
    applicability_evidence = {
        "decision_consumption_schema_version": DECISION_CONSUMPTION_SCHEMA_VERSION,
        "consumption_attempt_reference": sha256_reference(
            {
                "request_hash": _request_hash(request),
                "reason_code": reason_code,
                "timestamp": timestamp,
            },
            default_to_str=True,
        ),
    }
    if replay_evidence is not None:
        applicability_evidence.update(replay_evidence)
    return _blocked(
        request,
        reason_code=reason_code,
        timestamp=timestamp,
        policy_id=_request_field(request, "policy_id"),
        policy_version=_request_field(request, "policy_version"),
        policy_hash=_request_field(request, "policy_hash"),
        previous_evidence_hash=previous_evidence_hash,
        authority_verification_result=reason_code,
        authority_state_reference=ZERO_SHA256_REFERENCE,
        applicability_evidence=applicability_evidence,
    )


def _decision_consumption_replay_key(
    *,
    request: Mapping[str, Any],
    decision_evidence: Mapping[str, Any],
    authority: PolicyAuthority,
    applicability_evidence: Mapping[str, Any],
    obligation_evidence: Mapping[str, Any],
) -> str:
    return sha256_reference(
        {
            "schema_version": DECISION_REPLAY_SCHEMA_VERSION,
            "decision_evidence_hash": decision_evidence.get("current_evidence_hash"),
            "decision_id": decision_evidence.get("decision_id"),
            "request_hash": _request_hash(request),
            "correlation_id": request.get("correlation_id"),
            "policy_id": authority.policy_id,
            "policy_version": authority.policy_version,
            "policy_hash": authority.policy_hash,
            "authority_state_reference": _authority_state_reference(authority),
            "applicability_trace_reference": decision_evidence.get("applicability_trace_reference"),
            "temporal_effectivity_trace_reference": decision_evidence.get("temporal_effectivity_trace_reference"),
            "obligation_state_reference": obligation_evidence.get("obligation_state_reference"),
            "execution_precondition_trace_reference": decision_evidence.get("execution_precondition_trace_reference"),
            "policy_effective_until": applicability_evidence.get("policy_effective_until"),
        },
        default_to_str=True,
    )


def _decision_consumption_retention_seconds(evidence: Mapping[str, Any], timestamp: str) -> int | None:
    valid_until = evidence.get("decision_evidence_valid_until")
    if valid_until is None:
        return None
    valid_until_at, valid_until_error = _parse_utc_timestamp(valid_until if isinstance(valid_until, str) else "", "effective_until")
    consumed_at, consumed_error = _parse_utc_timestamp(timestamp, "evaluation")
    if valid_until_error or consumed_error or valid_until_at is None or consumed_at is None:
        return None
    seconds = int((valid_until_at - consumed_at).total_seconds())
    if seconds <= 0:
        return None
    return seconds


def _replay_evidence(
    *,
    result: str,
    replay_key_hash: str,
    decision_evidence: Mapping[str, Any],
    request: Mapping[str, Any] | None,
    store_type: str,
    timestamp: str,
    retention_seconds: int | None = None,
) -> dict[str, Any]:
    payload = {
        "decision_replay_schema_version": DECISION_REPLAY_SCHEMA_VERSION,
        "decision_replay_result": result,
        "replay_key_hash": replay_key_hash,
        "consumed_decision_evidence_hash": decision_evidence.get("current_evidence_hash"),
        "decision_replay_request_reference": _request_hash(request),
        "decision_replay_correlation_reference": sha256_reference({"correlation_id": _request_field(request, "correlation_id")}),
        "decision_replay_policy_reference": sha256_reference(
            {
                "policy_id": _request_field(request, "policy_id"),
                "policy_version": _request_field(request, "policy_version"),
                "policy_hash": _request_field(request, "policy_hash"),
            },
            default_to_str=True,
        ),
        "decision_replay_store_type": store_type,
        "decision_replay_timestamp": timestamp,
        "decision_replay_retention_seconds": retention_seconds,
    }
    payload["decision_replay_evidence_hash"] = sha256_reference(payload, default_to_str=True)
    return payload


def _validate_decision_evidence_integrity(evidence: Mapping[str, Any]) -> str | None:
    required = {
        "schema_version",
        "decision_trace_schema_version",
        "result",
        "reason_code",
        "timestamp",
        "policy_id",
        "policy_version",
        "policy_hash",
        "correlation_id",
        "request_hash",
        "current_evidence_hash",
        "previous_evidence_hash",
        "decision_evidence_valid_until",
        "decision_trace_hash",
        "decision_trace_result_reference",
        "decision_trace_correlation_reference",
        "decision_trace_request_reference",
        "decision_trace_policy_reference",
        "authority_trace_reference",
        "applicability_trace_reference",
        "temporal_effectivity_trace_reference",
        "obligation_trace_reference",
        "execution_precondition_trace_reference",
        "authority_state_reference",
        "applicability_verification_result",
        "obligation_verification_result",
        "obligation_state_reference",
        "matched_jurisdiction_reference",
        "matched_policy_scope_reference",
        "matched_use_case_reference",
        "policy_effective_from",
        "matched_rule_id",
    }
    if any(field not in evidence for field in required):
        return "DECISION_EVIDENCE_MALFORMED"
    if evidence.get("schema_version") != SCHEMA_VERSION:
        return "DECISION_EVIDENCE_UNSUPPORTED"
    if evidence.get("decision_trace_schema_version") != DECISION_TRACE_SCHEMA_VERSION:
        return "DECISION_EVIDENCE_UNSUPPORTED"
    hash_fields = {
        "current_evidence_hash",
        "previous_evidence_hash",
        "decision_trace_hash",
        "decision_trace_result_reference",
        "decision_trace_correlation_reference",
        "decision_trace_request_reference",
        "decision_trace_policy_reference",
        "authority_trace_reference",
        "applicability_trace_reference",
        "temporal_effectivity_trace_reference",
        "obligation_trace_reference",
        "execution_precondition_trace_reference",
        "authority_state_reference",
        "request_hash",
        "input_metadata_hash",
        "obligation_state_reference",
        "matched_jurisdiction_reference",
        "matched_policy_scope_reference",
        "matched_use_case_reference",
    }
    for field in hash_fields:
        if field in evidence and not is_sha256_reference(evidence.get(field)):
            return "DECISION_EVIDENCE_INTEGRITY_FAILED"
    payload = dict(evidence)
    current_evidence_hash = payload.pop("current_evidence_hash", None)
    if current_evidence_hash != sha256_reference(payload):
        return "DECISION_EVIDENCE_INTEGRITY_FAILED"
    trace = {
        "decision_trace_schema_version": evidence.get("decision_trace_schema_version"),
        "decision_trace_result_reference": evidence.get("decision_trace_result_reference"),
        "decision_trace_request_reference": evidence.get("decision_trace_request_reference"),
        "decision_trace_correlation_reference": evidence.get("decision_trace_correlation_reference"),
        "decision_trace_policy_reference": evidence.get("decision_trace_policy_reference"),
        "decision_trace_previous_evidence_hash": evidence.get("decision_trace_previous_evidence_hash"),
        "authority_trace_reference": evidence.get("authority_trace_reference"),
        "applicability_trace_reference": evidence.get("applicability_trace_reference"),
        "temporal_effectivity_trace_reference": evidence.get("temporal_effectivity_trace_reference"),
        "obligation_trace_reference": evidence.get("obligation_trace_reference"),
        "execution_precondition_trace_reference": evidence.get("execution_precondition_trace_reference"),
    }
    if evidence.get("decision_trace_hash") != sha256_reference(trace, default_to_str=True):
        return "DECISION_EVIDENCE_INTEGRITY_FAILED"
    if evidence.get("decision_trace_previous_evidence_hash") != evidence.get("previous_evidence_hash"):
        return "DECISION_EVIDENCE_CHAIN_INVALID"
    return None


def _validate_decision_evidence_binding(evidence: Mapping[str, Any], request: Mapping[str, Any]) -> str | None:
    if evidence.get("request_hash") != _request_hash(request):
        return "DECISION_BINDING_MISMATCH"
    if evidence.get("decision_trace_request_reference") != _request_hash(request):
        return "DECISION_BINDING_MISMATCH"
    if evidence.get("correlation_id") != request.get("correlation_id"):
        return "DECISION_BINDING_MISMATCH"
    if evidence.get("policy_id") != request.get("policy_id"):
        return "DECISION_BINDING_MISMATCH"
    if evidence.get("policy_version") != request.get("policy_version"):
        return "DECISION_BINDING_MISMATCH"
    if evidence.get("policy_hash") != request.get("policy_hash"):
        return "DECISION_BINDING_MISMATCH"
    if evidence.get("approved_policy_version") != request.get("policy_version"):
        return "DECISION_BINDING_MISMATCH"
    if evidence.get("approved_policy_hash") != request.get("policy_hash"):
        return "DECISION_BINDING_MISMATCH"
    policy_reference = sha256_reference(
        {
            "policy_id": request.get("policy_id"),
            "policy_version": request.get("policy_version"),
            "policy_hash": request.get("policy_hash"),
        },
        default_to_str=True,
    )
    if evidence.get("decision_trace_policy_reference") != policy_reference:
        return "DECISION_BINDING_MISMATCH"
    return None


def _validate_applicability_consumption_binding(
    evidence: Mapping[str, Any],
    current: Mapping[str, Any],
) -> str | None:
    fields = (
        "applicability_verification_result",
        "matched_jurisdiction_reference",
        "matched_policy_scope_reference",
        "matched_use_case_reference",
        "policy_effective_from",
        "policy_effective_until",
    )
    for field in fields:
        if evidence.get(field) != current.get(field):
            if field in {"policy_effective_from", "policy_effective_until"}:
                return "DECISION_TEMPORAL_INVALID"
            return "DECISION_APPLICABILITY_INVALID"
    return None


def _validate_obligation_consumption_binding(
    evidence: Mapping[str, Any],
    current: Mapping[str, Any],
) -> str | None:
    fields = (
        "obligation_verification_result",
        "obligations_evaluated_count",
        "required_obligation_references",
        "satisfied_obligation_references",
        "obligation_state_reference",
    )
    for field in fields:
        if evidence.get(field) != current.get(field):
            return "DECISION_OBLIGATION_INVALID"
    return None


def _decision_evidence_expired(evidence: Mapping[str, Any], timestamp: str) -> bool:
    valid_until = evidence.get("decision_evidence_valid_until")
    if valid_until is None:
        return False
    if not isinstance(valid_until, str):
        return True
    effective_until_at, effective_until_error = _parse_utc_timestamp(valid_until, "effective_until")
    evaluated_at, evaluated_error = _parse_utc_timestamp(timestamp, "evaluation")
    if effective_until_error or evaluated_error or effective_until_at is None or evaluated_at is None:
        return True
    return evaluated_at >= effective_until_at


def _decision_authority_reason(reason_code: str) -> str:
    mapping = {
        "POLICY_AUTHORITY_UNAVAILABLE": "DECISION_AUTHORITY_INVALID",
        "POLICY_AUTHORITY_AMBIGUOUS": "DECISION_AUTHORITY_INVALID",
        "POLICY_APPROVAL_EVIDENCE_MISSING": "DECISION_AUTHORITY_INVALID",
        "POLICY_APPROVAL_EVIDENCE_INVALID": "DECISION_AUTHORITY_INVALID",
        "POLICY_REVOKED": "DECISION_POLICY_REVOKED",
        "POLICY_SUPERSEDED": "DECISION_POLICY_SUPERSEDED",
        "POLICY_ID_MISMATCH": "DECISION_BINDING_MISMATCH",
        "POLICY_VERSION_MISMATCH": "DECISION_BINDING_MISMATCH",
        "POLICY_HASH_MISMATCH": "DECISION_BINDING_MISMATCH",
    }
    return mapping.get(reason_code, "DECISION_AUTHORITY_INVALID")


def _decision_applicability_reason(reason_code: str) -> str:
    if reason_code in {"POLICY_NOT_YET_EFFECTIVE", "POLICY_EXPIRED", "EFFECTIVE_FROM_MALFORMED", "EFFECTIVE_UNTIL_MALFORMED"}:
        return "DECISION_TEMPORAL_INVALID"
    return "DECISION_APPLICABILITY_INVALID"


def _decision_obligation_reason(reason_code: str) -> str:
    if reason_code == "EXECUTION_PRECONDITION_UNPROVEN":
        return "DECISION_PRECONDITION_INVALID"
    return "DECISION_OBLIGATION_INVALID"


def _coerce_policy_authority(authority: PolicyAuthority | Mapping[str, Any]) -> PolicyAuthority:
    if isinstance(authority, PolicyAuthority):
        return authority
    if not isinstance(authority, Mapping):
        raise ValueError("POLICY_AUTHORITY_MALFORMED")
    return PolicyAuthority(
        policy_id=str(authority.get("policy_id", "")),
        policy_version=str(authority.get("policy_version", "")),
        policy_hash=str(authority.get("policy_hash", "")),
        approved=authority.get("approved") is True,
        policy_document=authority.get("policy_document", {}),
        source=str(authority.get("source", "")),
        approval_evidence_present=authority.get("approval_evidence_present") is True,
        approval_evidence_valid=authority.get("approval_evidence_valid") is True,
        revoked=authority.get("revoked") is True,
        superseded=authority.get("superseded") is True,
        superseded_by_policy_version=_optional_str(authority.get("superseded_by_policy_version")),
        ambiguous=authority.get("ambiguous") is True,
        authority_available=authority.get("authority_available", True) is True,
        authority_state=str(authority.get("authority_state", "CURRENT")),
        authority_state_reference=_optional_str(authority.get("authority_state_reference")),
        applicability=authority.get("applicability") if isinstance(authority.get("applicability"), Mapping) else None,
        applicability_available=authority.get("applicability_available", True) is True,
        applicability_ambiguous=authority.get("applicability_ambiguous") is True,
    )


def _validate_request(request: Mapping[str, Any] | None) -> str | None:
    if not isinstance(request, Mapping):
        return "REQUEST_MALFORMED"
    if _contains_sensitive_data(request):
        return "SENSITIVE_DATA_REJECTED"
    if "policy_id" not in request:
        return "POLICY_ID_MISSING"
    if "policy_version" not in request:
        return "POLICY_VERSION_MISSING"
    if "policy_hash" not in request:
        return "POLICY_HASH_MISSING"
    missing = sorted(field for field in REQUIRED_REQUEST_FIELDS if field not in request)
    if missing:
        return "REQUEST_REQUIRED_FIELD_MISSING"
    for field in REQUIRED_REQUEST_FIELDS - {"input_metadata"}:
        if not isinstance(request.get(field), str) or not request.get(field):
            return "REQUEST_MALFORMED"
    if not isinstance(request.get("input_metadata"), Mapping):
        return "REQUEST_MALFORMED"
    if _contains_policy_authoring_attempt(request):
        return "AUTONOMOUS_POLICY_AUTHORITY_BLOCKED"
    if not is_sha256_reference(request.get("policy_hash")):
        return "POLICY_HASH_MALFORMED"
    return None


def _validate_policy_authority(authority: PolicyAuthority, request: Mapping[str, Any]) -> str | None:
    if not authority.authority_available:
        return "POLICY_AUTHORITY_UNAVAILABLE"
    if authority.ambiguous:
        return "POLICY_AUTHORITY_AMBIGUOUS"
    if not authority.approval_evidence_present:
        return "POLICY_APPROVAL_EVIDENCE_MISSING"
    if not authority.approval_evidence_valid:
        return "POLICY_APPROVAL_EVIDENCE_INVALID"
    if authority.revoked:
        return "POLICY_REVOKED"
    if authority.superseded or authority.superseded_by_policy_version:
        return "POLICY_SUPERSEDED"
    if authority.authority_state != "CURRENT":
        return "POLICY_AUTHORITY_STATE_UNSUPPORTED"
    if not authority.approved:
        return "POLICY_NOT_HUMAN_APPROVED"
    if not isinstance(authority.policy_document, Mapping):
        return "POLICY_MALFORMED"
    if not authority.policy_id or not authority.policy_version or not authority.policy_hash:
        return "POLICY_IDENTITY_MISSING"
    if not is_sha256_reference(authority.policy_hash):
        return "POLICY_HASH_UNVERIFIABLE"
    if authority.policy_id != request["policy_id"]:
        return "POLICY_ID_MISMATCH"
    if authority.policy_version != request["policy_version"]:
        return "POLICY_VERSION_MISMATCH"
    if authority.policy_hash != request["policy_hash"]:
        return "POLICY_HASH_MISMATCH"
    return None


def _authority_state_reference(authority: PolicyAuthority) -> str:
    if authority.authority_state_reference:
        return authority.authority_state_reference
    return sha256_reference(
        {
            "source": authority.source,
            "policy_id": authority.policy_id,
            "policy_version": authority.policy_version,
            "policy_hash": authority.policy_hash,
            "approved": authority.approved,
            "approval_evidence_present": authority.approval_evidence_present,
            "approval_evidence_valid": authority.approval_evidence_valid,
            "revoked": authority.revoked,
            "superseded": authority.superseded,
            "superseded_by_policy_version": authority.superseded_by_policy_version,
            "ambiguous": authority.ambiguous,
            "authority_available": authority.authority_available,
            "authority_state": authority.authority_state,
            "applicability_available": authority.applicability_available,
            "applicability_ambiguous": authority.applicability_ambiguous,
            "applicability_reference": sha256_reference(authority.applicability, default_to_str=True)
            if authority.applicability is not None
            else ZERO_SHA256_REFERENCE,
        },
        default_to_str=True,
    )


def _validate_applicability_and_effectivity(
    authority: PolicyAuthority,
    request: Mapping[str, Any],
    timestamp: str,
) -> tuple[str | None, dict[str, Any]]:
    evidence = {
        "applicability_verification_result": "NOT_EVALUATED",
        "matched_jurisdiction_reference": ZERO_SHA256_REFERENCE,
        "matched_policy_scope_reference": ZERO_SHA256_REFERENCE,
        "matched_use_case_reference": ZERO_SHA256_REFERENCE,
        "policy_effective_from": None,
        "policy_effective_until": None,
        "evaluation_timestamp": timestamp,
    }
    if not authority.applicability_available:
        evidence["applicability_verification_result"] = "POLICY_APPLICABILITY_UNAVAILABLE"
        return "POLICY_APPLICABILITY_UNAVAILABLE", evidence
    if authority.applicability_ambiguous:
        evidence["applicability_verification_result"] = "POLICY_APPLICABILITY_AMBIGUOUS"
        return "POLICY_APPLICABILITY_AMBIGUOUS", evidence

    applicability = _policy_applicability(authority)
    if not isinstance(applicability, Mapping) or not applicability:
        evidence["applicability_verification_result"] = "POLICY_APPLICABILITY_MISSING"
        return "POLICY_APPLICABILITY_MISSING", evidence

    jurisdiction = _request_field(request, "jurisdiction")
    if jurisdiction is None:
        evidence["applicability_verification_result"] = "JURISDICTION_MISSING"
        return "JURISDICTION_MISSING", evidence
    jurisdictions = _non_empty_str_set(applicability.get("jurisdictions"))
    if not jurisdictions:
        evidence["applicability_verification_result"] = "POLICY_JURISDICTION_MISSING"
        return "POLICY_JURISDICTION_MISSING", evidence
    if jurisdiction not in jurisdictions:
        evidence["applicability_verification_result"] = "JURISDICTION_MISMATCH"
        return "JURISDICTION_MISMATCH", evidence
    evidence["matched_jurisdiction_reference"] = sha256_reference({"jurisdiction": jurisdiction})

    policy_scope = _request_field(request, "policy_scope")
    if policy_scope is None:
        evidence["applicability_verification_result"] = "POLICY_SCOPE_MISSING"
        return "POLICY_SCOPE_MISSING", evidence
    policy_scopes = _non_empty_str_set(applicability.get("policy_scopes"))
    if not policy_scopes:
        evidence["applicability_verification_result"] = "POLICY_SCOPE_METADATA_MISSING"
        return "POLICY_SCOPE_METADATA_MISSING", evidence
    if policy_scope not in policy_scopes:
        evidence["applicability_verification_result"] = "POLICY_SCOPE_MISMATCH"
        return "POLICY_SCOPE_MISMATCH", evidence
    evidence["matched_policy_scope_reference"] = sha256_reference({"policy_scope": policy_scope})

    use_case = _use_case_classification(request)
    if use_case is None:
        evidence["applicability_verification_result"] = "USE_CASE_CLASSIFICATION_MISSING"
        return "USE_CASE_CLASSIFICATION_MISSING", evidence
    use_cases = _non_empty_str_set(applicability.get("use_case_classifications"))
    if not use_cases:
        evidence["applicability_verification_result"] = "USE_CASE_METADATA_MISSING"
        return "USE_CASE_METADATA_MISSING", evidence
    if use_case not in use_cases:
        evidence["applicability_verification_result"] = "USE_CASE_CLASSIFICATION_MISMATCH"
        return "USE_CASE_CLASSIFICATION_MISMATCH", evidence
    evidence["matched_use_case_reference"] = sha256_reference({"use_case_classification": use_case})

    evaluated_at, timestamp_error = _parse_utc_timestamp(timestamp, "evaluation")
    if timestamp_error:
        evidence["applicability_verification_result"] = timestamp_error
        return timestamp_error, evidence

    effective_from = applicability.get("effective_from")
    if not isinstance(effective_from, str) or not effective_from:
        evidence["applicability_verification_result"] = "EFFECTIVE_FROM_MISSING"
        return "EFFECTIVE_FROM_MISSING", evidence
    effective_from_at, effective_from_error = _parse_utc_timestamp(effective_from, "effective_from")
    if effective_from_error:
        evidence["applicability_verification_result"] = effective_from_error
        return effective_from_error, evidence
    evidence["policy_effective_from"] = effective_from
    if evaluated_at < effective_from_at:
        evidence["applicability_verification_result"] = "POLICY_NOT_YET_EFFECTIVE"
        return "POLICY_NOT_YET_EFFECTIVE", evidence

    effective_until = applicability.get("effective_until")
    if effective_until is not None:
        if not isinstance(effective_until, str) or not effective_until:
            evidence["applicability_verification_result"] = "EFFECTIVE_UNTIL_MALFORMED"
            return "EFFECTIVE_UNTIL_MALFORMED", evidence
        effective_until_at, effective_until_error = _parse_utc_timestamp(effective_until, "effective_until")
        if effective_until_error:
            evidence["applicability_verification_result"] = effective_until_error
            return effective_until_error, evidence
        evidence["policy_effective_until"] = effective_until
        if evaluated_at >= effective_until_at:
            evidence["applicability_verification_result"] = "POLICY_EXPIRED"
            return "POLICY_EXPIRED", evidence

    evidence["applicability_verification_result"] = "POLICY_APPLICABILITY_EFFECTIVITY_VERIFIED"
    return None, evidence


def _validate_policy_obligations(
    authority: PolicyAuthority,
    request: Mapping[str, Any],
    timestamp: str,
) -> tuple[str | None, dict[str, Any]]:
    evidence = {
        "obligation_verification_result": "NOT_EVALUATED",
        "obligations_evaluated_count": 0,
        "required_obligation_references": [],
        "satisfied_obligation_references": [],
        "obligation_state_reference": ZERO_SHA256_REFERENCE,
    }
    obligations = _policy_obligations(authority)
    if not isinstance(obligations, Sequence) or isinstance(obligations, (str, bytes)) or not obligations:
        evidence["obligation_verification_result"] = "POLICY_OBLIGATIONS_MISSING"
        return "POLICY_OBLIGATIONS_MISSING", evidence

    satisfaction_records = request.get("obligation_satisfaction")
    if not isinstance(satisfaction_records, Sequence) or isinstance(satisfaction_records, (str, bytes)):
        evidence["obligation_verification_result"] = "OBLIGATION_SATISFACTION_EVIDENCE_MISSING"
        return "OBLIGATION_SATISFACTION_EVIDENCE_MISSING", evidence

    context_hash = _execution_context_hash(request)
    required_references: list[str] = []
    satisfied_references: list[str] = []
    evaluated_count = 0
    for obligation in obligations:
        if not isinstance(obligation, Mapping):
            evidence["obligation_verification_result"] = "POLICY_OBLIGATION_MALFORMED"
            return "POLICY_OBLIGATION_MALFORMED", evidence
        obligation_id = _optional_str(obligation.get("obligation_id"))
        obligation_type = _optional_str(obligation.get("obligation_type"))
        if obligation_id is None or obligation_type is None or obligation.get("required") is not True:
            evidence["obligation_verification_result"] = "POLICY_OBLIGATION_MALFORMED"
            return "POLICY_OBLIGATION_MALFORMED", evidence
        if obligation_type not in SUPPORTED_OBLIGATION_TYPES:
            evidence["obligation_verification_result"] = "POLICY_OBLIGATION_TYPE_UNKNOWN"
            return "POLICY_OBLIGATION_TYPE_UNKNOWN", evidence

        evaluated_count += 1
        obligation_ref = sha256_reference(
            {
                "obligation_id": obligation_id,
                "obligation_type": obligation_type,
                "policy_id": authority.policy_id,
                "policy_version": authority.policy_version,
                "policy_hash": authority.policy_hash,
            }
        )
        required_references.append(obligation_ref)
        match = _matching_obligation_satisfaction(
            satisfaction_records,
            obligation_id=obligation_id,
            obligation_type=obligation_type,
            authority=authority,
            request=request,
        )
        if match is None:
            evidence.update(
                {
                    "obligation_verification_result": "REQUIRED_OBLIGATION_UNSATISFIED",
                    "obligations_evaluated_count": evaluated_count,
                    "required_obligation_references": required_references,
                    "satisfied_obligation_references": satisfied_references,
                }
            )
            return "REQUIRED_OBLIGATION_UNSATISFIED", evidence

        record_error = _validate_obligation_satisfaction_record(
            match,
            obligation=obligation,
            authority=authority,
            request=request,
            timestamp=timestamp,
            execution_context_hash=context_hash,
        )
        if record_error:
            evidence.update(
                {
                    "obligation_verification_result": record_error,
                    "obligations_evaluated_count": evaluated_count,
                    "required_obligation_references": required_references,
                    "satisfied_obligation_references": satisfied_references,
                }
            )
            return record_error, evidence
        satisfied_references.append(
            sha256_reference(
                {
                    "obligation_reference": obligation_ref,
                    "evidence_hash": match.get("evidence_hash"),
                    "authority_state": match.get("authority_state"),
                    "execution_context_hash": match.get("execution_context_hash"),
                },
                default_to_str=True,
            )
        )

    evidence.update(
        {
            "obligation_verification_result": "POLICY_OBLIGATIONS_VERIFIED",
            "obligations_evaluated_count": evaluated_count,
            "required_obligation_references": required_references,
            "satisfied_obligation_references": satisfied_references,
            "obligation_state_reference": sha256_reference(
                {
                    "policy_id": authority.policy_id,
                    "policy_version": authority.policy_version,
                    "policy_hash": authority.policy_hash,
                    "authority_state": authority.authority_state,
                    "required_obligation_references": required_references,
                    "satisfied_obligation_references": satisfied_references,
                    "execution_context_hash": context_hash,
                },
                default_to_str=True,
            ),
        }
    )
    return None, evidence


def _policy_obligations(authority: PolicyAuthority) -> Sequence[Any] | None:
    policy = authority.policy_document
    engine_policy = policy.get("ai_act_live_policy_engine")
    if isinstance(engine_policy, Mapping):
        return engine_policy.get("obligations")
    return None


def _matching_obligation_satisfaction(
    satisfaction_records: Sequence[Any],
    *,
    obligation_id: str,
    obligation_type: str,
    authority: PolicyAuthority,
    request: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    for record in satisfaction_records:
        if not isinstance(record, Mapping):
            return record
        if record.get("obligation_id") == obligation_id and record.get("obligation_type") == obligation_type:
            return record
    return None


def _validate_obligation_satisfaction_record(
    record: Mapping[str, Any],
    *,
    obligation: Mapping[str, Any],
    authority: PolicyAuthority,
    request: Mapping[str, Any],
    timestamp: str,
    execution_context_hash: str,
) -> str | None:
    if not isinstance(record, Mapping):
        return "OBLIGATION_EVIDENCE_MALFORMED"
    if record.get("state") == "AMBIGUOUS" or record.get("ambiguous") is True:
        return "OBLIGATION_STATE_AMBIGUOUS"
    if record.get("state") != "SATISFIED":
        return "REQUIRED_OBLIGATION_UNSATISFIED"
    if record.get("request_id") != request.get("request_id"):
        return "OBLIGATION_REQUEST_MISMATCH"
    if record.get("policy_id") != authority.policy_id:
        return "OBLIGATION_POLICY_ID_MISMATCH"
    if record.get("policy_version") != authority.policy_version:
        return "OBLIGATION_POLICY_VERSION_MISMATCH"
    if record.get("policy_hash") != authority.policy_hash:
        return "OBLIGATION_POLICY_HASH_MISMATCH"
    if record.get("authority_state") != authority.authority_state:
        return "OBLIGATION_AUTHORITY_STATE_MISMATCH"
    if record.get("execution_context_hash") != execution_context_hash:
        return "EXECUTION_PRECONDITION_UNPROVEN"
    if obligation.get("evidence_required") is True and not is_sha256_reference(record.get("evidence_hash")):
        if record.get("evidence_hash") in {None, ""}:
            return "OBLIGATION_SATISFACTION_EVIDENCE_MISSING"
        return "OBLIGATION_EVIDENCE_MALFORMED"
    if record.get("evidence_hash") is not None and not is_sha256_reference(record.get("evidence_hash")):
        return "OBLIGATION_EVIDENCE_MALFORMED"
    if obligation.get("obligation_type") in {"human_review_required", "approval_required"}:
        if record.get("approved_by_human") is not True:
            return "HUMAN_APPROVAL_OBLIGATION_UNSATISFIED"
        approver_type = str(record.get("approver_type", "")).strip().lower()
        if approver_type in {"ai", "agent", "model", "autonomous"}:
            return "AI_APPROVAL_CANNOT_SATISFY_HUMAN_OBLIGATION"
    freshness_seconds = obligation.get("freshness_seconds")
    if freshness_seconds is not None:
        if not isinstance(freshness_seconds, int) or isinstance(freshness_seconds, bool) or freshness_seconds <= 0:
            return "POLICY_OBLIGATION_MALFORMED"
        fulfilled_at = record.get("fulfilled_at")
        fulfilled_timestamp, fulfilled_error = _parse_utc_timestamp(
            fulfilled_at if isinstance(fulfilled_at, str) else "",
            "fulfilled_at",
        )
        evaluated_timestamp, evaluated_error = _parse_utc_timestamp(timestamp, "evaluation")
        if fulfilled_error or evaluated_error or fulfilled_timestamp is None or evaluated_timestamp is None:
            return "OBLIGATION_EVIDENCE_MALFORMED"
        if fulfilled_timestamp > evaluated_timestamp:
            return "OBLIGATION_EVIDENCE_STALE"
        if (evaluated_timestamp - fulfilled_timestamp).total_seconds() > freshness_seconds:
            return "OBLIGATION_EVIDENCE_STALE"
    return None


def _execution_context_hash(request: Mapping[str, Any]) -> str:
    context = {
        "request_id": request.get("request_id"),
        "tenant_id": request.get("tenant_id"),
        "environment": request.get("environment"),
        "actor_id": request.get("actor_id"),
        "jurisdiction": request.get("jurisdiction"),
        "policy_scope": request.get("policy_scope"),
        "input_metadata_hash": _input_hash(request),
    }
    return sha256_reference(context, default_to_str=True)


def _policy_applicability(authority: PolicyAuthority) -> Mapping[str, Any] | None:
    if isinstance(authority.applicability, Mapping):
        return authority.applicability
    policy = authority.policy_document
    engine_policy = policy.get("ai_act_live_policy_engine")
    if isinstance(engine_policy, Mapping) and isinstance(engine_policy.get("applicability"), Mapping):
        return engine_policy["applicability"]
    if isinstance(policy.get("applicability"), Mapping):
        return policy["applicability"]
    return None


def _non_empty_str_set(value: Any) -> set[str] | None:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        values = {item for item in value if isinstance(item, str) and item}
        return values or None
    return None


def _use_case_classification(request: Mapping[str, Any]) -> str | None:
    input_metadata = request.get("input_metadata")
    if not isinstance(input_metadata, Mapping):
        return None
    for field in ("use_case_classification", "system_type"):
        value = input_metadata.get(field)
        if isinstance(value, str) and value:
            return value
    return None


def _parse_utc_timestamp(value: str, field: str) -> tuple[datetime | None, str | None]:
    if not isinstance(value, str) or not value:
        return None, "EVALUATION_CLOCK_UNAVAILABLE" if field == "evaluation" else f"{field.upper()}_MALFORMED"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None, "EVALUATION_TIMESTAMP_MALFORMED" if field == "evaluation" else f"{field.upper()}_MALFORMED"
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None, "EVALUATION_TIMESTAMP_MALFORMED" if field == "evaluation" else f"{field.upper()}_MALFORMED"
    return parsed.astimezone(timezone.utc), None


def _validate_supported_policy(policy: Mapping[str, Any]) -> str | None:
    if policy.get("fail_closed") is not True:
        return "POLICY_FAIL_CLOSED_DISABLED"
    engine_policy = policy.get("ai_act_live_policy_engine")
    if not isinstance(engine_policy, Mapping) or engine_policy.get("enabled") is not True:
        return "POLICY_UNSUPPORTED"
    rules = engine_policy.get("rules")
    if not isinstance(rules, Sequence) or isinstance(rules, (str, bytes)) or not rules:
        return "POLICY_RULES_MISSING"
    for rule in rules:
        if not isinstance(rule, Mapping):
            return "POLICY_RULE_MALFORMED"
        if not all(isinstance(rule.get(field), str) and rule.get(field) for field in ("rule_id", "field", "operator", "effect")):
            return "POLICY_RULE_MALFORMED"
        if rule.get("operator") != SUPPORTED_RULE_OPERATOR:
            return "POLICY_RULE_UNSUPPORTED"
        if rule.get("effect") not in SUPPORTED_RULE_EFFECTS:
            return "POLICY_RULE_UNSUPPORTED"
        if "value" not in rule:
            return "POLICY_RULE_MALFORMED"
    return None


def _matching_rule_effects(
    rules: Sequence[Mapping[str, Any]],
    input_metadata: Mapping[str, Any],
) -> list[tuple[str, str]]:
    matches: list[tuple[str, str]] = []
    for rule in rules:
        field = str(rule["field"])
        if input_metadata.get(field) == rule.get("value"):
            matches.append((str(rule["rule_id"]), str(rule["effect"])))
    return matches


def _contains_policy_authoring_attempt(value: Mapping[str, Any]) -> bool:
    forbidden_flags = (
        "create_policy",
        "modify_policy",
        "approve_policy",
        "relax_policy",
        "promote_policy",
        "policy_creation_attempt",
        "policy_modification_attempt",
        "policy_approval_attempt",
        "policy_relaxation_attempt",
        "policy_promotion_attempt",
    )
    if any(value.get(flag) for flag in forbidden_flags):
        return True
    actor_type = str(value.get("policy_authority_actor", "")).strip().lower()
    return actor_type in {"ai", "agent", "model", "autonomous"}


def _contains_sensitive_data(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower()
            if normalized in SENSITIVE_KEYS:
                return True
            if _contains_sensitive_data(child):
                return True
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return any(_contains_sensitive_data(item) for item in value)
    return False


def _policy_id(policy: Mapping[str, Any]) -> str:
    for field in ("policy_id", "scope", "id"):
        value = policy.get(field)
        if isinstance(value, str) and value:
            return value
    return "policy/policy.json"


def _request_field(request: Mapping[str, Any] | None, field: str) -> str | None:
    if not isinstance(request, Mapping):
        return None
    value = request.get(field)
    return value if isinstance(value, str) and value else None


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _request_hash(request: Mapping[str, Any] | None) -> str:
    if not isinstance(request, Mapping):
        return sha256_reference({})
    safe_request = {
        field: request.get(field)
        for field in sorted(REQUIRED_REQUEST_FIELDS | {"jurisdiction", "policy_scope"})
        if field != "input_metadata"
    }
    safe_request["input_metadata_hash"] = _input_hash(request)
    safe_request["obligation_satisfaction_hash"] = sha256_reference(
        request.get("obligation_satisfaction", []),
        default_to_str=True,
    )
    return sha256_reference(safe_request, default_to_str=True)


def _input_hash(request: Mapping[str, Any] | None) -> str:
    if not isinstance(request, Mapping) or not isinstance(request.get("input_metadata"), Mapping):
        return sha256_reference({})
    return sha256_reference(request["input_metadata"], default_to_str=True)


def _safe_previous_hash(value: str) -> str:
    return value if is_sha256_reference(value) else ZERO_SHA256_REFERENCE


def _timestamp(clock: Clock | None) -> str:
    if clock is not None:
        value = clock()
        if isinstance(value, str) and value:
            return value
        return ""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
