from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence, Union

from governance.hashing import ZERO_SHA256_REFERENCE, is_sha256_reference, sha256_reference
from runtime import policy_validator


ALLOW = "ALLOW"
BLOCK = "BLOCK"

SCHEMA_VERSION = "usbay.ai_act_live_policy_engine.v1"
SUPPORTED_RULE_OPERATOR = "equals"
SUPPORTED_RULE_EFFECTS = frozenset({ALLOW, BLOCK})
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
    )


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
        "result": decision,
        "reason_code": reason_code,
        "correlation_id": correlation_id,
        "request_hash": _request_hash(request),
        "input_metadata_hash": _input_hash(request),
        "matched_rule_id": matched_rule_id,
        "previous_evidence_hash": previous_evidence_hash,
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
