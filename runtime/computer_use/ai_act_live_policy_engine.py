from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence

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


PolicyAuthorityLoader = Callable[[], PolicyAuthority | Mapping[str, Any]]
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
) -> LivePolicyEvaluation:
    correlation_id = _request_field(request, "correlation_id")
    base = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": timestamp,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "policy_hash": policy_hash,
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
    )


def _validate_request(request: Mapping[str, Any] | None) -> str | None:
    if not isinstance(request, Mapping):
        return "REQUEST_MALFORMED"
    if _contains_sensitive_data(request):
        return "SENSITIVE_DATA_REJECTED"
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


def _request_hash(request: Mapping[str, Any] | None) -> str:
    if not isinstance(request, Mapping):
        return sha256_reference({})
    safe_request = {
        field: request.get(field)
        for field in sorted(REQUIRED_REQUEST_FIELDS)
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
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
