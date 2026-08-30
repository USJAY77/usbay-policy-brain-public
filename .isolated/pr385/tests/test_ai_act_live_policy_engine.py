from __future__ import annotations

import json
from typing import Any

import pytest

from governance.hashing import ZERO_SHA256_REFERENCE, sha256_reference
import runtime.computer_use.ai_act_live_policy_engine as engine
from runtime.computer_use.ai_act_live_policy_engine import (
    ALLOW,
    BLOCK,
    REVIEW,
    PolicyAuthority,
    consume_decision_evidence,
    create_governed_execution_authorization,
    evaluate_live_policy,
    validate_governed_execution_authorization,
    validate_runtime_policy_decision_for_execution,
)
from security.decision_evidence_consumption_store import (
    ATOMIC_CONSUMPTION_FAILED,
    FIRST_CONSUMPTION,
    REPLAY_BLOCKED,
    SQLiteDecisionEvidenceConsumptionStore,
    UnsupportedDecisionEvidenceConsumptionStore,
)


NOW = "2026-08-11T12:00:00Z"


def _hash(label: str) -> str:
    return sha256_reference({"label": label})


def _applicability(**overrides: Any) -> dict[str, Any]:
    payload = {
        "jurisdictions": ["EU"],
        "policy_scopes": ["ai_act_live_policy"],
        "use_case_classifications": ["bounded_ai_act"],
        "effective_from": "2026-08-01T00:00:00Z",
        "effective_until": "2026-09-01T00:00:00Z",
    }
    payload.update(overrides)
    return payload


def _obligations(*, freshness_seconds: int = 86_400) -> list[dict[str, Any]]:
    return [
        {
            "obligation_id": "human-review",
            "obligation_type": "human_review_required",
            "required": True,
            "evidence_required": True,
            "freshness_seconds": freshness_seconds,
        },
        {
            "obligation_id": "execution-contract",
            "obligation_type": "execution_contract_required",
            "required": True,
            "evidence_required": True,
        },
    ]


def _dependency(**overrides: Any) -> dict[str, Any]:
    payload = {
        "dependency_id": "policy-source-primary",
        "dependency_type": "policy_source",
        "required": True,
        "readiness_status": "READY",
        "health_status": "READY",
        "compatibility_status": "READY",
        "integrity_status": "READY",
        "last_verified_at": "2026-08-11T11:59:00Z",
        "freshness_window_seconds": 300,
        "expected_version": "policy-source-v1",
        "observed_version": "policy-source-v1",
        "evidence_hash": _hash("policy-source-readiness"),
        "final_decision": "ALLOW",
    }
    payload.update(overrides)
    return payload


def _policy(
    *,
    rules: list[dict[str, Any]] | None = None,
    fail_closed: bool = True,
    enabled: bool = True,
    applicability: dict[str, Any] | None = None,
    obligations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "policy_id": "ai-act-live-policy-v1",
        "policy_version": "2026.08.11",
        "fail_closed": fail_closed,
        "ai_act_live_policy_engine": {
            "enabled": enabled,
            "applicability": _applicability() if applicability is None else applicability,
            "obligations": _obligations() if obligations is None else obligations,
            "rules": rules
            if rules is not None
            else [
                {
                    "rule_id": "allow-low-risk",
                    "field": "risk_classification",
                    "operator": "equals",
                    "value": "LOW",
                    "effect": ALLOW,
                }
            ],
        },
    }


def _authority(**overrides: Any) -> PolicyAuthority:
    policy = overrides.pop("policy_document", _policy())
    payload = {
        "policy_id": policy.get("policy_id", "ai-act-live-policy-v1") if isinstance(policy, dict) else "ai-act-live-policy-v1",
        "policy_version": policy.get("policy_version", "2026.08.11") if isinstance(policy, dict) else "2026.08.11",
        "policy_hash": _hash("approved-policy"),
        "approved": True,
        "policy_document": policy,
    }
    payload.update(overrides)
    return PolicyAuthority(**payload)


def _request(**overrides: Any) -> dict[str, Any]:
    input_metadata = {"risk_classification": "LOW", "system_type": "bounded_ai_act"}
    if isinstance(overrides.get("input_metadata"), dict):
        input_metadata.update(overrides.pop("input_metadata"))
    explicit_obligations = overrides.pop("obligation_satisfaction", None)
    payload = {
        "request_id": "req-ai-act-live-001",
        "correlation_id": "corr-ai-act-live-001",
        "tenant_id": "tenant-usbay",
        "environment": "pilot",
        "actor_id": "human-approved-runtime",
        "jurisdiction": "EU",
        "policy_scope": "ai_act_live_policy",
        "policy_id": "ai-act-live-policy-v1",
        "policy_version": "2026.08.11",
        "policy_hash": _hash("approved-policy"),
        "input_metadata": input_metadata,
    }
    payload.update(overrides)
    if explicit_obligations is None:
        payload["obligation_satisfaction"] = _satisfaction_records(payload)
    else:
        payload["obligation_satisfaction"] = explicit_obligations
    return payload


def _execution_context_hash(request: dict[str, Any]) -> str:
    return sha256_reference(
        {
            "request_id": request.get("request_id"),
            "tenant_id": request.get("tenant_id"),
            "environment": request.get("environment"),
            "actor_id": request.get("actor_id"),
            "jurisdiction": request.get("jurisdiction"),
            "policy_scope": request.get("policy_scope"),
            "input_metadata_hash": sha256_reference(request.get("input_metadata", {}), default_to_str=True),
        },
        default_to_str=True,
    )


def _satisfaction_records(request: dict[str, Any]) -> list[dict[str, Any]]:
    base = {
        "request_id": request["request_id"],
        "policy_id": request["policy_id"],
        "policy_version": request["policy_version"],
        "policy_hash": request["policy_hash"],
        "authority_state": "CURRENT",
        "execution_context_hash": _execution_context_hash(request),
        "state": "SATISFIED",
        "fulfilled_at": NOW,
    }
    return [
        {
            **base,
            "obligation_id": "human-review",
            "obligation_type": "human_review_required",
            "evidence_hash": _hash("human-review-evidence"),
            "approved_by_human": True,
            "approver_type": "human",
        },
        {
            **base,
            "obligation_id": "execution-contract",
            "obligation_type": "execution_contract_required",
            "evidence_hash": _hash("execution-contract-evidence"),
        },
    ]


def _evaluate(
    request: dict[str, Any] | None = None,
    authority: PolicyAuthority | None = None,
    *,
    clock_value: str = NOW,
):
    return evaluate_live_policy(
        _request() if request is None else request,
        policy_authority_loader=lambda: authority or _authority(),
        previous_evidence_hash=ZERO_SHA256_REFERENCE,
        clock=lambda: clock_value,
    )


def _consume(
    evidence: dict[str, Any] | None,
    request: dict[str, Any] | None = None,
    authority: PolicyAuthority | None = None,
    *,
    consumption_store: Any | None = None,
    clock_value: str = NOW,
):
    return consume_decision_evidence(
        _request() if request is None else request,
        evidence,
        policy_authority_loader=lambda: authority or _authority(),
        consumption_store=consumption_store or SQLiteDecisionEvidenceConsumptionStore(":memory:"),
        previous_evidence_hash=ZERO_SHA256_REFERENCE,
        clock=lambda: clock_value,
    )


def _allow_evidence() -> dict[str, Any]:
    return dict(_evaluate().evidence)


def _review_policy() -> dict[str, Any]:
    return _policy(
        rules=[
            {
                "rule_id": "review-medium-risk",
                "field": "risk_classification",
                "operator": "equals",
                "value": "MEDIUM",
                "effect": REVIEW,
            }
        ]
    )


def _review_request(**overrides: Any) -> dict[str, Any]:
    return _request(input_metadata={"risk_classification": "MEDIUM"}, **overrides)


def _review_evidence() -> dict[str, Any]:
    return dict(_evaluate(_review_request(), _authority(policy_document=_review_policy())).evidence)


def _consumed_decision() -> Any:
    return _consume(_allow_evidence())


def _execution_contract(**overrides: Any) -> dict[str, Any]:
    payload = {
        "subject_id": "human-approved-runtime",
        "agent_id": "replit-executor",
        "action_id": "execute-command",
        "tool_id": "runtime.replit_executor.execute_command",
        "resource_id": "commands/test_command.json",
        "target_id": "local-subprocess",
        "parameter_hash": _hash("echo-ok-command"),
        "purpose": "bounded_ai_act_runtime_execution",
        "expires_at": "2026-08-11T12:05:00Z",
        "authorization_nonce": "exec-auth-nonce-001",
        "human_intent_reference": "intent-human-approved-001",
        "human_intent_approved_by": "human-reviewer-1",
        "human_intent_approver_type": "human",
        "human_intent_approved_at": "2026-08-11T11:59:00Z",
        "human_intent_expires_at": "2026-08-11T12:05:00Z",
    }
    payload.update(overrides)
    if "human_intent_hash" not in payload:
        payload["human_intent_hash"] = engine._human_intent_hash(payload)
    return payload


def _execution_authorization(
    request: dict[str, Any] | None = None,
    consumed_decision: Any | None = None,
    contract: dict[str, Any] | None = None,
    *,
    clock_value: str = NOW,
) -> dict[str, Any]:
    result = create_governed_execution_authorization(
        _request() if request is None else request,
        _consumed_decision() if consumed_decision is None else consumed_decision,
        _execution_contract() if contract is None else contract,
        clock=lambda: clock_value,
    )
    assert result.decision == ALLOW
    return dict(result.evidence)


def _rehash_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    payload = dict(evidence)
    trace = {
        "decision_trace_schema_version": payload.get("decision_trace_schema_version"),
        "decision_trace_result_reference": payload.get("decision_trace_result_reference"),
        "decision_trace_request_reference": payload.get("decision_trace_request_reference"),
        "decision_trace_correlation_reference": payload.get("decision_trace_correlation_reference"),
        "decision_trace_policy_reference": payload.get("decision_trace_policy_reference"),
        "decision_trace_previous_evidence_hash": payload.get("decision_trace_previous_evidence_hash"),
        "authority_trace_reference": payload.get("authority_trace_reference"),
        "applicability_trace_reference": payload.get("applicability_trace_reference"),
        "temporal_effectivity_trace_reference": payload.get("temporal_effectivity_trace_reference"),
        "obligation_trace_reference": payload.get("obligation_trace_reference"),
        "execution_precondition_trace_reference": payload.get("execution_precondition_trace_reference"),
    }
    if all(value is not None for value in trace.values()):
        payload["decision_trace_hash"] = sha256_reference(trace, default_to_str=True)
    payload.pop("current_evidence_hash", None)
    return {**payload, "current_evidence_hash": sha256_reference(payload)}


def test_valid_allow_returns_allow_without_execution_authority() -> None:
    result = _evaluate()

    assert result.decision == ALLOW
    assert result.reason_code == "POLICY_RULE_ALLOWED"
    assert result.evidence["authority_verification_result"] == "POLICY_AUTHORITY_VERIFIED"
    assert result.evidence["applicability_verification_result"] == "POLICY_APPLICABILITY_EFFECTIVITY_VERIFIED"
    assert result.execution_authorized is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
    assert result.evidence["execution_authorized"] is False


def test_explicit_review_policy_rule_returns_review_without_execution_authority() -> None:
    result = _evaluate(_review_request(), _authority(policy_document=_review_policy()))

    assert result.decision == REVIEW
    assert result.reason_code == "POLICY_REVIEW_REQUIRED"
    assert result.execution_authorized is False
    assert result.human_review_required is True
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
    assert result.evidence["result"] == REVIEW
    assert result.evidence["reason_code"] == "POLICY_REVIEW_REQUIRED"
    assert result.evidence["matched_rule_id"] == "review-medium-risk"
    assert result.evidence["execution_authorized"] is False
    assert result.evidence["human_review_required"] is True


def test_review_decision_is_not_consumable_or_executable_as_allow() -> None:
    evidence = _review_evidence()
    consumed = _consume(evidence, _review_request(), _authority(policy_document=_review_policy()))
    contract = _execution_contract()
    authorization = _execution_authorization(
        request=_request(),
        consumed_decision=_consumed_decision(),
        contract=contract,
    )

    assert consumed.decision == BLOCK
    assert consumed.reason_code == "DECISION_NOT_ALLOW"
    assert create_governed_execution_authorization(
        _review_request(),
        _evaluate(_review_request(), _authority(policy_document=_review_policy())),
        contract,
        clock=lambda: NOW,
    ).reason_code == "EXEC_AUTH_DECISION_LINK_INVALID"
    assert validate_runtime_policy_decision_for_execution(
        evidence,
        _review_request(),
        contract,
        authorization,
        command_hash=contract["parameter_hash"],
        consumed_decision_evidence_hash=evidence["current_evidence_hash"],
    ) == "RUNTIME_POLICY_DECISION_NOT_ALLOW"


@pytest.mark.parametrize(
    ("effect", "reason_code"),
    [
        ("review", "POLICY_RULE_UNSUPPORTED"),
        ("REVIEW_PENDING", "POLICY_RULE_UNSUPPORTED"),
        ("", "POLICY_RULE_MALFORMED"),
        (None, "POLICY_RULE_MALFORMED"),
    ],
)
def test_unknown_malformed_missing_or_lowercase_review_effects_fail_closed(
    effect: Any,
    reason_code: str,
) -> None:
    rule = {
        "rule_id": "unsupported-review",
        "field": "risk_classification",
        "operator": "equals",
        "value": "MEDIUM",
    }
    if effect is not None:
        rule["effect"] = effect

    result = _evaluate(_review_request(), _authority(policy_document=_policy(rules=[rule])))

    assert result.decision == BLOCK
    assert result.reason_code == reason_code


def test_review_evidence_is_hash_bound_chain_bound_and_tamper_evident() -> None:
    first = _evaluate(_review_request(), _authority(policy_document=_review_policy()))
    second_request = _review_request(request_id="req-review-002", correlation_id="corr-review-002")
    second = evaluate_live_policy(
        second_request,
        policy_authority_loader=lambda: _authority(policy_document=_review_policy()),
        previous_evidence_hash=first.evidence["current_evidence_hash"],
        clock=lambda: NOW,
    )
    evidence = dict(first.evidence)
    current_hash = evidence.pop("current_evidence_hash")
    tampered = {**evidence, "human_review_required": False}

    assert first.decision == REVIEW
    assert current_hash == sha256_reference(evidence)
    assert sha256_reference(tampered) != current_hash
    assert second.decision == REVIEW
    assert second.evidence["previous_evidence_hash"] == first.evidence["current_evidence_hash"]
    assert second.evidence["decision_trace_previous_evidence_hash"] == first.evidence["current_evidence_hash"]


def test_review_evidence_binding_rejects_policy_request_and_authority_substitution() -> None:
    evidence = _review_evidence()
    authority = _authority(policy_document=_review_policy())

    assert _consume(evidence, _review_request(policy_hash=_hash("other-policy")), authority).reason_code == "DECISION_NOT_ALLOW"
    assert _consume(evidence, _review_request(request_id="other-request"), authority).reason_code == "DECISION_NOT_ALLOW"

    stale_review_policy = _policy(
        rules=[
            {
                "rule_id": "review-medium-risk-rotated",
                "field": "risk_classification",
                "operator": "equals",
                "value": "MEDIUM",
                "effect": REVIEW,
            }
        ]
    )
    assert _consume(evidence, _review_request(), _authority(policy_document=stale_review_policy)).reason_code == "DECISION_NOT_ALLOW"


def test_agent_or_self_approval_cannot_turn_review_into_execution_authority() -> None:
    request = _review_request()
    request["obligation_satisfaction"][0]["approver_type"] = "agent"

    result = _evaluate(request, _authority(policy_document=_review_policy()))

    assert result.decision == BLOCK
    assert result.reason_code == "AI_APPROVAL_CANNOT_SATISFY_HUMAN_OBLIGATION"

    request = _review_request()
    request["obligation_satisfaction"][0]["approved_by_human"] = False
    result = _evaluate(request, _authority(policy_document=_review_policy()))

    assert result.decision == BLOCK
    assert result.reason_code == "HUMAN_APPROVAL_OBLIGATION_UNSATISFIED"


def test_valid_allow_requires_matching_applicability_and_current_effectivity() -> None:
    result = _evaluate()

    assert result.decision == ALLOW
    assert result.evidence["matched_jurisdiction_reference"].startswith("sha256:")
    assert result.evidence["matched_policy_scope_reference"].startswith("sha256:")
    assert result.evidence["matched_use_case_reference"].startswith("sha256:")
    assert result.evidence["policy_effective_from"] == "2026-08-01T00:00:00Z"
    assert result.evidence["policy_effective_until"] == "2026-09-01T00:00:00Z"
    assert result.evidence["evaluation_timestamp"] == NOW


def test_valid_allow_requires_all_policy_obligations_satisfied() -> None:
    result = _evaluate()

    assert result.decision == ALLOW
    assert result.evidence["obligation_verification_result"] == "POLICY_OBLIGATIONS_VERIFIED"
    assert result.evidence["obligations_evaluated_count"] == 2
    assert len(result.evidence["required_obligation_references"]) == 2
    assert len(result.evidence["satisfied_obligation_references"]) == 2
    assert result.evidence["obligation_state_reference"].startswith("sha256:")


@pytest.mark.parametrize(
    ("dependencies", "expected_reason"),
    [
        (None, "POLICY_DEPENDENCY_MISSING"),
        ([_dependency(readiness_status="STALE", last_verified_at="2026-08-11T11:00:00Z")], "POLICY_DEPENDENCY_NOT_READY"),
        ([_dependency(readiness_status="UNVERIFIED", integrity_status="UNVERIFIED")], "POLICY_DEPENDENCY_NOT_READY"),
        ([{"dependency_id": "policy-source-primary"}], "POLICY_DEPENDENCY_NOT_READY"),
        ([_dependency(observed_version="policy-source-v2")], "POLICY_DEPENDENCY_NOT_READY"),
        ([_dependency(evidence_hash="not-a-sha256-reference")], "POLICY_DEPENDENCY_NOT_READY"),
    ],
)
def test_policy_dependency_integrity_failures_block_before_allow(
    dependencies: Any,
    expected_reason: str,
) -> None:
    policy = _policy()
    policy["policy_dependencies_required"] = True
    if dependencies is not None:
        policy["policy_dependencies"] = dependencies

    result = _evaluate(authority=_authority(policy_document=policy))

    assert result.decision == BLOCK
    assert result.reason_code == expected_reason
    assert result.evidence["dependency_verification_result"] != "POLICY_DEPENDENCIES_VERIFIED"
    assert result.evidence["execution_authorized"] is False


def test_policy_dependency_verification_error_blocks_before_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken_dependency_readiness(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("dependency verifier unavailable")

    policy = _policy()
    policy["policy_dependencies"] = [_dependency()]
    monkeypatch.setattr(engine, "evaluate_dependency_readiness", broken_dependency_readiness)

    result = _evaluate(authority=_authority(policy_document=policy))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_DEPENDENCY_VERIFICATION_UNAVAILABLE"
    assert result.evidence["dependency_verification_result"] == "POLICY_DEPENDENCY_VERIFICATION_UNAVAILABLE"


def test_valid_policy_dependency_preserves_allow_path_and_binds_evidence() -> None:
    policy = _policy()
    policy["policy_dependencies"] = [_dependency()]

    result = _evaluate(authority=_authority(policy_document=policy))

    assert result.decision == ALLOW
    assert result.reason_code == "POLICY_RULE_ALLOWED"
    assert result.evidence["dependency_verification_result"] == "POLICY_DEPENDENCIES_VERIFIED"
    assert result.evidence["dependency_count"] == 1
    assert result.evidence["dependency_readiness_hash"].startswith("sha256:")
    assert result.evidence["dependency_reference_hashes"] == [
        sha256_reference(
            {
                "dependency_id": "policy-source-primary",
                "dependency_type": "policy_source",
                "required": True,
                "readiness_status": "READY",
                "expected_version": "policy-source-v1",
                "observed_version": "policy-source-v1",
                "evidence_hash": _hash("policy-source-readiness"),
                "final_decision": "ALLOW",
            }
        )
    ]


def test_policy_dependency_evidence_is_decision_hash_bound() -> None:
    first_policy = _policy()
    first_policy["policy_dependencies"] = [_dependency(evidence_hash=_hash("policy-source-readiness-one"))]
    second_policy = _policy()
    second_policy["policy_dependencies"] = [_dependency(evidence_hash=_hash("policy-source-readiness-two"))]

    first = _evaluate(authority=_authority(policy_document=first_policy))
    second = _evaluate(authority=_authority(policy_document=second_policy))

    assert first.decision == ALLOW
    assert second.decision == ALLOW
    assert first.evidence["dependency_readiness_hash"] != second.evidence["dependency_readiness_hash"]
    assert first.evidence["dependency_reference_hashes"] != second.evidence["dependency_reference_hashes"]
    assert first.evidence["current_evidence_hash"] != second.evidence["current_evidence_hash"]


def test_missing_required_obligation_metadata_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(policy_document=_policy(obligations=[])))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_OBLIGATIONS_MISSING"


def test_required_obligation_unsatisfied_blocks_before_allow() -> None:
    request = _request()
    request["obligation_satisfaction"] = request["obligation_satisfaction"][1:]

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "REQUIRED_OBLIGATION_UNSATISFIED"


def test_missing_obligation_satisfaction_evidence_blocks_before_allow() -> None:
    request = _request()
    request["obligation_satisfaction"][0].pop("evidence_hash")

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "OBLIGATION_SATISFACTION_EVIDENCE_MISSING"


def test_malformed_obligation_evidence_blocks_before_allow() -> None:
    request = _request()
    request["obligation_satisfaction"][0]["evidence_hash"] = "not-a-sha"

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "OBLIGATION_EVIDENCE_MALFORMED"


def test_obligation_request_mismatch_blocks_before_allow() -> None:
    request = _request()
    request["obligation_satisfaction"][0]["request_id"] = "other-request"

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "OBLIGATION_REQUEST_MISMATCH"


def test_obligation_policy_identity_mismatch_blocks_before_allow() -> None:
    request = _request()
    request["obligation_satisfaction"][0]["policy_id"] = "other-policy"

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "OBLIGATION_POLICY_ID_MISMATCH"


def test_obligation_policy_version_mismatch_blocks_before_allow() -> None:
    request = _request()
    request["obligation_satisfaction"][0]["policy_version"] = "2026.08.10"

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "OBLIGATION_POLICY_VERSION_MISMATCH"


def test_obligation_policy_hash_mismatch_blocks_before_allow() -> None:
    request = _request()
    request["obligation_satisfaction"][0]["policy_hash"] = _hash("other-policy")

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "OBLIGATION_POLICY_HASH_MISMATCH"


def test_stale_obligation_evidence_blocks_before_allow() -> None:
    request = _request()
    request["obligation_satisfaction"][0]["fulfilled_at"] = "2026-08-09T12:00:00Z"

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "OBLIGATION_EVIDENCE_STALE"


def test_ambiguous_obligation_state_blocks_before_allow() -> None:
    request = _request()
    request["obligation_satisfaction"][0]["state"] = "AMBIGUOUS"

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "OBLIGATION_STATE_AMBIGUOUS"


def test_unknown_obligation_type_blocks_before_allow() -> None:
    result = _evaluate(
        authority=_authority(
            policy_document=_policy(
                obligations=[
                    {
                        "obligation_id": "unknown",
                        "obligation_type": "invented_obligation",
                        "required": True,
                        "evidence_required": True,
                    }
                ]
            )
        )
    )

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_OBLIGATION_TYPE_UNKNOWN"


def test_missing_execution_precondition_blocks_before_allow() -> None:
    request = _request()
    request["obligation_satisfaction"][0]["execution_context_hash"] = _hash("wrong-context")

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "EXECUTION_PRECONDITION_UNPROVEN"


def test_ai_generated_approval_cannot_satisfy_human_obligation() -> None:
    request = _request()
    request["obligation_satisfaction"][0]["approved_by_human"] = False

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "HUMAN_APPROVAL_OBLIGATION_UNSATISFIED"

    request = _request()
    request["obligation_satisfaction"][0]["approver_type"] = "ai"
    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "AI_APPROVAL_CANNOT_SATISFY_HUMAN_OBLIGATION"


def test_missing_applicability_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(policy_document=_policy(applicability={})))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_APPLICABILITY_MISSING"


def test_missing_jurisdiction_blocks_before_allow() -> None:
    request = _request()
    request.pop("jurisdiction")

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "JURISDICTION_MISSING"


def test_jurisdiction_mismatch_blocks_before_allow() -> None:
    result = _evaluate(_request(jurisdiction="US"))

    assert result.decision == BLOCK
    assert result.reason_code == "JURISDICTION_MISMATCH"


def test_missing_policy_scope_blocks_before_allow() -> None:
    request = _request()
    request.pop("policy_scope")

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_SCOPE_MISSING"


def test_policy_scope_mismatch_blocks_before_allow() -> None:
    result = _evaluate(_request(policy_scope="unapproved_scope"))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_SCOPE_MISMATCH"


def test_missing_use_case_classification_blocks_before_allow() -> None:
    result = _evaluate(_request(input_metadata={"system_type": ""}))

    assert result.decision == BLOCK
    assert result.reason_code == "USE_CASE_CLASSIFICATION_MISSING"


def test_use_case_classification_mismatch_blocks_before_allow() -> None:
    result = _evaluate(_request(input_metadata={"system_type": "unapproved_use"}))

    assert result.decision == BLOCK
    assert result.reason_code == "USE_CASE_CLASSIFICATION_MISMATCH"


def test_missing_effective_from_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(policy_document=_policy(applicability=_applicability(effective_from=None))))

    assert result.decision == BLOCK
    assert result.reason_code == "EFFECTIVE_FROM_MISSING"


def test_not_yet_effective_policy_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(policy_document=_policy(applicability=_applicability(effective_from="2026-08-12T00:00:00Z"))))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_NOT_YET_EFFECTIVE"


def test_expired_policy_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(policy_document=_policy(applicability=_applicability(effective_until="2026-08-11T12:00:00Z"))))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_EXPIRED"


def test_malformed_effective_from_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(policy_document=_policy(applicability=_applicability(effective_from="not-a-date"))))

    assert result.decision == BLOCK
    assert result.reason_code == "EFFECTIVE_FROM_MALFORMED"


def test_malformed_effective_until_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(policy_document=_policy(applicability=_applicability(effective_until="2026-09-01 00:00:00"))))

    assert result.decision == BLOCK
    assert result.reason_code == "EFFECTIVE_UNTIL_MALFORMED"


def test_ambiguous_applicability_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(applicability_ambiguous=True))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_APPLICABILITY_AMBIGUOUS"


def test_unavailable_applicability_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(applicability_available=False))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_APPLICABILITY_UNAVAILABLE"


def test_unavailable_clock_blocks_before_allow() -> None:
    result = _evaluate(clock_value="")

    assert result.decision == BLOCK
    assert result.reason_code == "EVALUATION_CLOCK_UNAVAILABLE"


def test_malformed_evaluation_timestamp_blocks_before_allow() -> None:
    result = _evaluate(clock_value="not-a-date")

    assert result.decision == BLOCK
    assert result.reason_code == "EVALUATION_TIMESTAMP_MALFORMED"


def test_condition_violation_blocks() -> None:
    request = _request(input_metadata={"risk_classification": "HIGH"})

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_CONDITION_NOT_SATISFIED"


def test_missing_policy_blocks() -> None:
    result = evaluate_live_policy(_request(), policy_authority_loader=lambda: None, clock=lambda: NOW)

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_EVALUATION_EXCEPTION"


def test_unknown_policy_id_blocks() -> None:
    result = _evaluate(_request(policy_id="unknown-policy"))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_ID_MISMATCH"


def test_missing_policy_id_blocks() -> None:
    request = _request()
    request.pop("policy_id")

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_ID_MISSING"


def test_missing_policy_version_blocks() -> None:
    request = _request()
    request.pop("policy_version")

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_VERSION_MISSING"


def test_policy_version_mismatch_blocks() -> None:
    result = _evaluate(_request(policy_version="2026.08.10"))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_VERSION_MISMATCH"


def test_missing_policy_hash_blocks() -> None:
    request = _request()
    request.pop("policy_hash")

    result = _evaluate(request)

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_HASH_MISSING"


def test_unapproved_policy_blocks() -> None:
    result = _evaluate(authority=_authority(approved=False))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_NOT_HUMAN_APPROVED"


def test_malformed_policy_blocks() -> None:
    result = _evaluate(authority=_authority(policy_document={"policy_id": "ai-act-live-policy-v1"}))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_FAIL_CLOSED_DISABLED"


def test_unverifiable_policy_hash_blocks() -> None:
    result = _evaluate(authority=_authority(policy_hash="not-a-sha"))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_HASH_UNVERIFIABLE"


def test_unsupported_policy_blocks() -> None:
    result = _evaluate(authority=_authority(policy_document=_policy(enabled=False)))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_UNSUPPORTED"


def test_revoked_policy_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(revoked=True))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_REVOKED"
    assert result.evidence["authority_verification_result"] == "POLICY_REVOKED"


def test_superseded_policy_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(superseded=True, superseded_by_policy_version="2026.08.12"))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_SUPERSEDED"


def test_missing_approval_evidence_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(approval_evidence_present=False))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_APPROVAL_EVIDENCE_MISSING"


def test_invalid_approval_evidence_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(approval_evidence_valid=False))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_APPROVAL_EVIDENCE_INVALID"


def test_ambiguous_authority_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(ambiguous=True))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_AUTHORITY_AMBIGUOUS"


def test_malformed_authority_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(policy_document=[]))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_MALFORMED"


def test_unavailable_authority_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(authority_available=False))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_AUTHORITY_UNAVAILABLE"


def test_unsupported_authority_state_blocks_before_allow() -> None:
    result = _evaluate(authority=_authority(authority_state="UNKNOWN"))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_AUTHORITY_STATE_UNSUPPORTED"


def test_evaluator_exception_blocks() -> None:
    def broken_loader() -> PolicyAuthority:
        raise RuntimeError("authority unavailable")

    result = evaluate_live_policy(_request(), policy_authority_loader=broken_loader, clock=lambda: NOW)

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_EVALUATION_EXCEPTION"


def test_ambiguous_decision_blocks() -> None:
    policy = _policy(
        rules=[
            {
                "rule_id": "allow-low-risk",
                "field": "risk_classification",
                "operator": "equals",
                "value": "LOW",
                "effect": ALLOW,
            },
            {
                "rule_id": "block-low-risk-conflict",
                "field": "risk_classification",
                "operator": "equals",
                "value": "LOW",
                "effect": BLOCK,
            },
        ]
    )

    result = _evaluate(authority=_authority(policy_document=policy))

    assert result.decision == BLOCK
    assert result.reason_code == "AMBIGUOUS_POLICY_DECISION"


def test_allow_evidence_contains_required_hash_only_fields() -> None:
    result = _evaluate()
    evidence = result.evidence

    assert evidence["decision_id"] == result.decision_id
    assert evidence["timestamp"] == NOW
    assert evidence["policy_id"] == "ai-act-live-policy-v1"
    assert evidence["policy_version"] == "2026.08.11"
    assert evidence["policy_hash"] == _hash("approved-policy")
    assert evidence["requested_policy_version"] == "2026.08.11"
    assert evidence["approved_policy_version"] == "2026.08.11"
    assert evidence["requested_policy_hash"] == _hash("approved-policy")
    assert evidence["approved_policy_hash"] == _hash("approved-policy")
    assert evidence["authority_verification_result"] == "POLICY_AUTHORITY_VERIFIED"
    assert evidence["authority_state_reference"].startswith("sha256:")
    assert evidence["result"] == ALLOW
    assert evidence["reason_code"] == "POLICY_RULE_ALLOWED"
    assert evidence["correlation_id"] == "corr-ai-act-live-001"
    assert evidence["previous_evidence_hash"] == ZERO_SHA256_REFERENCE
    assert evidence["current_evidence_hash"].startswith("sha256:")
    assert evidence["evidence_mode"] == "hash-only-redacted"
    assert evidence["redacted"] is True


def test_allow_evidence_contains_complete_decision_traceability() -> None:
    result = _evaluate()
    evidence = result.evidence

    assert result.decision == ALLOW
    assert evidence["decision_trace_schema_version"] == "usbay.ai_act_live_policy_engine.decision_trace.v1"
    assert evidence["decision_trace_hash"].startswith("sha256:")
    assert evidence["decision_trace_result_reference"].startswith("sha256:")
    assert evidence["decision_trace_request_reference"] == evidence["request_hash"]
    assert evidence["decision_trace_correlation_reference"].startswith("sha256:")
    assert evidence["decision_trace_policy_reference"].startswith("sha256:")
    assert evidence["decision_trace_previous_evidence_hash"] == ZERO_SHA256_REFERENCE
    assert evidence["authority_trace_reference"].startswith("sha256:")
    assert evidence["applicability_trace_reference"].startswith("sha256:")
    assert evidence["temporal_effectivity_trace_reference"].startswith("sha256:")
    assert evidence["obligation_trace_reference"].startswith("sha256:")
    assert evidence["execution_precondition_trace_reference"].startswith("sha256:")


def test_block_evidence_contains_first_failed_governance_gate_traceability() -> None:
    result = _evaluate(authority=_authority(authority_available=False))
    evidence = result.evidence

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_AUTHORITY_UNAVAILABLE"
    assert evidence["authority_verification_result"] == "POLICY_AUTHORITY_UNAVAILABLE"
    assert evidence["applicability_verification_result"] == "NOT_EVALUATED"
    assert evidence["obligation_verification_result"] == "NOT_EVALUATED"
    assert evidence["decision_trace_hash"].startswith("sha256:")
    assert evidence["authority_trace_reference"].startswith("sha256:")
    assert evidence["decision_trace_policy_reference"].startswith("sha256:")


def test_block_reason_codes_remain_deterministic_by_governance_gate() -> None:
    cases = (
        (_request(), _authority(authority_available=False), "POLICY_AUTHORITY_UNAVAILABLE"),
        (_request(jurisdiction="US"), _authority(), "JURISDICTION_MISMATCH"),
        (
            _request(),
            _authority(policy_document=_policy(applicability=_applicability(effective_from="2026-08-12T00:00:00Z"))),
            "POLICY_NOT_YET_EFFECTIVE",
        ),
        (_request(obligation_satisfaction=[]), _authority(), "REQUIRED_OBLIGATION_UNSATISFIED"),
        (_request(policy_hash=_hash("other-policy")), _authority(), "POLICY_HASH_MISMATCH"),
    )

    for request, authority, reason_code in cases:
        first = _evaluate(request, authority)
        second = _evaluate(request, authority)
        assert first.decision == BLOCK
        assert second.decision == BLOCK
        assert first.reason_code == reason_code
        assert second.reason_code == reason_code
        assert first.evidence["decision_trace_hash"] == second.evidence["decision_trace_hash"]


def test_block_evidence_contains_required_hash_only_fields() -> None:
    result = _evaluate(_request(input_metadata={"risk_classification": "HIGH"}))
    evidence = result.evidence

    assert result.decision == BLOCK
    assert evidence["result"] == BLOCK
    assert evidence["reason_code"] == "POLICY_CONDITION_NOT_SATISFIED"
    assert evidence["policy_hash"] == _hash("approved-policy")
    assert evidence["current_evidence_hash"].startswith("sha256:")


def test_evidence_binds_exact_policy_version_and_hash() -> None:
    result = _evaluate()

    assert result.policy_version == "2026.08.11"
    assert result.policy_hash == _hash("approved-policy")
    assert result.evidence["policy_version"] == result.policy_version
    assert result.evidence["policy_hash"] == result.policy_hash
    assert result.evidence["approved_policy_version"] == result.policy_version
    assert result.evidence["approved_policy_hash"] == result.policy_hash


def test_hash_chain_links_to_predecessor_hash() -> None:
    first = _evaluate()
    second = evaluate_live_policy(
        _request(request_id="req-ai-act-live-002", correlation_id="corr-ai-act-live-002"),
        policy_authority_loader=lambda: _authority(),
        previous_evidence_hash=first.evidence["current_evidence_hash"],
        clock=lambda: NOW,
    )

    assert second.evidence["previous_evidence_hash"] == first.evidence["current_evidence_hash"]
    assert second.evidence["current_evidence_hash"] != first.evidence["current_evidence_hash"]


def test_evidence_hash_recomputes_from_immutable_record() -> None:
    result = _evaluate()
    evidence = dict(result.evidence)
    current_hash = evidence.pop("current_evidence_hash")

    assert current_hash == sha256_reference(evidence)


def test_tampering_changes_decision_evidence_hash() -> None:
    result = _evaluate()
    evidence = dict(result.evidence)
    current_hash = evidence.pop("current_evidence_hash")
    tampered = {**evidence, "reason_code": "TAMPERED_REASON"}

    assert sha256_reference(tampered) != current_hash


def test_evidence_generation_failure_cannot_yield_allow(monkeypatch) -> None:
    original_decision_trace = engine._decision_trace

    def fail_for_allow(*args: Any, **kwargs: Any) -> dict[str, Any]:
        if kwargs.get("decision") == ALLOW:
            raise RuntimeError("trace unavailable")
        return original_decision_trace(*args, **kwargs)

    monkeypatch.setattr(engine, "_decision_trace", fail_for_allow)

    result = engine.evaluate_live_policy(
        _request(),
        policy_authority_loader=lambda: _authority(),
        previous_evidence_hash=ZERO_SHA256_REFERENCE,
        clock=lambda: NOW,
    )

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_EVALUATION_EXCEPTION"
    assert result.execution_authorized is False


def test_sensitive_data_is_rejected_and_not_stored_in_evidence() -> None:
    result = _evaluate(_request(input_metadata={"risk_classification": "LOW", "token": "do-not-store"}))
    rendered = json.dumps(result.evidence, sort_keys=True)

    assert result.decision == BLOCK
    assert result.reason_code == "SENSITIVE_DATA_REJECTED"
    assert "do-not-store" not in rendered
    assert "token" not in rendered.lower()
    assert "raw_payload" not in rendered
    assert "prompt" not in rendered


def test_sensitive_decision_evidence_excludes_credentials_prompts_and_payloads() -> None:
    sensitive_inputs = (
        {"api_key": "api-key-value"},
        {"credential": "credential-value"},
        {"password": "password-value"},
        {"prompt": "raw prompt value"},
        {"personal_data": "personal payload"},
    )

    for metadata in sensitive_inputs:
        result = _evaluate(_request(input_metadata={"risk_classification": "LOW", **metadata}))
        rendered = json.dumps(result.evidence, sort_keys=True).lower()
        assert result.decision == BLOCK
        for key, value in metadata.items():
            assert key not in rendered
            assert str(value).lower() not in rendered


def test_block_cannot_trigger_downstream_execution() -> None:
    result = _evaluate(_request(input_metadata={"risk_classification": "HIGH"}))

    assert result.decision == BLOCK
    assert result.execution_authorized is False
    assert result.evidence["execution_authorized"] is False


def test_allow_does_not_execute_external_action() -> None:
    side_effect = {"called": False}

    result = _evaluate(_request(input_metadata={"risk_classification": "LOW", "side_effect": side_effect}))

    assert result.decision == ALLOW
    assert side_effect["called"] is False
    assert result.execution_authorized is False


def test_ai_cannot_create_modify_approve_or_promote_policy() -> None:
    attempts = (
        {"policy_creation_attempt": True},
        {"policy_modification_attempt": True},
        {"policy_approval_attempt": True},
        {"policy_promotion_attempt": True},
        {"policy_authority_actor": "ai"},
    )

    for attempt in attempts:
        request = _request(**attempt)
        result = _evaluate(request)
        assert result.decision == BLOCK
        assert result.reason_code == "AUTONOMOUS_POLICY_AUTHORITY_BLOCKED"


def test_policy_hash_mismatch_blocks() -> None:
    result = _evaluate(_request(policy_hash=_hash("changed-policy")))

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_HASH_MISMATCH"


def test_malformed_request_blocks() -> None:
    result = _evaluate({"request_id": "missing-fields"})

    assert result.decision == BLOCK
    assert result.reason_code == "POLICY_ID_MISSING"


def test_valid_current_allow_evidence_passes_consumption_gate_without_execution_authority() -> None:
    evidence = _allow_evidence()

    result = _consume(evidence)

    assert result.decision == ALLOW
    assert result.reason_code == "DECISION_EVIDENCE_CONSUMED"
    assert result.execution_authorized is False
    assert result.evidence["execution_authorized"] is False
    assert result.evidence["decision_consumption_schema_version"] == "usbay.ai_act_live_policy_engine.decision_consumption.v1"
    assert result.evidence["consumed_decision_evidence_hash"] == evidence["current_evidence_hash"]
    assert result.evidence["previous_evidence_hash"] == evidence["current_evidence_hash"]
    assert result.evidence["authority_verification_result"] == "DECISION_EVIDENCE_CONSUMPTION_VERIFIED"


def test_consumption_gate_blocks_missing_malformed_block_and_unsupported_evidence() -> None:
    assert _consume(None).reason_code == "DECISION_EVIDENCE_MISSING"
    assert _consume({"result": ALLOW}).reason_code == "DECISION_EVIDENCE_MALFORMED"

    block_evidence = dict(_evaluate(_request(input_metadata={"risk_classification": "HIGH"})).evidence)
    assert _consume(block_evidence).reason_code == "DECISION_NOT_ALLOW"

    unsupported = _allow_evidence()
    unsupported["schema_version"] = "unsupported"
    unsupported = _rehash_evidence(unsupported)
    assert _consume(unsupported).reason_code == "DECISION_EVIDENCE_UNSUPPORTED"


def test_consumption_gate_blocks_tampered_hashes_and_broken_chain() -> None:
    tampered = _allow_evidence()
    tampered["reason_code"] = "POLICY_RULE_ALLOWED_BUT_TAMPERED"
    assert _consume(tampered).reason_code == "DECISION_EVIDENCE_INTEGRITY_FAILED"

    invalid_hash = _allow_evidence()
    invalid_hash["current_evidence_hash"] = _hash("wrong-current-hash")
    assert _consume(invalid_hash).reason_code == "DECISION_EVIDENCE_INTEGRITY_FAILED"

    broken_chain = _allow_evidence()
    broken_chain["decision_trace_previous_evidence_hash"] = _hash("broken-chain")
    broken_chain = _rehash_evidence(broken_chain)
    assert _consume(broken_chain).reason_code == "DECISION_EVIDENCE_CHAIN_INVALID"


def test_consumption_gate_blocks_request_policy_and_correlation_binding_mismatch() -> None:
    evidence = _allow_evidence()

    assert _consume(evidence, _request(request_id="other-request")).reason_code == "DECISION_BINDING_MISMATCH"
    assert _consume(evidence, _request(correlation_id="other-correlation")).reason_code == "DECISION_BINDING_MISMATCH"
    assert _consume(evidence, _request(policy_hash=_hash("other-policy"))).reason_code == "DECISION_BINDING_MISMATCH"


def test_consumption_gate_revalidates_current_authority_state() -> None:
    evidence = _allow_evidence()

    cases = (
        (_authority(authority_available=False), "DECISION_AUTHORITY_INVALID"),
        (_authority(ambiguous=True), "DECISION_AUTHORITY_INVALID"),
        (_authority(approval_evidence_valid=False), "DECISION_AUTHORITY_INVALID"),
        (_authority(revoked=True), "DECISION_POLICY_REVOKED"),
        (_authority(superseded=True, superseded_by_policy_version="2026.08.12"), "DECISION_POLICY_SUPERSEDED"),
        (_authority(policy_hash=_hash("rotated-policy")), "DECISION_BINDING_MISMATCH"),
    )

    for authority, reason_code in cases:
        result = _consume(evidence, authority=authority)
        assert result.decision == BLOCK
        assert result.reason_code == reason_code


def test_consumption_gate_blocks_current_applicability_temporal_obligation_and_precondition_changes() -> None:
    evidence = _allow_evidence()

    applicability_changed = _authority(policy_document=_policy(applicability=_applicability(policy_scopes=["different"])))
    assert _consume(evidence, authority=applicability_changed).reason_code == "DECISION_APPLICABILITY_INVALID"

    not_effective = _authority(policy_document=_policy(applicability=_applicability(effective_from="2026-08-12T00:00:00Z")))
    assert _consume(evidence, authority=not_effective).reason_code == "DECISION_TEMPORAL_INVALID"

    obligation_changed = _authority(
        policy_document=_policy(
            obligations=[
                *_obligations(),
                {
                    "obligation_id": "purpose",
                    "obligation_type": "purpose_binding_required",
                    "required": True,
                    "evidence_required": True,
                },
            ]
        )
    )
    assert _consume(evidence, authority=obligation_changed).reason_code == "DECISION_OBLIGATION_INVALID"

    request = _request()
    request["obligation_satisfaction"][0]["execution_context_hash"] = _hash("wrong-context")
    assert _consume(evidence, request).reason_code == "DECISION_BINDING_MISMATCH"


def test_consumption_gate_blocks_expired_decision_evidence() -> None:
    evidence = _allow_evidence()

    result = _consume(evidence, clock_value="2026-09-01T00:00:00Z")

    assert result.decision == BLOCK
    assert result.reason_code == "DECISION_TEMPORAL_INVALID"


def test_consumption_gate_blocks_toctou_policy_rule_change_after_allow() -> None:
    evidence = _allow_evidence()
    changed_policy = _policy(
        rules=[
            {
                "rule_id": "allow-low-risk",
                "field": "risk_classification",
                "operator": "equals",
                "value": "LOW",
                "effect": BLOCK,
            }
        ]
    )

    result = _consume(evidence, authority=_authority(policy_document=changed_policy))

    assert result.decision == BLOCK
    assert result.reason_code == "DECISION_POLICY_STALE"


def test_consumption_gate_blocks_evaluator_exception_without_allow() -> None:
    def broken_loader() -> PolicyAuthority:
        raise RuntimeError("authority unavailable")

    result = consume_decision_evidence(
        _request(),
        _allow_evidence(),
        policy_authority_loader=broken_loader,
        clock=lambda: NOW,
    )

    assert result.decision == BLOCK
    assert result.reason_code == "DECISION_EVIDENCE_CONSUMPTION_EXCEPTION"
    assert result.execution_authorized is False


def test_consumption_evidence_excludes_sensitive_data_and_rejects_sensitive_evidence() -> None:
    result = _consume(_allow_evidence())
    rendered = json.dumps(result.evidence, sort_keys=True).lower()

    assert result.decision == ALLOW
    for forbidden in ("api_key", "credential", "password", "prompt", "token", "raw_payload"):
        assert forbidden not in rendered

    sensitive_evidence = _allow_evidence()
    sensitive_evidence["token"] = "do-not-store"
    sensitive_evidence = _rehash_evidence(sensitive_evidence)
    blocked = _consume(sensitive_evidence)
    blocked_rendered = json.dumps(blocked.evidence, sort_keys=True).lower()

    assert blocked.decision == BLOCK
    assert blocked.reason_code == "DECISION_EVIDENCE_MALFORMED"
    assert "do-not-store" not in blocked_rendered
    assert "token" not in blocked_rendered


def test_consumption_gate_enforces_durable_single_use_replay_authority(tmp_path) -> None:
    evidence = _allow_evidence()
    store = SQLiteDecisionEvidenceConsumptionStore(tmp_path / "consume.db")

    first = _consume(evidence, consumption_store=store)
    second = _consume(evidence, consumption_store=store)

    assert first.decision == ALLOW
    assert first.reason_code == "DECISION_EVIDENCE_CONSUMED"
    assert first.evidence["decision_replay_result"] == FIRST_CONSUMPTION
    assert second.decision == BLOCK
    assert second.reason_code == REPLAY_BLOCKED
    assert second.evidence["decision_replay_result"] == REPLAY_BLOCKED
    assert first.evidence["execution_authorized"] is False
    assert second.evidence["execution_authorized"] is False


def test_consumption_gate_blocks_when_durable_store_unavailable() -> None:
    result = _consume(_allow_evidence(), consumption_store=UnsupportedDecisionEvidenceConsumptionStore())

    assert result.decision == BLOCK
    assert result.reason_code == "UNSUPPORTED_STORE"
    assert result.evidence["decision_replay_result"] == "UNSUPPORTED_STORE"
    assert result.evidence["execution_authorized"] is False


class _AtomicFailureStore:
    store_type = "test-failure"

    def consume_if_unused(self, *args: Any, **kwargs: Any):
        return type(
            "Result",
            (),
            {
                "result": ATOMIC_CONSUMPTION_FAILED,
                "reason_code": ATOMIC_CONSUMPTION_FAILED,
                "store_type": self.store_type,
            },
        )()


def test_consumption_gate_blocks_atomic_failure_before_allow() -> None:
    result = _consume(_allow_evidence(), consumption_store=_AtomicFailureStore())

    assert result.decision == BLOCK
    assert result.reason_code == ATOMIC_CONSUMPTION_FAILED
    assert result.evidence["decision_replay_result"] == ATOMIC_CONSUMPTION_FAILED


class _SpyStore:
    store_type = "spy"

    def __init__(self) -> None:
        self.calls = 0

    def consume_if_unused(self, *args: Any, **kwargs: Any):
        self.calls += 1
        return type(
            "Result",
            (),
            {"result": FIRST_CONSUMPTION, "reason_code": FIRST_CONSUMPTION, "store_type": self.store_type},
        )()


def test_invalid_decision_evidence_blocks_without_consuming_replay_key() -> None:
    store = _SpyStore()

    result = _consume({"result": ALLOW}, consumption_store=store)

    assert result.decision == BLOCK
    assert result.reason_code == "DECISION_EVIDENCE_MALFORMED"
    assert store.calls == 0


def test_stale_policy_blocks_without_consuming_replay_key() -> None:
    store = _SpyStore()
    evidence = _allow_evidence()

    result = _consume(evidence, authority=_authority(revoked=True), consumption_store=store)

    assert result.decision == BLOCK
    assert result.reason_code == "DECISION_POLICY_REVOKED"
    assert store.calls == 0


def test_replay_evidence_is_hash_only_and_deterministic(tmp_path) -> None:
    evidence = _allow_evidence()
    store = SQLiteDecisionEvidenceConsumptionStore(tmp_path / "consume.db")

    result = _consume(evidence, consumption_store=store)
    rendered = json.dumps(result.evidence, sort_keys=True).lower()

    assert result.decision == ALLOW
    assert result.evidence["decision_replay_schema_version"] == "usbay.ai_act_live_policy_engine.decision_replay.v1"
    assert result.evidence["replay_key_hash"].startswith("sha256:")
    assert result.evidence["decision_replay_evidence_hash"].startswith("sha256:")
    assert result.evidence["decision_replay_retention_seconds"] == 1_771_200
    for forbidden in ("api_key", "credential", "password", "prompt", "token", "raw_payload", "secret"):
        assert forbidden not in rendered


def test_exact_governed_action_binding_creates_hash_only_authorization() -> None:
    consumed = _consumed_decision()
    contract = _execution_contract()

    result = create_governed_execution_authorization(_request(), consumed, contract, clock=lambda: NOW)

    assert result.decision == ALLOW
    assert result.reason_code == "EXEC_AUTH_CREATED"
    assert result.execution_authorized is False
    assert result.evidence["execution_authorization_schema_version"] == "usbay.ai_act_live_policy_engine.execution_authorization.v1"
    assert result.evidence["execution_authorization_hash"].startswith("sha256:")
    assert result.evidence["decision_evidence_hash"] == consumed.evidence["consumed_decision_evidence_hash"]
    assert result.evidence["policy_hash"] == _hash("approved-policy")
    assert result.evidence["subject_id"] == contract["subject_id"]
    assert result.evidence["tool_id"] == contract["tool_id"]
    assert result.evidence["resource_id"] == contract["resource_id"]
    assert result.evidence["parameter_hash"] == contract["parameter_hash"]
    assert result.evidence["purpose"] == contract["purpose"]
    assert validate_governed_execution_authorization(
        result.evidence,
        _request(),
        contract,
        consumed_decision_evidence_hash=consumed.evidence["consumed_decision_evidence_hash"],
        clock=lambda: NOW,
    ) is None
    rendered = json.dumps(result.evidence, sort_keys=True).lower()
    for forbidden in ("api_key", "credential", "password", "prompt", "token", "raw_payload", "secret"):
        assert forbidden not in rendered


def test_runtime_policy_decision_validation_binds_allow_to_exact_execution_request() -> None:
    request = _request()
    evidence = _allow_evidence()
    consumed = _consume(evidence)
    contract = _execution_contract()
    authorization = _execution_authorization(request=request, consumed_decision=consumed, contract=contract)

    assert validate_runtime_policy_decision_for_execution(
        evidence,
        request,
        contract,
        authorization,
        command_hash=contract["parameter_hash"],
        consumed_decision_evidence_hash=evidence["current_evidence_hash"],
    ) is None


@pytest.mark.parametrize(
    ("contract_mutation", "reason"),
    [
        (lambda contract: contract.pop("human_intent_reference"), "EXEC_AUTH_HUMAN_INTENT_MISSING"),
        (lambda contract: contract.pop("human_intent_hash"), "EXEC_AUTH_HUMAN_INTENT_HASH_MISSING"),
        (lambda contract: contract.update({"human_intent_reference": ""}), "EXEC_AUTH_HUMAN_INTENT_MALFORMED"),
        (lambda contract: contract.update({"human_intent_approver_type": "ai"}), "EXEC_AUTH_HUMAN_INTENT_NOT_HUMAN"),
        (lambda contract: contract.update({"human_intent_expires_at": "2026-08-11T11:59:59Z"}), "EXEC_AUTH_HUMAN_INTENT_STALE"),
        (lambda contract: contract.update({"action_id": "other-action"}), "EXEC_AUTH_HUMAN_INTENT_HASH_MISMATCH"),
        (lambda contract: contract.update({"parameter_hash": _hash("changed-parameters")}), "EXEC_AUTH_HUMAN_INTENT_HASH_MISMATCH"),
        (lambda contract: contract.update({"human_intent_hash": _hash("tampered-intent")}), "EXEC_AUTH_HUMAN_INTENT_HASH_MISMATCH"),
        (lambda contract: contract.update({"human_intent_reference": "intent-human-approved-002"}), "EXEC_AUTH_HUMAN_INTENT_HASH_MISMATCH"),
    ],
)
def test_execution_authorization_creation_blocks_invalid_human_intent_binding(
    contract_mutation,
    reason: str,
) -> None:
    consumed = _consumed_decision()
    contract = _execution_contract()
    contract_mutation(contract)

    result = create_governed_execution_authorization(_request(), consumed, contract, clock=lambda: NOW)

    assert result.decision == BLOCK
    assert result.reason_code == reason
    assert result.evidence["execution_authorization_result"] == "BLOCK"
    assert "human_intent_reference" not in result.evidence
    assert "intent-human-approved" not in json.dumps(result.evidence).lower()


def test_execution_authorization_evidence_binds_non_sensitive_human_intent() -> None:
    consumed = _consumed_decision()
    contract = _execution_contract()

    result = create_governed_execution_authorization(_request(), consumed, contract, clock=lambda: NOW)

    assert result.decision == ALLOW
    assert result.evidence["human_intent_reference"] == contract["human_intent_reference"]
    assert result.evidence["human_intent_hash"] == contract["human_intent_hash"]
    assert result.evidence["human_intent_verification_result"] == "HUMAN_INTENT_VERIFIED"
    assert validate_governed_execution_authorization(
        result.evidence,
        _request(),
        contract,
        consumed_decision_evidence_hash=consumed.evidence["consumed_decision_evidence_hash"],
        clock=lambda: NOW,
    ) is None
    rendered = json.dumps(result.evidence, sort_keys=True).lower()
    assert "human intent raw" not in rendered
    assert "approve this exact command" not in rendered


@pytest.mark.parametrize(
    ("evidence_factory", "reason"),
    [
        (lambda: None, "RUNTIME_POLICY_DECISION_MISSING"),
        (lambda: _evaluate(_request(input_metadata={"risk_classification": "HIGH"})).evidence, "RUNTIME_POLICY_DECISION_NOT_ALLOW"),
        (lambda: {**_allow_evidence(), "current_evidence_hash": _hash("tampered")}, "DECISION_EVIDENCE_INTEGRITY_FAILED"),
        (lambda: {**_allow_evidence(), "token": "sensitive"}, "RUNTIME_POLICY_DECISION_MALFORMED"),
    ],
)
def test_runtime_policy_decision_validation_blocks_missing_deny_tampered_and_sensitive_evidence(
    evidence_factory,
    reason: str,
) -> None:
    request = _request()
    evidence = evidence_factory()
    valid_evidence = _allow_evidence()
    consumed = _consume(valid_evidence)
    contract = _execution_contract()
    authorization = _execution_authorization(request=request, consumed_decision=consumed, contract=contract)

    assert validate_runtime_policy_decision_for_execution(
        evidence,
        request,
        contract,
        authorization,
        command_hash=contract["parameter_hash"],
        consumed_decision_evidence_hash=valid_evidence["current_evidence_hash"],
    ) == reason


def test_runtime_policy_decision_validation_blocks_replay_against_different_request() -> None:
    original_evidence = _allow_evidence()
    replayed_request = _request(request_id="other-request")
    consumed = _consume(original_evidence)
    contract = _execution_contract()
    authorization = _execution_authorization(consumed_decision=consumed, contract=contract)

    assert validate_runtime_policy_decision_for_execution(
        original_evidence,
        replayed_request,
        contract,
        authorization,
        command_hash=contract["parameter_hash"],
        consumed_decision_evidence_hash=original_evidence["current_evidence_hash"],
    ) == "DECISION_BINDING_MISMATCH"


def test_runtime_policy_decision_validation_blocks_command_substitution() -> None:
    evidence = _allow_evidence()
    consumed = _consume(evidence)
    contract = _execution_contract()
    authorization = _execution_authorization(consumed_decision=consumed, contract=contract)

    assert validate_runtime_policy_decision_for_execution(
        evidence,
        _request(),
        contract,
        authorization,
        command_hash=_hash("altered-command"),
        consumed_decision_evidence_hash=evidence["current_evidence_hash"],
    ) == "RUNTIME_POLICY_COMMAND_HASH_MISMATCH"


def test_runtime_policy_decision_validation_blocks_consumed_hash_mismatch() -> None:
    evidence = _allow_evidence()
    consumed = _consume(evidence)
    contract = _execution_contract()
    authorization = _execution_authorization(consumed_decision=consumed, contract=contract)

    assert validate_runtime_policy_decision_for_execution(
        evidence,
        _request(),
        contract,
        authorization,
        command_hash=contract["parameter_hash"],
        consumed_decision_evidence_hash=_hash("other-consumed-decision"),
    ) == "RUNTIME_POLICY_DECISION_HASH_MISMATCH"


def test_equivalent_execution_authorization_inputs_are_deterministic() -> None:
    consumed = _consumed_decision()
    contract = _execution_contract()

    first = _execution_authorization(consumed_decision=consumed, contract=contract)
    second = _execution_authorization(consumed_decision=consumed, contract=dict(contract))

    assert first["execution_authorization_hash"] == second["execution_authorization_hash"]
    changed = _execution_authorization(
        consumed_decision=consumed,
        contract=_execution_contract(parameter_hash=_hash("changed-parameters")),
    )
    assert changed["execution_authorization_hash"] != first["execution_authorization_hash"]


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("tool_id", "other-tool", "EXEC_AUTH_ACTION_MISMATCH"),
        ("action_id", "other-action", "EXEC_AUTH_ACTION_MISMATCH"),
        ("resource_id", "other-resource", "EXEC_AUTH_RESOURCE_MISMATCH"),
        ("target_id", "other-target", "EXEC_AUTH_RESOURCE_MISMATCH"),
        ("parameter_hash", _hash("changed-parameters"), "EXEC_AUTH_PARAMETER_MISMATCH"),
        ("subject_id", "other-subject", "EXEC_AUTH_SUBJECT_MISMATCH"),
        ("agent_id", "other-agent", "EXEC_AUTH_SUBJECT_MISMATCH"),
        ("purpose", "other-purpose", "EXEC_AUTH_PURPOSE_MISMATCH"),
    ],
)
def test_execution_authorization_validation_blocks_action_binding_mismatches(
    field: str,
    value: str,
    reason: str,
) -> None:
    consumed = _consumed_decision()
    contract = _execution_contract()
    authorization = _execution_authorization(consumed_decision=consumed, contract=contract)
    changed_contract = _execution_contract(**{field: value})

    assert validate_governed_execution_authorization(
        authorization,
        _request(),
        changed_contract,
        consumed_decision_evidence_hash=consumed.evidence["consumed_decision_evidence_hash"],
        clock=lambda: NOW,
    ) == reason


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda auth: auth.pop("tool_id"), "EXEC_AUTH_MALFORMED"),
        (lambda auth: auth.update({"purpose": "tampered"}), "EXEC_AUTH_PURPOSE_MISMATCH"),
        (lambda auth: auth.update({"execution_authorization_hash": _hash("tampered")}), "EXEC_AUTH_TAMPERED"),
        (lambda auth: auth.update({"decision_evidence_hash": _hash("other-decision")}), "EXEC_AUTH_DECISION_LINK_INVALID"),
        (lambda auth: auth.update({"policy_hash": _hash("other-policy")}), "EXEC_AUTH_POLICY_LINK_INVALID"),
        (lambda auth: auth.update({"decision_replay_result": REPLAY_BLOCKED}), "EXEC_AUTH_REUSED"),
        (lambda auth: auth.update({"expires_at": "2026-08-11T11:59:59Z"}), "EXEC_AUTH_EXPIRED"),
    ],
)
def test_execution_authorization_validation_blocks_malformed_tampered_and_stale_authorization(
    mutate,
    reason: str,
) -> None:
    consumed = _consumed_decision()
    contract = _execution_contract()
    authorization = _execution_authorization(consumed_decision=consumed, contract=contract)
    mutate(authorization)

    assert validate_governed_execution_authorization(
        authorization,
        _request(),
        contract,
        consumed_decision_evidence_hash=consumed.evidence["consumed_decision_evidence_hash"],
        clock=lambda: NOW,
    ) == reason


def test_execution_authorization_creation_blocks_missing_invalid_and_reused_inputs() -> None:
    consumed = _consumed_decision()
    assert create_governed_execution_authorization(_request(), consumed, None, clock=lambda: NOW).reason_code == "EXEC_AUTH_MISSING"

    contract = _execution_contract()
    missing_field = dict(contract)
    missing_field.pop("tool_id")
    assert create_governed_execution_authorization(_request(), consumed, missing_field, clock=lambda: NOW).reason_code == "EXEC_AUTH_ACTION_MISMATCH"

    block_decision = _evaluate(_request(input_metadata={"risk_classification": "HIGH"}))
    assert create_governed_execution_authorization(_request(), block_decision, contract, clock=lambda: NOW).reason_code == "EXEC_AUTH_DECISION_LINK_INVALID"

    reused = dict(consumed.evidence)
    reused["decision_replay_result"] = REPLAY_BLOCKED
    reused = _rehash_evidence(reused)
    assert create_governed_execution_authorization(_request(), reused, contract, clock=lambda: NOW).reason_code == "EXEC_AUTH_REUSED"

    tampered = dict(consumed.evidence)
    tampered["policy_hash"] = _hash("other-policy")
    assert create_governed_execution_authorization(_request(), tampered, contract, clock=lambda: NOW).reason_code == "EXEC_AUTH_TAMPERED"


def test_execution_authorization_engine_does_not_execute_side_effect() -> None:
    side_effect = {"called": False}

    result = create_governed_execution_authorization(
        _request(input_metadata={"risk_classification": "LOW", "side_effect": side_effect}),
        _consumed_decision(),
        _execution_contract(),
        clock=lambda: NOW,
    )

    assert result.decision == BLOCK
    assert side_effect["called"] is False
    assert result.execution_authorized is False
