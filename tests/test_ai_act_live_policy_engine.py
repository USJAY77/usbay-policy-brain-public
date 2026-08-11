from __future__ import annotations

import json
from typing import Any

from governance.hashing import ZERO_SHA256_REFERENCE, sha256_reference
from runtime.computer_use.ai_act_live_policy_engine import (
    ALLOW,
    BLOCK,
    PolicyAuthority,
    evaluate_live_policy,
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


def test_sensitive_data_is_rejected_and_not_stored_in_evidence() -> None:
    result = _evaluate(_request(input_metadata={"risk_classification": "LOW", "token": "do-not-store"}))
    rendered = json.dumps(result.evidence, sort_keys=True)

    assert result.decision == BLOCK
    assert result.reason_code == "SENSITIVE_DATA_REJECTED"
    assert "do-not-store" not in rendered
    assert "token" not in rendered.lower()
    assert "raw_payload" not in rendered
    assert "prompt" not in rendered


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
