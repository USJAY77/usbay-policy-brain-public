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


def _policy(*, rules: list[dict[str, Any]] | None = None, fail_closed: bool = True, enabled: bool = True) -> dict[str, Any]:
    return {
        "policy_id": "ai-act-live-policy-v1",
        "policy_version": "2026.08.11",
        "fail_closed": fail_closed,
        "ai_act_live_policy_engine": {
            "enabled": enabled,
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
    payload = {
        "request_id": "req-ai-act-live-001",
        "correlation_id": "corr-ai-act-live-001",
        "tenant_id": "tenant-usbay",
        "environment": "pilot",
        "actor_id": "human-approved-runtime",
        "policy_id": "ai-act-live-policy-v1",
        "policy_version": "2026.08.11",
        "policy_hash": _hash("approved-policy"),
        "input_metadata": {"risk_classification": "LOW", "system_type": "bounded_ai_act"},
    }
    payload.update(overrides)
    return payload


def _evaluate(request: dict[str, Any] | None = None, authority: PolicyAuthority | None = None):
    return evaluate_live_policy(
        _request() if request is None else request,
        policy_authority_loader=lambda: authority or _authority(),
        previous_evidence_hash=ZERO_SHA256_REFERENCE,
        clock=lambda: NOW,
    )


def test_valid_allow_returns_allow_without_execution_authority() -> None:
    result = _evaluate()

    assert result.decision == ALLOW
    assert result.reason_code == "POLICY_RULE_ALLOWED"
    assert result.evidence["authority_verification_result"] == "POLICY_AUTHORITY_VERIFIED"
    assert result.execution_authorized is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
    assert result.evidence["execution_authorized"] is False


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
