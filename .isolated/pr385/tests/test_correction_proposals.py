from governance.correction_proposals import (
    APPROVAL_APPROVED,
    APPROVAL_REJECTED,
    DECISION_DENY,
    DECISION_MANUAL_EXECUTION_ELIGIBLE,
    DECISION_PROPOSE,
    EXECUTION_BLOCKED,
    EXECUTION_NOT_EXECUTED,
    REASON_APPROVAL_EXPIRED,
    REASON_APPROVAL_REJECTED,
    REASON_APPROVAL_REQUIRED,
    REASON_OK,
    REASON_UNKNOWN_STATE,
    audit_evidence,
    detect_governance_issue,
    evaluate_proposal_approval,
    generate_correction_proposal,
    proposal_hash,
    with_approval_status,
)


FIXED_TIME = "2026-06-12T00:00:00Z"


def _proposal(issue_type="CI_FAILURE", expires_at=""):
    issue = detect_governance_issue(
        issue_type,
        observed_failure="governance validation failed without raw output",
        source="codex-autofix-ci",
    )
    return generate_correction_proposal(
        issue,
        timestamp=FIXED_TIME,
        expires_at=expires_at,
    )


def test_correction_proposal_generated_with_required_audit_fields():
    proposal = _proposal("DEPENDENCY_REMEDIATION")

    assert proposal["proposal_id"]
    assert proposal["proposal_hash"] == proposal_hash(proposal)
    assert proposal["risk_level"] == "MEDIUM"
    assert proposal["approval_status"] == "PENDING"
    assert proposal["execution_status"] == EXECUTION_BLOCKED
    assert proposal["human_approval_required"] is True
    assert proposal["auto_execution_allowed"] is False
    evidence = proposal["audit_evidence"]
    assert evidence["proposal_id"] == proposal["proposal_id"]
    assert evidence["proposal_hash"] == proposal["proposal_hash"]
    assert evidence["risk_level"] == proposal["risk_level"]
    assert evidence["proposed_action"] == proposal["proposed_action"]
    assert evidence["approval_status"] == proposal["approval_status"]
    assert evidence["execution_status"] == proposal["execution_status"]
    assert evidence["timestamp"] == FIXED_TIME
    assert evidence["audit_hash"]


def test_pending_proposal_requires_human_approval_and_cannot_execute():
    proposal = _proposal()

    result = evaluate_proposal_approval(proposal, now=FIXED_TIME)

    assert result["decision"] == DECISION_DENY
    assert result["reason_code"] == REASON_APPROVAL_REQUIRED
    assert result["execution_status"] == EXECUTION_BLOCKED
    assert result["auto_execution_allowed"] is False


def test_rejected_proposal_is_denied():
    proposal = with_approval_status(_proposal("RUNTIME_DRIFT"), APPROVAL_REJECTED)

    result = evaluate_proposal_approval(proposal, now=FIXED_TIME)

    assert result["decision"] == DECISION_DENY
    assert result["reason_code"] == REASON_APPROVAL_REJECTED
    assert result["execution_status"] == EXECUTION_BLOCKED


def test_approved_proposal_is_manual_execution_eligible_but_not_executed():
    proposal = with_approval_status(_proposal("REVOCATION"), APPROVAL_APPROVED)

    result = evaluate_proposal_approval(proposal, now=FIXED_TIME)

    assert result["decision"] == DECISION_MANUAL_EXECUTION_ELIGIBLE
    assert result["reason_code"] == REASON_OK
    assert result["execution_status"] == EXECUTION_NOT_EXECUTED
    assert result["auto_execution_allowed"] is False
    assert result["audit_evidence"]["execution_status"] == EXECUTION_NOT_EXECUTED


def test_expired_proposal_is_denied_even_if_approved():
    proposal = with_approval_status(
        _proposal("NONCE_STORE", expires_at="2026-06-11T00:00:00Z"),
        APPROVAL_APPROVED,
    )

    result = evaluate_proposal_approval(proposal, now=FIXED_TIME)

    assert result["decision"] == DECISION_DENY
    assert result["reason_code"] == REASON_APPROVAL_EXPIRED
    assert result["execution_status"] == EXECUTION_BLOCKED


def test_unknown_or_tampered_proposal_state_denies():
    proposal = _proposal()
    proposal["approval_status"] = "MAYBE"
    proposal["proposal_hash"] = proposal_hash(proposal)
    unknown = evaluate_proposal_approval(proposal, now=FIXED_TIME)
    tampered = _proposal()
    tampered["proposed_action"] = "execute_without_approval"

    tampered_result = evaluate_proposal_approval(tampered, now=FIXED_TIME)

    assert unknown["decision"] == DECISION_DENY
    assert unknown["reason_code"] == REASON_UNKNOWN_STATE
    assert tampered_result["decision"] == DECISION_DENY
    assert tampered_result["reason_code"] == REASON_UNKNOWN_STATE


def test_unsupported_issue_detection_denies():
    result = detect_governance_issue("UNKNOWN", observed_failure="unknown", source="local")

    assert result["decision"] == DECISION_DENY
    assert result["reason_code"] == "unsupported_proposal_issue"


def test_audit_evidence_is_deterministic_for_same_proposal_and_reason():
    proposal = _proposal()

    first = audit_evidence(proposal, reason_code=REASON_APPROVAL_REQUIRED)
    second = audit_evidence(proposal, reason_code=REASON_APPROVAL_REQUIRED)

    assert first == second
