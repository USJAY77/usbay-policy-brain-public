from runtime.execution_authority.execution_evidence import bind_execution_evidence


def test_execution_evidence_binds_all_required_references() -> None:
    binding = bind_execution_evidence(
        execution_id="exec-1",
        approval_id="approval-1",
        contract_id="contract-1",
        decision_id="decision-1",
        audit_chain_id="audit-1",
        policy_version="pb177",
    )

    assert binding.decision == "VERIFIED"
    assert binding.reason == "evidence_bound"
    assert binding.evidence_hash


def test_execution_evidence_fail_closed_missing_approval() -> None:
    binding = bind_execution_evidence(
        execution_id="exec-1",
        approval_id=None,
        contract_id="contract-1",
        decision_id="decision-1",
        audit_chain_id="audit-1",
        policy_version="pb177",
    )

    assert binding.decision == "FAIL_CLOSED"
    assert "approval_id" in binding.reason

