from pilot_operations.end_to_end_dry_run import (
    build_cross_system_evidence_trace,
    build_end_to_end_dry_run_scenario,
)


def test_cross_system_trace_hash_chains_every_step():
    trace = build_cross_system_evidence_trace()

    assert trace["decision"] == "VERIFIED"
    assert trace["status"] == "READY_FOR_REVIEW"
    assert trace["record_count"] == 8
    assert trace["audit_chain"]["record_count"] == 8
    assert trace["audit_chain"]["external_execution_performed"] is False
    assert trace["sensitive_data_stored"] is False


def test_missing_step_evidence_fails_closed():
    scenario = build_end_to_end_dry_run_scenario()
    scenario["steps"] = scenario["steps"][:-1]

    trace = build_cross_system_evidence_trace(scenario)

    assert trace["decision"] == "FAIL_CLOSED"
    assert "MISSING_WORKFLOW_STEPS" in trace["gaps"]
    assert "MISSING_EVIDENCE_TERMINAL" in trace["gaps"]


def test_unknown_step_decision_fails_closed():
    scenario = build_end_to_end_dry_run_scenario()
    scenario["steps"][0]["decision"] = "UNKNOWN"

    trace = build_cross_system_evidence_trace(scenario)

    assert trace["decision"] == "FAIL_CLOSED"
    assert "UNVERIFIED_STEP_LINKEDIN" in trace["gaps"]
