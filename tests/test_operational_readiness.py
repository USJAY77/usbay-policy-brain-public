from control_plane.operational_readiness import OperationalReadinessInput, validate_operational_readiness


def test_operational_readiness_verifies_all_control_plane_inputs() -> None:
    report = validate_operational_readiness(
        OperationalReadinessInput(
            governance="VERIFIED",
            runtime="VERIFIED",
            authority="VERIFIED",
            adapters="VERIFIED",
            review_workflows="VERIFIED",
        )
    )

    assert report.decision == "VERIFIED"
    assert report.status == "READY_FOR_REVIEW"
    assert report.report["live_execution_enabled"] is False
    assert report.report["network_calls_enabled"] is False
    assert report.audit_hash


def test_operational_readiness_fail_closed_on_missing_adapter_readiness() -> None:
    report = validate_operational_readiness(
        OperationalReadinessInput(
            governance="VERIFIED",
            runtime="VERIFIED",
            authority="VERIFIED",
            adapters="FAIL_CLOSED",
            review_workflows="VERIFIED",
        )
    )

    assert report.decision == "FAIL_CLOSED"
    assert report.status == "BLOCKED"
    assert report.failed_controls == ("adapters",)

