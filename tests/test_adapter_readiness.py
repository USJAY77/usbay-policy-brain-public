from runtime.execution_adapters.adapter_approval_binding import validate_adapter_approval_binding
from runtime.execution_adapters.adapter_readiness import AdapterRegistration, evaluate_adapter_readiness


def _binding():
    return validate_adapter_approval_binding(
        decision_id="decision-1",
        approval_id="approval-1",
        policy_version="pb182",
        execution_token="token-1",
        authority_id="authority-1",
    )


def _registrations():
    return [
        AdapterRegistration("desktop", "runtime.execution_adapters.desktop_adapter", True, True, True, True),
        AdapterRegistration("browser", "runtime.execution_adapters.browser_adapter", True, True, True, True),
        AdapterRegistration("api", "runtime.execution_adapters.api_adapter", True, True, True, True),
    ]


def test_adapter_readiness_verifies_registered_mock_adapters() -> None:
    readiness = evaluate_adapter_readiness(_registrations(), _binding())

    assert readiness.decision == "VERIFIED"
    assert readiness.status == "READY_FOR_REVIEW"
    assert readiness.report["live_execution_enabled"] is False
    assert readiness.audit_hash


def test_adapter_readiness_fail_closed_missing_adapter() -> None:
    readiness = evaluate_adapter_readiness(_registrations()[:2], _binding())

    assert readiness.decision == "FAIL_CLOSED"
    assert "api" in readiness.missing_adapters
    assert "adapter_registration_missing" in readiness.report["failed_controls"]


def test_adapter_readiness_fail_closed_invalid_approval_binding() -> None:
    readiness = evaluate_adapter_readiness(_registrations(), None)

    assert readiness.decision == "FAIL_CLOSED"
    assert "approval_binding_invalid" in readiness.report["failed_controls"]


def test_adapter_readiness_fail_closed_if_live_execution_enabled() -> None:
    registrations = [
        AdapterRegistration("desktop", "runtime.execution_adapters.desktop_adapter", True, True, True, True, True),
        AdapterRegistration("browser", "runtime.execution_adapters.browser_adapter", True, True, True, True),
        AdapterRegistration("api", "runtime.execution_adapters.api_adapter", True, True, True, True),
    ]

    readiness = evaluate_adapter_readiness(registrations, _binding())

    assert readiness.decision == "FAIL_CLOSED"
    assert "desktop_live_execution_enabled" in readiness.report["failed_controls"]

