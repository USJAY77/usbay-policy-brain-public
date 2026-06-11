from runtime.execution_adapters.adapter_approval_binding import validate_adapter_approval_binding
from runtime.execution_adapters.desktop_adapter import (
    DesktopActionSchema,
    DesktopAdapterContract,
    DesktopExecutionRequest,
    DesktopTargetSchema,
)


def _binding():
    return validate_adapter_approval_binding(
        decision_id="decision-1",
        approval_id="approval-1",
        policy_version="pb178",
        execution_token="token-1",
        authority_id="authority-1",
    )


def _request(action_type: str = "read_screen", risk_level: str = "LOW", approval_binding=None, dry_run: bool = True):
    return DesktopExecutionRequest(
        action=DesktopActionSchema(
            action_id="desktop-action-1",
            action_type=action_type,
            risk_level=risk_level,
            required_capability="desktop:mock",
        ),
        target=DesktopTargetSchema("target-1", "window", (10, 20)),
        policy_version="pb178",
        audit_id="audit-1",
        approval_binding=approval_binding,
        dry_run=dry_run,
    )


def test_desktop_adapter_allows_low_risk_mock_request() -> None:
    decision = DesktopAdapterContract().validate(_request())

    assert decision.decision == "ALLOW"
    assert decision.live_execution_performed is False
    assert decision.audit_hash


def test_desktop_adapter_requires_review_for_high_risk_click_without_approval() -> None:
    decision = DesktopAdapterContract().validate(_request("click", "HIGH"))

    assert decision.decision == "HUMAN_REVIEW"
    assert decision.reason == "desktop_action_requires_approval"


def test_desktop_adapter_allows_high_risk_click_with_valid_binding_only_as_contract() -> None:
    decision = DesktopAdapterContract().validate(_request("click", "HIGH", _binding()))

    assert decision.decision == "ALLOW"
    assert decision.live_execution_performed is False


def test_desktop_adapter_blocks_unknown_action() -> None:
    decision = DesktopAdapterContract().validate(_request("launch_process", "HIGH"))

    assert decision.decision == "BLOCK"
    assert decision.reason == "unsupported_desktop_action"


def test_desktop_adapter_fail_closed_when_live_execution_requested() -> None:
    decision = DesktopAdapterContract().validate(_request(dry_run=False))

    assert decision.decision == "FAIL_CLOSED"
    assert decision.reason == "live_desktop_execution_forbidden"

