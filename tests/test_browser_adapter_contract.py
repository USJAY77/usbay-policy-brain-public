from runtime.execution_adapters.adapter_approval_binding import validate_adapter_approval_binding
from runtime.execution_adapters.browser_adapter import (
    BrowserActionSchema,
    BrowserAdapterContract,
    BrowserAdapterRequest,
    BrowserNavigationSchema,
)


def _binding():
    return validate_adapter_approval_binding(
        decision_id="decision-1",
        approval_id="approval-1",
        policy_version="pb179",
        execution_token="token-1",
        authority_id="authority-1",
    )


def _request(action_type: str = "read_page", target: str = "status page", risk_level: str = "LOW", binding=None):
    return BrowserAdapterRequest(
        action=BrowserActionSchema(
            action_id="browser-action-1",
            action_type=action_type,
            target=target,
            risk_level=risk_level,
            approval_binding=binding,
        ),
        navigation=BrowserNavigationSchema("https://example.invalid/status", "example.invalid", "mock_read"),
        policy_version="pb179",
        audit_id="audit-1",
    )


def test_browser_adapter_allows_low_risk_mock_read() -> None:
    decision = BrowserAdapterContract().validate(_request())

    assert decision.decision == "ALLOW"
    assert decision.live_execution_performed is False
    assert decision.audit_hash


def test_browser_adapter_requires_review_for_github_merge_target() -> None:
    decision = BrowserAdapterContract().validate(_request("click", "GitHub merge button", "HIGH"))

    assert decision.decision == "HUMAN_REVIEW"
    assert decision.reason == "browser_action_requires_approval"


def test_browser_adapter_allows_privileged_target_only_with_valid_binding() -> None:
    decision = BrowserAdapterContract().validate(_request("click", "GitHub merge button", "HIGH", _binding()))

    assert decision.decision == "ALLOW"
    assert decision.live_execution_performed is False


def test_browser_adapter_blocks_unknown_action() -> None:
    decision = BrowserAdapterContract().validate(_request("execute_javascript", "page", "HIGH"))

    assert decision.decision == "BLOCK"
    assert decision.reason == "unsupported_browser_action"


def test_browser_adapter_fail_closed_without_audit_binding() -> None:
    request = BrowserAdapterRequest(
        action=_request().action,
        navigation=_request().navigation,
        policy_version="pb179",
        audit_id=None,
    )

    decision = BrowserAdapterContract().validate(request)

    assert decision.decision == "FAIL_CLOSED"
    assert decision.reason == "audit_id_missing"

