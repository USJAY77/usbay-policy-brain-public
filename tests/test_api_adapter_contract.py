from runtime.execution_adapters.adapter_approval_binding import validate_adapter_approval_binding
from runtime.execution_adapters.api_adapter import ApiAdapterContract, ApiRequestContract


def _binding():
    return validate_adapter_approval_binding(
        decision_id="decision-1",
        approval_id="approval-1",
        policy_version="pb180",
        execution_token="token-1",
        authority_id="authority-1",
    )


def _request(method: str = "GET", binding=None, dry_run: bool = True):
    return ApiRequestContract(
        request_id="api-request-1",
        method=method,
        endpoint="/mock/governance/status",
        policy_version="pb180",
        audit_id="audit-1",
        approval_binding=binding,
        dry_run=dry_run,
    )


def test_api_adapter_allows_low_risk_mock_get() -> None:
    response = ApiAdapterContract().validate(_request())

    assert response.status == "ALLOW"
    assert response.outbound_request_performed is False
    assert response.audit_hash


def test_api_adapter_requires_review_for_mutating_method() -> None:
    response = ApiAdapterContract().validate(_request("POST"))

    assert response.status == "HUMAN_REVIEW"
    assert response.reason == "api_mutation_requires_approval"


def test_api_adapter_allows_mutating_method_with_valid_binding_only_as_contract() -> None:
    response = ApiAdapterContract().validate(_request("DELETE", _binding()))

    assert response.status == "ALLOW"
    assert response.outbound_request_performed is False


def test_api_adapter_blocks_unsupported_method() -> None:
    response = ApiAdapterContract().validate(_request("TRACE"))

    assert response.status == "BLOCK"
    assert response.reason == "unsupported_api_method"


def test_api_adapter_fail_closed_when_live_request_requested() -> None:
    response = ApiAdapterContract().validate(_request(dry_run=False))

    assert response.status == "FAIL_CLOSED"
    assert response.reason == "live_api_request_forbidden"

