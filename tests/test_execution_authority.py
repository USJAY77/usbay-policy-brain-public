from runtime.execution_authority.authority_registry import AuthorityRecord, AuthorityRegistry
from runtime.execution_authority.execution_authority import ExecutionAuthority


def _authority() -> ExecutionAuthority:
    registry = AuthorityRegistry.from_records(
        [AuthorityRecord("auth-1", "USBAY-GLOBAL23", ("execute:runtime", "review:execution"))]
    )
    return ExecutionAuthority(registry)


def test_execution_authority_allows_valid_scope() -> None:
    decision = _authority().validate(
        execution_id="exec-1",
        authority_id="auth-1",
        required_scope="execute:runtime",
        policy_version="pb173",
    )

    assert decision.decision == "ALLOW"
    assert decision.owner == "USBAY-GLOBAL23"
    assert decision.audit_hash


def test_execution_authority_fail_closed_missing_authority() -> None:
    decision = _authority().validate(
        execution_id="exec-1",
        authority_id=None,
        required_scope="execute:runtime",
        policy_version="pb173",
    )

    assert decision.decision == "FAIL_CLOSED"
    assert decision.reason == "authority_missing"


def test_execution_authority_blocks_wrong_scope() -> None:
    decision = _authority().validate(
        execution_id="exec-1",
        authority_id="auth-1",
        required_scope="delete:production",
        policy_version="pb173",
    )

    assert decision.decision == "BLOCK"
    assert decision.reason == "scope_not_authorized"


def test_execution_authority_blocks_revoked_authority() -> None:
    registry = AuthorityRegistry.from_records([AuthorityRecord("auth-1", "USBAY-AUDIT", ("execute:runtime",))])
    registry.revoke("auth-1")
    decision = ExecutionAuthority(registry).validate(
        execution_id="exec-1",
        authority_id="auth-1",
        required_scope="execute:runtime",
        policy_version="pb173",
    )

    assert decision.decision == "BLOCK"
    assert decision.reason == "authority_revoked"

