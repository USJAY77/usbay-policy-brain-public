from runtime.execution_authority.authority_registry import AuthorityRecord, AuthorityRegistry
from runtime.execution_authority.execution_revocation import ExecutionRevocationFramework
from runtime.execution_authority.execution_token import ExecutionTokenLifecycle


def test_execution_revocation_invalidates_execution_token_and_authority() -> None:
    registry = AuthorityRegistry.from_records([AuthorityRecord("auth-1", "USBAY-AUDIT", ("execute:runtime",))])
    tokens = ExecutionTokenLifecycle()
    token = tokens.issue("exec-1", "auth-1")
    framework = ExecutionRevocationFramework(registry, tokens)

    record = framework.revoke_execution(
        execution_id="exec-1",
        reason="security revoke",
        token_id=token.token_id,
        authority_id="auth-1",
    )

    assert framework.is_revoked("exec-1") is True
    assert tokens.validate(token.token_id, "exec-1") == (False, "token_revoked")
    assert registry.get("auth-1").active is False
    assert record.audit_hash


def test_execution_revocation_records_without_token_or_authority() -> None:
    framework = ExecutionRevocationFramework(AuthorityRegistry(), ExecutionTokenLifecycle())

    record = framework.revoke_execution(execution_id="exec-1", reason="manual revoke")

    assert record.execution_id == "exec-1"
    assert record.reason == "manual revoke"
    assert framework.is_revoked("exec-1") is True

