from runtime.execution_authority.execution_token import ExecutionTokenLifecycle


def test_execution_token_valid_once() -> None:
    lifecycle = ExecutionTokenLifecycle()
    token = lifecycle.issue("exec-1", "auth-1")

    valid, reason = lifecycle.validate(token.token_id, "exec-1")
    replay_valid, replay_reason = lifecycle.validate(token.token_id, "exec-1")

    assert valid is True
    assert reason == "token_valid"
    assert replay_valid is False
    assert replay_reason == "token_replay"


def test_execution_token_expired_blocks() -> None:
    lifecycle = ExecutionTokenLifecycle()
    token = lifecycle.issue("exec-1", "auth-1", ttl_seconds=-1)

    valid, reason = lifecycle.validate(token.token_id, "exec-1")

    assert valid is False
    assert reason == "token_expired"


def test_execution_token_revoked_blocks() -> None:
    lifecycle = ExecutionTokenLifecycle()
    token = lifecycle.issue("exec-1", "auth-1")
    lifecycle.revoke(token.token_id)

    valid, reason = lifecycle.validate(token.token_id, "exec-1")

    assert valid is False
    assert reason == "token_revoked"


def test_execution_token_execution_mismatch_blocks() -> None:
    lifecycle = ExecutionTokenLifecycle()
    token = lifecycle.issue("exec-1", "auth-1")

    valid, reason = lifecycle.validate(token.token_id, "exec-2")

    assert valid is False
    assert reason == "token_execution_mismatch"

