from pathlib import Path

import pytest

from governance.hashing import sha256_reference
import runtime.replit_executor as replit_executor


class _SignerAdapter:
    signer_type = "test_runtime_signer"

    def sign_file(self, *, payload_path: Path, signature_path: Path, cwd: Path) -> None:
        return None


def _command() -> dict:
    return {
        "entrypoint": "echo",
        "args": ["ok"],
    }


def _hash(label: str) -> str:
    return sha256_reference({"label": label})


def _governed_request() -> dict:
    return {
        "request_id": "req-ai-act-live-001",
        "correlation_id": "corr-ai-act-live-001",
        "tenant_id": "tenant-usbay",
        "environment": "pilot",
        "actor_id": "human-approved-runtime",
        "policy_id": "ai-act-live-policy-v1",
        "policy_version": "2026.08.11",
        "policy_hash": _hash("approved-policy"),
        "input_metadata": {"risk_classification": "LOW", "system_type": "bounded_ai_act"},
    }


def _execution_contract(**overrides) -> dict:
    payload = {
        "subject_id": "human-approved-runtime",
        "agent_id": "replit-executor",
        "action_id": "execute-command",
        "tool_id": "runtime.replit_executor.execute_command",
        "resource_id": "commands/test_command.json",
        "target_id": "local-subprocess",
        "parameter_hash": _hash("echo-ok-command"),
        "purpose": "bounded_ai_act_runtime_execution",
        "expires_at": "2026-09-01T00:00:00Z",
        "authorization_nonce": "exec-auth-nonce-001",
    }
    payload.update(overrides)
    return payload


def _authorization(**overrides) -> dict:
    payload = {
        "execution_authorization_schema_version": "usbay.ai_act_live_policy_engine.execution_authorization.v1",
        "execution_authorization_result": "ALLOW",
        "execution_authorization_validation_result": "EXEC_AUTH_VALID",
        "authorization_id": "exec-auth-001",
        "consumed_decision_id": "ai-act-live-policy-decision",
        "decision_evidence_hash": _hash("allow-decision-evidence"),
        "decision_consumption_evidence_hash": _hash("consumed-decision-evidence"),
        "decision_replay_evidence_hash": _hash("decision-replay-evidence"),
        "decision_replay_result": "FIRST_CONSUMPTION",
        "correlation_id": "corr-ai-act-live-001",
        "request_hash": replit_executor.ai_act_live_policy_engine._request_hash(_governed_request()),
        "policy_id": "ai-act-live-policy-v1",
        "policy_version": "2026.08.11",
        "policy_hash": _hash("approved-policy"),
        "human_policy_authority_reference": _hash("authority-state"),
        "subject_id": "human-approved-runtime",
        "agent_id": "replit-executor",
        "action_id": "execute-command",
        "tool_id": "runtime.replit_executor.execute_command",
        "resource_id": "commands/test_command.json",
        "target_id": "local-subprocess",
        "parameter_hash": _hash("echo-ok-command"),
        "purpose": "bounded_ai_act_runtime_execution",
        "issued_at": "2026-08-11T12:00:00Z",
        "expires_at": "2026-09-01T00:00:00Z",
        "authorization_nonce_hash": sha256_reference({"authorization_nonce": "exec-auth-nonce-001"}),
    }
    payload.update(overrides)
    payload["execution_authorization_hash"] = sha256_reference(
        replit_executor.ai_act_live_policy_engine._execution_authorization_hash_payload(payload),
        default_to_str=True,
    )
    return payload


def _execution_binding(**contract_overrides) -> dict:
    return {
        "governed_request": _governed_request(),
        "governed_execution_contract": _execution_contract(**contract_overrides),
        "governed_execution_authorization": _authorization(),
        "consumed_decision_evidence_hash": _hash("allow-decision-evidence"),
    }


def _governed_paths(tmp_path: Path) -> dict:
    return {
        "token_path": tmp_path / "action_token.json",
        "signature_path": tmp_path / "action_token.sig",
        "governance_public_key": tmp_path / "public_key.pem",
        "runtime_signer_adapter": _SignerAdapter(),
        "runtime_key_id": "runtime-key-1",
        "attestation_path": tmp_path / "execution_attestation.json",
        "attestation_signature_path": tmp_path / "execution_attestation.sig",
    }


def _forbid_subprocess(*_args, **_kwargs):
    raise AssertionError("SUBPROCESS_CALLED")


def test_execute_command_blocks_missing_authorization_inputs_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(replit_executor, "_run_subprocess", _forbid_subprocess)

    with pytest.raises(RuntimeError, match="missing governed execution inputs"):
        replit_executor.execute_command(command=_command(), cwd=tmp_path)


def test_direct_executor_bypass_blocks_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    subprocess_called = {"value": False}

    def forbidden(*_args, **_kwargs):
        subprocess_called["value"] = True
        raise AssertionError("SUBPROCESS_CALLED")

    monkeypatch.setattr(replit_executor, "_run_subprocess", forbidden)

    with pytest.raises(RuntimeError, match="missing governed execution inputs"):
        replit_executor.execute_command(command=_command(), cwd=tmp_path)

    assert subprocess_called["value"] is False


@pytest.mark.parametrize(
    ("case_name", "failure"),
    [
        ("malformed_authorization", "invalid action token JSON"),
        ("stale_authorization", "action token expired"),
        ("tenant_mismatch", "tenant binding mismatch"),
        ("environment_mismatch", "environment binding mismatch"),
        ("policy_version_mismatch", "policy version mismatch"),
        ("identity_mismatch", "identity subject mismatch"),
        ("attestation_mismatch", "verifier attestation mismatch"),
        ("dependency_failure", "authority registry unavailable"),
        ("replay_detected", "replay detected"),
        ("concurrent_replay_detected", "concurrent replay detected"),
        ("toctou_failure", "TOCTOU revalidation failed"),
    ],
)
def test_execute_command_blocks_canonical_authorization_failures_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    case_name: str,
    failure: str,
) -> None:
    del case_name
    paths = _governed_paths(tmp_path)
    subprocess_called = {"value": False}

    def forbidden(*_args, **_kwargs):
        subprocess_called["value"] = True
        raise AssertionError("SUBPROCESS_CALLED")

    def fail_authorization(**_kwargs):
        raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: {failure}")

    monkeypatch.setattr(replit_executor, "_run_subprocess", forbidden)
    monkeypatch.setattr(replit_executor.action_token, "verify_action_token", fail_authorization)

    with pytest.raises(RuntimeError, match=failure):
        replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths)

    assert subprocess_called["value"] is False


def test_execute_command_blocks_unavailable_runtime_signer_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _governed_paths(tmp_path)
    paths["runtime_signer_adapter"] = object()
    monkeypatch.setattr(replit_executor, "_run_subprocess", _forbid_subprocess)

    with pytest.raises(RuntimeError, match="runtime signer type unavailable"):
        replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths)


@pytest.mark.parametrize(
    ("contract_override", "reason"),
    [
        ({"tool_id": "other-tool"}, "EXEC_AUTH_ACTION_MISMATCH"),
        ({"action_id": "other-action"}, "EXEC_AUTH_ACTION_MISMATCH"),
        ({"resource_id": "other-resource"}, "EXEC_AUTH_RESOURCE_MISMATCH"),
        ({"target_id": "other-target"}, "EXEC_AUTH_RESOURCE_MISMATCH"),
        ({"parameter_hash": _hash("changed-parameters")}, "EXEC_AUTH_PARAMETER_MISMATCH"),
        ({"subject_id": "other-subject"}, "EXEC_AUTH_SUBJECT_MISMATCH"),
        ({"agent_id": "other-agent"}, "EXEC_AUTH_SUBJECT_MISMATCH"),
        ({"purpose": "other-purpose"}, "EXEC_AUTH_PURPOSE_MISMATCH"),
        ({"expires_at": "2026-08-11T11:59:59Z"}, "EXEC_AUTH_EXPIRED"),
    ],
)
def test_execute_command_blocks_governed_execution_authorization_mismatches_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    contract_override: dict,
    reason: str,
) -> None:
    paths = _governed_paths(tmp_path)
    binding = _execution_binding(**contract_override)
    subprocess_called = {"value": False}

    def authorize(**_kwargs):
        return {"command_id": "command-1"}

    def forbidden(*_args, **_kwargs):
        subprocess_called["value"] = True
        raise AssertionError("SUBPROCESS_CALLED")

    monkeypatch.setattr(replit_executor.action_token, "verify_action_token", authorize)
    monkeypatch.setattr(replit_executor, "_run_subprocess", forbidden)

    with pytest.raises(RuntimeError, match=reason):
        replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths, **binding)

    assert subprocess_called["value"] is False


@pytest.mark.parametrize(
    ("authorization_override", "reason"),
    [
        ({}, "EXEC_AUTH_MISSING"),
        ({"execution_authorization_result": "BLOCK"}, "EXEC_AUTH_DECISION_LINK_INVALID"),
        ({"decision_replay_result": "REPLAY_BLOCKED"}, "EXEC_AUTH_REUSED"),
        ({"policy_hash": _hash("other-policy")}, "EXEC_AUTH_POLICY_LINK_INVALID"),
        ({"decision_evidence_hash": _hash("other-decision")}, "EXEC_AUTH_DECISION_LINK_INVALID"),
    ],
)
def test_execute_command_blocks_missing_malformed_and_invalid_execution_authorization_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    authorization_override: dict,
    reason: str,
) -> None:
    paths = _governed_paths(tmp_path)
    binding = _execution_binding()
    if authorization_override:
        binding["governed_execution_authorization"] = _authorization(**authorization_override)
    else:
        binding["governed_execution_authorization"] = None
    subprocess_called = {"value": False}

    def authorize(**_kwargs):
        return {"command_id": "command-1"}

    def forbidden(*_args, **_kwargs):
        subprocess_called["value"] = True
        raise AssertionError("SUBPROCESS_CALLED")

    monkeypatch.setattr(replit_executor.action_token, "verify_action_token", authorize)
    monkeypatch.setattr(replit_executor, "_run_subprocess", forbidden)

    with pytest.raises(RuntimeError, match=reason):
        replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths, **binding)

    assert subprocess_called["value"] is False


def test_execute_command_blocks_when_execution_authorization_verifier_unavailable_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _governed_paths(tmp_path)
    binding = _execution_binding()
    subprocess_called = {"value": False}

    def authorize(**_kwargs):
        return {"command_id": "command-1"}

    def unavailable(*_args, **_kwargs):
        return "EXEC_AUTH_VERIFIER_UNAVAILABLE"

    def forbidden(*_args, **_kwargs):
        subprocess_called["value"] = True
        raise AssertionError("SUBPROCESS_CALLED")

    monkeypatch.setattr(replit_executor.action_token, "verify_action_token", authorize)
    monkeypatch.setattr(replit_executor.ai_act_live_policy_engine, "validate_governed_execution_authorization", unavailable)
    monkeypatch.setattr(replit_executor, "_run_subprocess", forbidden)

    with pytest.raises(RuntimeError, match="EXEC_AUTH_VERIFIER_UNAVAILABLE"):
        replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths, **binding)

    assert subprocess_called["value"] is False


def test_execute_command_runs_subprocess_once_after_authorization(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _governed_paths(tmp_path)
    binding = _execution_binding()
    order: list[str] = []
    subprocess_call_count = {"value": 0}

    def authorize(**kwargs):
        order.append("authorize")
        assert kwargs["governed_execution_authorization"]["execution_authorization_hash"] == binding["governed_execution_authorization"]["execution_authorization_hash"]
        return {"command_id": "command-1"}

    def run(command: dict, *, cwd: Path) -> dict:
        assert command == _command()
        assert cwd == tmp_path
        order.append("subprocess")
        subprocess_call_count["value"] += 1
        return {"stdout": "ok\n", "stderr": "", "exit_code": 0}

    def attest(**kwargs):
        order.append("attest")
        assert kwargs["command_id"] == "command-1"
        assert kwargs["stdout"] == "ok\n"
        assert kwargs["exit_code"] == 0
        return {"command_id": "command-1", "signature_status": "signed"}

    def sha256_file(path: Path) -> str:
        assert path in {paths["token_path"], paths["attestation_path"]}
        return "sha256:" + "a" * 64

    monkeypatch.setattr(replit_executor.action_token, "verify_action_token", authorize)
    monkeypatch.setattr(replit_executor, "_run_subprocess", run)
    monkeypatch.setattr(replit_executor.attestation, "generate_execution_attestation", attest)
    monkeypatch.setattr(replit_executor.ledger, "sha256_file", sha256_file)

    result = replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths, **binding)

    assert order == ["authorize", "subprocess", "attest"]
    assert subprocess_call_count["value"] == 1
    assert result["stdout"] == "ok\n"
    assert result["stderr"] == ""
    assert result["exit_code"] == 0
    assert result["action_token_hash"] == "sha256:" + "a" * 64
    assert result["execution_attestation_hash"] == "sha256:" + "a" * 64
