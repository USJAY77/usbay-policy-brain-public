from pathlib import Path
import json

import pytest

from governance.hashing import sha256_reference
import runtime.replit_executor as replit_executor
from security.execution_lifecycle_store import (
    ALREADY_TERMINAL,
    COMPLETED,
    EXECUTION_STARTED,
    LIFECYCLE_PARTIAL_UNKNOWN,
    PARTIAL_UNKNOWN,
    START_ACQUIRED,
    TERMINAL_RECORDED,
    SQLiteExecutionLifecycleStore,
    UnsupportedExecutionLifecycleStore,
)


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


def _execution_binding(tmp_path: Path | None = None, **contract_overrides) -> dict:
    binding = {
        "governed_request": _governed_request(),
        "governed_execution_contract": _execution_contract(**contract_overrides),
        "governed_execution_authorization": _authorization(),
        "consumed_decision_evidence_hash": _hash("allow-decision-evidence"),
    }
    if tmp_path is not None:
        binding["lifecycle_store"] = SQLiteExecutionLifecycleStore(tmp_path / "execution_lifecycle.db")
    return binding


def _execution_binding_without_lifecycle(**contract_overrides) -> dict:
    return {
        "governed_request": _governed_request(),
        "governed_execution_contract": _execution_contract(**contract_overrides),
        "governed_execution_authorization": _authorization(),
        "consumed_decision_evidence_hash": _hash("allow-decision-evidence"),
    }


def _governed_paths(tmp_path: Path) -> dict:
    audit_dir = replit_executor.ROOT / "audit" / "logs" / f"replit-executor-test-{tmp_path.name}"
    return {
        "token_path": tmp_path / "action_token.json",
        "signature_path": tmp_path / "action_token.sig",
        "governance_public_key": tmp_path / "public_key.pem",
        "runtime_signer_adapter": _SignerAdapter(),
        "runtime_key_id": "runtime-key-1",
        "attestation_path": audit_dir / "execution_attestation.json",
        "attestation_signature_path": audit_dir / "execution_attestation.sig",
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
    binding = _execution_binding(tmp_path, **contract_override)
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
    binding = _execution_binding(tmp_path)
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
    binding = _execution_binding(tmp_path)
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
    binding = _execution_binding(tmp_path)
    order: list[str] = []
    subprocess_call_count = {"value": 0}
    lifecycle_store = binding["lifecycle_store"]
    original_start = lifecycle_store.acquire_execution_start
    original_terminal = lifecycle_store.record_terminal_outcome

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

    def sha256_file(path: Path) -> str:
        assert path in {paths["token_path"], paths["attestation_path"]}
        return "sha256:" + "a" * 64

    monkeypatch.setattr(replit_executor.action_token, "verify_action_token", authorize)
    monkeypatch.setattr(replit_executor, "_run_subprocess", run)
    original_attest = replit_executor.attestation.generate_execution_attestation

    def attest(**kwargs):
        order.append("attest")
        assert kwargs["command_id"] == "command-1"
        assert kwargs["stdout"] == "ok\n"
        assert kwargs["exit_code"] == 0
        return original_attest(**kwargs)

    def start(*args, **kwargs):
        order.append("lifecycle_start")
        return original_start(*args, **kwargs)

    def terminal(*args, **kwargs):
        order.append("lifecycle_terminal")
        return original_terminal(*args, **kwargs)

    monkeypatch.setattr(replit_executor.attestation, "generate_execution_attestation", attest)
    monkeypatch.setattr(replit_executor.ledger, "sha256_file", sha256_file)
    monkeypatch.setattr(lifecycle_store, "acquire_execution_start", start)
    monkeypatch.setattr(lifecycle_store, "record_terminal_outcome", terminal)

    result = replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths, **binding)

    assert order == ["authorize", "lifecycle_start", "subprocess", "attest", "lifecycle_terminal"]
    assert subprocess_call_count["value"] == 1
    assert result["stdout"] == "ok\n"
    assert result["stderr"] == ""
    assert result["exit_code"] == 0
    assert result["action_token_hash"] == "sha256:" + "a" * 64
    assert result["execution_attestation_hash"] == "sha256:" + "a" * 64
    assert result["execution_lifecycle"]["execution_lifecycle_state"] == COMPLETED


def test_execute_command_binds_execution_outcome_to_exact_authorization(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _governed_paths(tmp_path)
    binding = _execution_binding(tmp_path)

    monkeypatch.setattr(replit_executor.action_token, "verify_action_token", lambda **_kwargs: {"command_id": "command-1"})
    monkeypatch.setattr(replit_executor, "_run_subprocess", lambda command, *, cwd: {"stdout": "ok\n", "stderr": "", "exit_code": 0})
    monkeypatch.setattr(replit_executor.ledger, "sha256_file", lambda _path: "sha256:" + "a" * 64)

    result = replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths, **binding)
    evidence = result["execution_attestation"]

    assert result["execution_outcome_state"] == "COMPLETED"
    assert result["execution_lifecycle"]["execution_lifecycle_state"] == COMPLETED
    assert result["execution_lifecycle"]["execution_authorization_hash"] == binding["governed_execution_authorization"]["execution_authorization_hash"]
    assert evidence["schema_version"] == "usbay.execution_outcome_evidence.v1"
    assert evidence["execution_authorization_hash"] == binding["governed_execution_authorization"]["execution_authorization_hash"]
    assert evidence["authorization_id"] == binding["governed_execution_authorization"]["authorization_id"]
    assert evidence["consumed_decision_evidence_hash"] == binding["consumed_decision_evidence_hash"]
    assert evidence["decision_evidence_hash"] == binding["governed_execution_authorization"]["decision_evidence_hash"]
    assert evidence["decision_consumption_evidence_hash"] == binding["governed_execution_authorization"]["decision_consumption_evidence_hash"]
    assert evidence["decision_replay_evidence_hash"] == binding["governed_execution_authorization"]["decision_replay_evidence_hash"]
    assert evidence["policy_id"] == binding["governed_execution_authorization"]["policy_id"]
    assert evidence["policy_hash"] == binding["governed_execution_authorization"]["policy_hash"]
    assert evidence["request_hash"] == binding["governed_execution_authorization"]["request_hash"]
    assert evidence["command_hash"] == replit_executor.attestation.command_hash(_command())
    assert evidence["execution_contract_hash"] == replit_executor.attestation.execution_contract_hash(binding["governed_execution_contract"])
    assert evidence["outcome_hash"].startswith("sha256:")
    assert evidence["current_evidence_hash"].startswith("sha256:")
    assert replit_executor.attestation.validate_execution_outcome_attestation(
        evidence,
        command=_command(),
        governed_execution_authorization=binding["governed_execution_authorization"],
        governed_execution_contract=binding["governed_execution_contract"],
        consumed_decision_evidence_hash=binding["consumed_decision_evidence_hash"],
    ) is None


def test_nonzero_exit_is_failed_not_completed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _governed_paths(tmp_path)
    binding = _execution_binding(tmp_path)

    monkeypatch.setattr(replit_executor.action_token, "verify_action_token", lambda **_kwargs: {"command_id": "command-1"})
    monkeypatch.setattr(replit_executor, "_run_subprocess", lambda command, *, cwd: {"stdout": "", "stderr": "no\n", "exit_code": 2})
    monkeypatch.setattr(replit_executor.ledger, "sha256_file", lambda _path: "sha256:" + "a" * 64)

    result = replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths, **binding)

    assert result["exit_code"] == 2
    assert result["execution_outcome_state"] == "FAILED"
    assert result["execution_attestation"]["outcome_state"] != "COMPLETED"
    assert result["execution_lifecycle"]["execution_lifecycle_state"] == "FAILED"


def test_partial_unknown_state_is_not_completed() -> None:
    assert (
        replit_executor.attestation.outcome_state(
            None,
            side_effect_completed=False,
            evidence_binding_valid=False,
        )
        == "PARTIAL_UNKNOWN"
    )
    assert (
        replit_executor.attestation.outcome_state(
            0,
            side_effect_completed=True,
            evidence_binding_valid=False,
        )
        == "PARTIAL_UNKNOWN"
    )


def test_execution_exception_does_not_create_false_completed_attestation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _governed_paths(tmp_path)
    binding = _execution_binding(tmp_path)
    attestation_called = {"value": False}

    def fail_run(*_args, **_kwargs):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: simulated execution failure")

    def attest(*_args, **_kwargs):
        attestation_called["value"] = True
        raise AssertionError("ATTESTATION_SHOULD_NOT_BE_COMPLETED")

    monkeypatch.setattr(replit_executor.action_token, "verify_action_token", lambda **_kwargs: {"command_id": "command-1"})
    monkeypatch.setattr(replit_executor, "_run_subprocess", fail_run)
    monkeypatch.setattr(replit_executor.attestation, "generate_execution_attestation", attest)

    with pytest.raises(RuntimeError, match="simulated execution failure"):
        replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths, **binding)

    assert attestation_called["value"] is False
    recovered = binding["lifecycle_store"].recover(
        replit_executor.execution_lifecycle_store.lifecycle_binding(
            command=_command(),
            governed_execution_authorization=binding["governed_execution_authorization"],
            governed_execution_contract=binding["governed_execution_contract"],
            consumed_decision_evidence_hash=binding["consumed_decision_evidence_hash"],
            command_hash=replit_executor.attestation.command_hash(_command()),
            execution_contract_hash=replit_executor.attestation.execution_contract_hash(binding["governed_execution_contract"]),
        )
    )
    assert recovered.state == PARTIAL_UNKNOWN


def test_outcome_evidence_generation_failure_never_reports_governed_completion(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _governed_paths(tmp_path)
    binding = _execution_binding(tmp_path)

    monkeypatch.setattr(replit_executor.action_token, "verify_action_token", lambda **_kwargs: {"command_id": "command-1"})
    monkeypatch.setattr(replit_executor, "_run_subprocess", lambda command, *, cwd: {"stdout": "ok\n", "stderr": "", "exit_code": 0})

    def fail_attestation(*_args, **_kwargs):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: OUTCOME_BINDING_INVALID")

    monkeypatch.setattr(replit_executor.attestation, "generate_execution_attestation", fail_attestation)

    with pytest.raises(RuntimeError, match="OUTCOME_BINDING_INVALID"):
        replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths, **binding)
    recovered = binding["lifecycle_store"].recover(
        replit_executor.execution_lifecycle_store.lifecycle_binding(
            command=_command(),
            governed_execution_authorization=binding["governed_execution_authorization"],
            governed_execution_contract=binding["governed_execution_contract"],
            consumed_decision_evidence_hash=binding["consumed_decision_evidence_hash"],
            command_hash=replit_executor.attestation.command_hash(_command()),
            execution_contract_hash=replit_executor.attestation.execution_contract_hash(binding["governed_execution_contract"]),
        )
    )
    assert recovered.state == PARTIAL_UNKNOWN


def test_outcome_binding_mismatch_and_tamper_are_verification_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _governed_paths(tmp_path)
    binding = _execution_binding(tmp_path)

    monkeypatch.setattr(replit_executor.action_token, "verify_action_token", lambda **_kwargs: {"command_id": "command-1"})
    monkeypatch.setattr(replit_executor, "_run_subprocess", lambda command, *, cwd: {"stdout": "ok\n", "stderr": "", "exit_code": 0})
    monkeypatch.setattr(replit_executor.ledger, "sha256_file", lambda _path: "sha256:" + "a" * 64)

    result = replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths, **binding)
    evidence = dict(result["execution_attestation"])
    evidence["execution_authorization_hash"] = _hash("other-auth")
    assert replit_executor.attestation.validate_execution_outcome_attestation(
        evidence,
        command=_command(),
        governed_execution_authorization=binding["governed_execution_authorization"],
        governed_execution_contract=binding["governed_execution_contract"],
        consumed_decision_evidence_hash=binding["consumed_decision_evidence_hash"],
    ) == "OUTCOME_BINDING_MISMATCH"

    tampered = dict(result["execution_attestation"])
    tampered["outcome_state"] = "COMPLETED" if result["execution_attestation"]["outcome_state"] == "FAILED" else "FAILED"
    assert replit_executor.attestation.validate_execution_outcome_attestation(
        tampered,
        command=_command(),
        governed_execution_authorization=binding["governed_execution_authorization"],
        governed_execution_contract=binding["governed_execution_contract"],
        consumed_decision_evidence_hash=binding["consumed_decision_evidence_hash"],
    ) in {"OUTCOME_STATE_INVALID", "OUTCOME_HASH_INVALID"}


def test_missing_outcome_field_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _governed_paths(tmp_path)
    binding = _execution_binding(tmp_path)

    monkeypatch.setattr(replit_executor.action_token, "verify_action_token", lambda **_kwargs: {"command_id": "command-1"})
    monkeypatch.setattr(replit_executor, "_run_subprocess", lambda command, *, cwd: {"stdout": "ok\n", "stderr": "", "exit_code": 0})
    monkeypatch.setattr(replit_executor.ledger, "sha256_file", lambda _path: "sha256:" + "a" * 64)

    result = replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths, **binding)
    evidence = dict(result["execution_attestation"])
    evidence.pop("execution_contract_hash")

    assert replit_executor.attestation.validate_execution_outcome_attestation(
        evidence,
        command=_command(),
        governed_execution_authorization=binding["governed_execution_authorization"],
        governed_execution_contract=binding["governed_execution_contract"],
        consumed_decision_evidence_hash=binding["consumed_decision_evidence_hash"],
    ) == "OUTCOME_BINDING_MISMATCH"


def test_outcome_evidence_excludes_sensitive_data(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _governed_paths(tmp_path)
    binding = _execution_binding(tmp_path)

    monkeypatch.setattr(replit_executor.action_token, "verify_action_token", lambda **_kwargs: {"command_id": "command-1"})
    monkeypatch.setattr(replit_executor, "_run_subprocess", lambda command, *, cwd: {"stdout": "ok\n", "stderr": "", "exit_code": 0})
    monkeypatch.setattr(replit_executor.ledger, "sha256_file", lambda _path: "sha256:" + "a" * 64)

    result = replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths, **binding)
    rendered = json.dumps(result["execution_attestation"], sort_keys=True).lower()

    for forbidden in ("api_key", "credential", "password", "prompt", "token", "raw_payload", "secret", "exec-auth-nonce-001"):
        assert forbidden not in rendered


def test_execute_command_blocks_without_supported_lifecycle_store_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _governed_paths(tmp_path)
    binding = _execution_binding_without_lifecycle()
    subprocess_called = {"value": False}

    monkeypatch.setattr(replit_executor.action_token, "verify_action_token", lambda **_kwargs: {"command_id": "command-1"})

    def forbidden(*_args, **_kwargs):
        subprocess_called["value"] = True
        raise AssertionError("SUBPROCESS_CALLED")

    monkeypatch.setattr(replit_executor, "_run_subprocess", forbidden)
    binding["lifecycle_store"] = UnsupportedExecutionLifecycleStore()

    with pytest.raises(RuntimeError, match="UNSUPPORTED_LIFECYCLE_STORE"):
        replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths, **binding)

    assert subprocess_called["value"] is False


def test_restart_after_execution_started_blocks_second_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _governed_paths(tmp_path)
    binding = _execution_binding(tmp_path)
    lifecycle_store = binding["lifecycle_store"]
    lifecycle_binding = replit_executor.execution_lifecycle_store.lifecycle_binding(
        command=_command(),
        governed_execution_authorization=binding["governed_execution_authorization"],
        governed_execution_contract=binding["governed_execution_contract"],
        consumed_decision_evidence_hash=binding["consumed_decision_evidence_hash"],
        command_hash=replit_executor.attestation.command_hash(_command()),
        execution_contract_hash=replit_executor.attestation.execution_contract_hash(binding["governed_execution_contract"]),
    )
    assert lifecycle_store.acquire_execution_start(lifecycle_binding, started_at="2026-08-13T12:00:00Z").state == EXECUTION_STARTED
    subprocess_called = {"value": False}

    monkeypatch.setattr(replit_executor.action_token, "verify_action_token", lambda **_kwargs: {"command_id": "command-1"})

    def forbidden(*_args, **_kwargs):
        subprocess_called["value"] = True
        raise AssertionError("SUBPROCESS_CALLED")

    monkeypatch.setattr(replit_executor, "_run_subprocess", forbidden)

    with pytest.raises(RuntimeError, match="EXECUTION_STARTED_WITHOUT_TERMINAL_EVIDENCE"):
        replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths, **binding)

    assert subprocess_called["value"] is False


def test_restart_after_completed_blocks_second_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _governed_paths(tmp_path)
    binding = _execution_binding(tmp_path)
    subprocess_call_count = {"value": 0}

    monkeypatch.setattr(replit_executor.action_token, "verify_action_token", lambda **_kwargs: {"command_id": "command-1"})
    monkeypatch.setattr(replit_executor, "_run_subprocess", lambda command, *, cwd: subprocess_call_count.update(value=subprocess_call_count["value"] + 1) or {"stdout": "ok\n", "stderr": "", "exit_code": 0})
    monkeypatch.setattr(replit_executor.ledger, "sha256_file", lambda _path: "sha256:" + "a" * 64)

    result = replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths, **binding)
    assert result["execution_lifecycle"]["execution_lifecycle_state"] == COMPLETED

    with pytest.raises(RuntimeError, match=ALREADY_TERMINAL):
        replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths, **binding)

    assert subprocess_call_count["value"] == 1
