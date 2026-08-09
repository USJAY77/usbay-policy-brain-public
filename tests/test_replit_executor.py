from pathlib import Path

import pytest

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


def test_execute_command_runs_subprocess_once_after_authorization(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = _governed_paths(tmp_path)
    order: list[str] = []
    subprocess_call_count = {"value": 0}

    def authorize(**_kwargs):
        order.append("authorize")
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

    result = replit_executor.execute_command(command=_command(), cwd=tmp_path, **paths)

    assert order == ["authorize", "subprocess", "attest"]
    assert subprocess_call_count["value"] == 1
    assert result["stdout"] == "ok\n"
    assert result["stderr"] == ""
    assert result["exit_code"] == 0
    assert result["action_token_hash"] == "sha256:" + "a" * 64
    assert result["execution_attestation_hash"] == "sha256:" + "a" * 64
