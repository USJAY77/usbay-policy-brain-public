from __future__ import annotations

from pathlib import Path

from terminal.verification_harness import execute_verification_command


def test_safe_verification_harness_executes_read_only_json_validation(tmp_path: Path) -> None:
    target = tmp_path / "safe.json"
    target.write_text('{"ok": true}', encoding="utf-8")
    result = execute_verification_command(["python3", "-m", "json.tool", str(target)], cwd=Path.cwd())
    assert result["decision"] == "VERIFIED"
    assert result["exit_code"] == 0
    assert result["stdout_hash"]
    assert result["stderr_hash"]
    assert result["policy_hash"]


def test_safe_verification_harness_fails_closed_on_unknown_command() -> None:
    result = execute_verification_command(["python3", "-c", "print('not allowed')"])
    assert result["decision"] == "FAIL_CLOSED"
    assert result["blocked_reason"] == "UNKNOWN_COMMAND"


def test_safe_verification_harness_fails_closed_on_shell_injection() -> None:
    result = execute_verification_command("git status; git push")
    assert result["decision"] == "FAIL_CLOSED"
    assert result["blocked_reason"] == "SHELL_INJECTION_PATTERN"


def test_safe_verification_harness_fails_closed_on_sensitive_path() -> None:
    result = execute_verification_command(["python3", "-m", "json.tool", ".env"])
    assert result["decision"] == "FAIL_CLOSED"
    assert result["blocked_reason"] == "SENSITIVE_PATH"
    assert result["stdout_stored"] == ""
