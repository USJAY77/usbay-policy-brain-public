from __future__ import annotations

from terminal.command_governance import classify_command, command_risk_classification_json


def test_low_risk_read_only_commands_are_allowed() -> None:
    for command in (
        ["git", "status"],
        ["git", "diff", "--check"],
        ["git", "diff", "--name-only"],
        ["python3", "-m", "json.tool", "file.json"],
        ["python3", "-m", "py_compile", "terminal/command_governance.py"],
        ["pytest", "-q", "tests/test_command_risk_classification.py"],
    ):
        result = classify_command(command)
        assert result["risk_level"] == "LOW"
        assert result["decision"] == "ALLOW_READ_ONLY"


def test_medium_and_high_commands_require_proposal_or_human_approval() -> None:
    assert classify_command(["apply_patch"])["risk_level"] == "MEDIUM"
    high = classify_command(["git", "add", "file.py"])
    assert high["risk_level"] == "HIGH"
    assert high["decision"] == "HUMAN_APPROVAL_REQUIRED"


def test_critical_commands_block() -> None:
    for command in (
        ["git", "push"],
        ["git", "merge", "main"],
        ["rm", "file"],
        ["chmod", "777", "file"],
        ["curl", "https://example.test"],
        ["pip", "install", "package"],
        ["npm", "install"],
        ["cat", ".env"],
    ):
        result = classify_command(command)
        assert result["execution_allowed"] is False
        assert result["risk_level"] == "CRITICAL"


def test_shell_injection_pattern_fails_closed() -> None:
    result = classify_command("git status && git push")
    assert result["decision"] == "FAIL_CLOSED"
    assert result["reason"] == "SHELL_INJECTION_PATTERN"


def test_classification_contract_declares_high_and_critical_rules() -> None:
    contract = command_risk_classification_json()
    assert contract["high_requires_human_approval"] is True
    assert contract["critical_blocks"] is True
