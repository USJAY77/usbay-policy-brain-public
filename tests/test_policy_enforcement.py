from pathlib import Path

from runtime.computer_use.policy_enforcement import PolicyEnforcer


def test_policy_missing_fail_closed(tmp_path: Path) -> None:
    check = PolicyEnforcer(policy_path=tmp_path / "missing.json").check("read_screen", "pb168")

    assert check.decision == "FAIL_CLOSED"
    assert check.reason == "policy_missing"


def test_policy_version_mismatch_fail_closed() -> None:
    check = PolicyEnforcer({"policy_version": "old", "allowed_actions": ["read_screen"]}).check("read_screen", "pb168")

    assert check.decision == "FAIL_CLOSED"
    assert check.reason == "policy_version_mismatch"


def test_unsupported_action_blocks() -> None:
    check = PolicyEnforcer({"policy_version": "pb168", "allowed_actions": ["read_screen"]}).check("delete", "pb168")

    assert check.decision == "BLOCK"
    assert check.reason == "unsupported_action"


def test_valid_policy_allows_supported_action() -> None:
    check = PolicyEnforcer({"policy_version": "pb168", "allowed_actions": ["read_screen"]}).check(
        "read_screen", "pb168"
    )

    assert check.decision == "ALLOW"

