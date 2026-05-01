from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import gateway.app as gateway_app
from security.policy_registry import PolicyRegistryError
from scripts.public_release_check import REPO_ROOT, run_checks, scan_private_keys


def test_public_repo_contains_no_private_key_material() -> None:
    assert scan_private_keys(REPO_ROOT) == []


def test_secret_scan_fails_when_fake_private_key_is_added(tmp_path: Path) -> None:
    fake_key = tmp_path / "policy_private.key"
    fake_key.write_text(
        "-----BEGIN " + "PRIVATE KEY-----\nnot-a-real-key\n-----END " + "PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    findings = scan_private_keys(tmp_path)

    assert findings
    assert any("private_key" in finding for finding in findings)


def test_gateway_startup_fails_closed_when_private_key_is_inserted() -> None:
    fake_key = REPO_ROOT / "governance" / "tests" / "fake_private.key"
    fake_key.parent.mkdir(parents=True, exist_ok=True)
    fake_key.write_text("local-private-key-placeholder\n", encoding="utf-8")
    try:
        with pytest.raises(PolicyRegistryError, match="forbidden_runtime_file_present"):
            gateway_app.validate_no_private_keys_in_repo()
    finally:
        fake_key.unlink(missing_ok=True)


def test_gateway_startup_fails_closed_on_tmp_private_pem() -> None:
    fake_key = REPO_ROOT / "tmp" / "fake_private.pem"
    fake_key.parent.mkdir(parents=True, exist_ok=True)
    fake_key.write_text("local-private-key-placeholder\n", encoding="utf-8")
    try:
        with pytest.raises(PolicyRegistryError, match="forbidden_runtime_file_present"):
            gateway_app.validate_no_forbidden_runtime_files()
    finally:
        fake_key.unlink(missing_ok=True)


def test_public_release_check_fails_on_env_file(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("TOKEN=not-real\n", encoding="utf-8")

    findings = run_checks(tmp_path, include_tests=False)

    assert "env_file:.env" in findings


def test_public_release_check_fails_on_private_key(tmp_path: Path) -> None:
    (tmp_path / "actor_private.key").write_text("local-dev-private-material\n", encoding="utf-8")

    findings = run_checks(tmp_path, include_tests=False)

    assert any(finding.startswith("private_key_file:actor_private.key") for finding in findings)


def test_mac_validation_script_has_single_valid_invalid_output_contract() -> None:
    script = REPO_ROOT / "scripts" / "mac_validate.sh"

    syntax = subprocess.run(["bash", "-n", str(script)], text=True, capture_output=True, check=False)
    text = script.read_text(encoding="utf-8")

    assert syntax.returncode == 0
    assert "MAC_VALIDATION_VALID" in text
    assert "MAC_VALIDATION_INVALID" in text
    assert '"$PYTHON_BIN" -m pytest -q >/dev/null' in text
    assert "scripts/public_release_check.py >/dev/null" in text


def test_public_release_check_cli_validates_clean_minimal_tree(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "public_release_check.py"), str(tmp_path)],
        env={"USBAY_PUBLIC_RELEASE_SKIP_TESTS": "1"},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "PUBLIC_RELEASE_VALID"


def test_pre_commit_hook_blocks_staged_private_key(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, text=True, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "USBAY Test"], cwd=repo, check=True)
    hooks_dir = repo / ".git" / "hooks"
    hook = hooks_dir / "pre-commit"
    hook.write_text((REPO_ROOT / ".githooks" / "pre-commit").read_text(encoding="utf-8"), encoding="utf-8")
    hook.chmod(0o755)
    private_key = repo / "actor_private.key"
    private_key.write_text("local-private-key-placeholder\n", encoding="utf-8")
    subprocess.run(["git", "add", "actor_private.key"], cwd=repo, check=True)

    result = subprocess.run(
        ["git", "commit", "-m", "attempt private key commit"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "pre_commit_secret_scan" in result.stderr
