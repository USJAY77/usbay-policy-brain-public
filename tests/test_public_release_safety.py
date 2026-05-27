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
    fake_key = REPO_ROOT / "governance" / "fake_private.key"
    fake_key.parent.mkdir(parents=True, exist_ok=True)
    secret_contents = "local-private-key-placeholder"
    fake_key.write_text(secret_contents + "\n", encoding="utf-8")
    try:
        with pytest.raises(PolicyRegistryError, match="forbidden_runtime_file_present") as exc_info:
            gateway_app.validate_no_private_keys_in_repo()
        message = str(exc_info.value)
        assert "governance/fake_private.key" in message
        assert "private_key_file" in message
        assert secret_contents not in message
    finally:
        fake_key.unlink(missing_ok=True)


def test_gateway_startup_fails_closed_on_tmp_private_pem() -> None:
    fake_key = REPO_ROOT / "tmp" / "fake_private.pem"
    fake_key.parent.mkdir(parents=True, exist_ok=True)
    secret_contents = "local-private-key-placeholder"
    fake_key.write_text(secret_contents + "\n", encoding="utf-8")
    try:
        with pytest.raises(PolicyRegistryError, match="forbidden_runtime_file_present") as exc_info:
            gateway_app.validate_no_forbidden_runtime_files()
        message = str(exc_info.value)
        assert "tmp/fake_private.pem" in message
        assert "tmp_private_file" in message
        assert secret_contents not in message
    finally:
        fake_key.unlink(missing_ok=True)


def test_forbidden_runtime_file_diagnostics_are_structured_and_content_safe(tmp_path: Path) -> None:
    forbidden = tmp_path / "secrets" / "runtime.key"
    secret_contents = "do-not-log-this-secret-value"
    forbidden.parent.mkdir(parents=True, exist_ok=True)
    forbidden.write_text(secret_contents, encoding="utf-8")

    diagnostics = gateway_app.forbidden_runtime_file_diagnostics(tmp_path)

    assert diagnostics["error"] == "forbidden_runtime_file_present"
    assert diagnostics["findings"] == [{"path": "secrets/runtime.key", "rule": "secrets_directory"}]
    assert diagnostics["offending_paths"] == ["secrets/runtime.key"]
    assert diagnostics["matched_rules"] == ["secrets_directory"]
    assert secret_contents not in str(diagnostics)


def test_public_verification_pems_are_allowed_when_contents_are_public_keys(tmp_path: Path) -> None:
    public_pem = "-----BEGIN PUBLIC KEY-----\nnot-real-public-test-key\n-----END PUBLIC KEY-----\n"
    paths = (
        tmp_path / "keys_runtime" / "root_authority_ed25519.pub.pem",
        tmp_path / "keys_runtime" / "release_ed25519.pub.pem",
        tmp_path / "approvals" / "approver_public_key.pem",
        tmp_path / "approvals" / "dev-ci" / "approver1_public_key.pem",
    )
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(public_pem, encoding="utf-8")

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == []
    assert gateway_app.validate_no_forbidden_runtime_files(tmp_path) is True


def test_public_verification_pem_name_with_private_material_fails_closed(tmp_path: Path) -> None:
    private_material = "-----BEGIN " + "PRIVATE KEY-----\nprivate-test-value\n-----END " + "PRIVATE KEY-----\n"
    path = tmp_path / "keys_runtime" / "root_authority_ed25519.pub.pem"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(private_material, encoding="utf-8")

    findings = gateway_app.forbidden_runtime_file_findings(tmp_path)

    assert findings == [{"path": "keys_runtime/root_authority_ed25519.pub.pem", "rule": "public_verification_pem_not_public_key"}]
    with pytest.raises(PolicyRegistryError, match="forbidden_runtime_file_present") as exc_info:
        gateway_app.validate_no_forbidden_runtime_files(tmp_path)
    assert "keys_runtime/root_authority_ed25519.pub.pem" in str(exc_info.value)
    assert "public_verification_pem_not_public_key" in str(exc_info.value)
    assert "private-test-value" not in str(exc_info.value)


def test_arbitrary_public_pem_is_not_globally_whitelisted(tmp_path: Path) -> None:
    path = tmp_path / "random" / "debug_public_key.pem"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("-----BEGIN PUBLIC KEY-----\nnot-real\n-----END PUBLIC KEY-----\n", encoding="utf-8")

    findings = gateway_app.forbidden_runtime_file_findings(tmp_path)

    assert findings == [{"path": "random/debug_public_key.pem", "rule": "unapproved_pem_file"}]


def test_runtime_scan_excludes_test_fixture_private_key_markers(tmp_path: Path) -> None:
    fixture = tmp_path / "tests" / "test_pem_classification.py"
    fixture.parent.mkdir(parents=True, exist_ok=True)
    fixture.write_text(
        'PRIVATE_FIXTURE = "-----BEGIN ' + 'PRIVATE KEY-----\\nfixture-only\\n-----END ' + 'PRIVATE KEY-----"\n',
        encoding="utf-8",
    )

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == []
    assert gateway_app.validate_no_forbidden_runtime_files(tmp_path) is True


def test_runtime_scan_still_blocks_deployable_private_key_markers(tmp_path: Path) -> None:
    runtime_file = tmp_path / "gateway" / "runtime_private_fixture.py"
    runtime_file.parent.mkdir(parents=True, exist_ok=True)
    runtime_file.write_text(
        'PRIVATE_RUNTIME = "-----BEGIN ' + 'PRIVATE KEY-----\\nprod-block\\n-----END ' + 'PRIVATE KEY-----"\n',
        encoding="utf-8",
    )

    findings = gateway_app.forbidden_runtime_file_findings(tmp_path)

    assert findings == [{"path": "gateway/runtime_private_fixture.py", "rule": "private_key_material_marker"}]
    with pytest.raises(PolicyRegistryError, match="forbidden_runtime_file_present") as exc_info:
        gateway_app.validate_no_forbidden_runtime_files(tmp_path)
    assert "gateway/runtime_private_fixture.py" in str(exc_info.value)
    assert "private_key_material_marker" in str(exc_info.value)
    assert "prod-block" not in str(exc_info.value)


def test_governed_public_key_artifacts_are_allowed_without_global_key_whitelist(tmp_path: Path) -> None:
    raw_public_key = b"\x01" * 32
    pem_public_key = "-----BEGIN PUBLIC KEY-----\nnot-real\n-----END PUBLIC KEY-----\n"
    paths = (
        tmp_path / "governance" / "keys" / "actor_public.key",
        tmp_path / "governance" / "keys" / "request_public.key",
        tmp_path / "governance" / "policy_public.key",
        tmp_path / "governance" / "request_public.key",
    )
    paths[0].parent.mkdir(parents=True, exist_ok=True)
    paths[0].write_bytes(raw_public_key)
    for path in paths[1:]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(pem_public_key, encoding="utf-8")

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == []


def test_public_named_key_with_private_material_still_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "governance" / "keys" / "actor_public.key"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("-----BEGIN " + "PRIVATE KEY-----\ndo-not-log\n-----END " + "PRIVATE KEY-----\n", encoding="utf-8")

    findings = gateway_app.forbidden_runtime_file_findings(tmp_path)

    assert findings == [{"path": "governance/keys/actor_public.key", "rule": "public_verification_key_not_public_material"}]
    with pytest.raises(PolicyRegistryError, match="forbidden_runtime_file_present") as exc_info:
        gateway_app.validate_no_forbidden_runtime_files(tmp_path)
    assert "governance/keys/actor_public.key" in str(exc_info.value)
    assert "public_verification_key_not_public_material" in str(exc_info.value)
    assert "do-not-log" not in str(exc_info.value)


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
