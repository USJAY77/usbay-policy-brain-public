from __future__ import annotations

import subprocess
import shutil
import sys
from pathlib import Path

import pytest

import gateway.app as gateway_app
from security.policy_registry import PolicyRegistryError
from scripts.public_release_check import REPO_ROOT, run_checks, scan_git_history, scan_private_keys, scan_unsafe_shell


def _init_git_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "runtime-scan@example.invalid"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Runtime Scan Test"], cwd=path, check=True)
    subprocess.run(["git", "commit", "--allow-empty", "-qm", "initial"], cwd=path, check=True)


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
    _init_git_repo(tmp_path)
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
    _init_git_repo(tmp_path)
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
    _init_git_repo(tmp_path)
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
    _init_git_repo(tmp_path)
    path = tmp_path / "random" / "debug_public_key.pem"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("-----BEGIN PUBLIC KEY-----\nnot-real\n-----END PUBLIC KEY-----\n", encoding="utf-8")

    findings = gateway_app.forbidden_runtime_file_findings(tmp_path)

    assert findings == [{"path": "random/debug_public_key.pem", "rule": "unapproved_pem_file"}]


def test_runtime_scan_excludes_test_fixture_private_key_markers(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    fixture = tmp_path / "tests" / "test_pem_classification.py"
    fixture.parent.mkdir(parents=True, exist_ok=True)
    fixture.write_text(
        'PRIVATE_FIXTURE = "-----BEGIN ' + 'PRIVATE KEY-----\\nfixture-only\\n-----END ' + 'PRIVATE KEY-----"\n',
        encoding="utf-8",
    )

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == []
    assert gateway_app.validate_no_forbidden_runtime_files(tmp_path) is True


def test_runtime_scan_still_blocks_deployable_private_key_markers(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
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
    _init_git_repo(tmp_path)
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
    _init_git_repo(tmp_path)
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


@pytest.mark.parametrize(
    "relative_path",
    (
        ".cache/uv/archive/private.key",
        ".config/.semgrep/private.key",
        ".config/replit/.semgrep/private.key",
        ".local/share/pnpm/store/private.key",
        ".local/state/replit/private.key",
        ".pythonlibs/private.key",
        "node_modules/.pnpm/private.key",
    ),
)
def test_untracked_managed_runtime_artifact_is_excluded(tmp_path: Path, relative_path: str) -> None:
    _init_git_repo(tmp_path)
    artifact = tmp_path / relative_path
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("-----BEGIN PRIVATE KEY-----\nmanaged-package-fixture\n", encoding="utf-8")

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == []


@pytest.mark.parametrize(
    "relative_path",
    (
        ".cache/uv/archive/private.key",
        ".config/.semgrep/private.key",
        ".config/replit/.semgrep/private.key",
        ".local/share/pnpm/store/private.key",
        ".local/state/replit/private.key",
        ".pythonlibs/private.key",
        "node_modules/.pnpm/private.key",
    ),
)
def test_tracked_file_cannot_masquerade_as_managed_runtime_artifact(tmp_path: Path, relative_path: str) -> None:
    _init_git_repo(tmp_path)
    artifact = tmp_path / relative_path
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("-----BEGIN PRIVATE KEY-----\nrepository-fixture\n", encoding="utf-8")
    subprocess.run(["git", "add", "-f", "--", relative_path], cwd=tmp_path, check=True)

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == [
        {"path": relative_path, "rule": "private_key_file"}
    ]


@pytest.mark.parametrize(
    "relative_path",
    (
        ".cache/uvish/private.key",
        ".local/share/pnpm/storefront/private.key",
        "node_modules/.pnpm-malicious/private.key",
        "application/node_modules/.pnpm/private.key",
    ),
)
def test_similar_unmanaged_prefix_still_fails_closed(tmp_path: Path, relative_path: str) -> None:
    _init_git_repo(tmp_path)
    artifact = tmp_path / relative_path
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("not-a-real-secret\n", encoding="utf-8")

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == [
        {"path": relative_path, "rule": "private_key_file"}
    ]


def test_unknown_untracked_runtime_path_still_fails_closed(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    artifact = tmp_path / "application" / "runtime.py"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("-----BEGIN PRIVATE KEY-----\nunknown-fixture\n", encoding="utf-8")

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == [
        {"path": "application/runtime.py", "rule": "private_key_material_marker"}
    ]


def test_managed_runtime_file_symlink_to_outside_root_fails_closed(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    target = tmp_path.parent / f"{tmp_path.name}-outside.key"
    try:
        target.write_text("not-a-real-secret\n", encoding="utf-8")
        link = tmp_path / "node_modules" / ".pnpm" / "linked.key"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)

        findings = gateway_app.forbidden_runtime_file_findings(tmp_path)

        assert findings == [{"path": "node_modules/.pnpm/linked.key", "rule": "runtime_symlink_path"}]
    finally:
        target.unlink(missing_ok=True)


def test_managed_runtime_directory_symlink_fails_closed(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    target = tmp_path.parent / f"{tmp_path.name}-outside"
    try:
        target.mkdir()
        (target / "runtime.key").write_text("not-a-real-secret\n", encoding="utf-8")
        link = tmp_path / ".cache" / "uv" / "linked"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target, target_is_directory=True)

        findings = gateway_app.forbidden_runtime_file_findings(tmp_path)

        assert findings == [{"path": ".cache/uv/linked", "rule": "runtime_symlink_path"}]
    finally:
        (target / "runtime.key").unlink(missing_ok=True)
        target.rmdir()


def test_excluded_runtime_directory_cannot_hide_symlink(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    target = tmp_path.parent / f"{tmp_path.name}-outside.key"
    try:
        target.write_text("not-a-real-secret\n", encoding="utf-8")
        link = tmp_path / "tests" / "linked.key"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)

        assert gateway_app.forbidden_runtime_file_findings(tmp_path) == [
            {"path": "tests/linked.key", "rule": "runtime_symlink_path"}
        ]
    finally:
        target.unlink(missing_ok=True)


def test_untracked_pnpm_link_to_managed_store_is_allowed(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    target = tmp_path / "node_modules" / ".pnpm" / "package@1.0.0" / "node_modules" / "package"
    target.mkdir(parents=True)
    link = tmp_path / "node_modules" / "package"
    link.symlink_to(target, target_is_directory=True)

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == []


def test_untracked_pnpm_workspace_link_to_governed_target_is_allowed(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    target = tmp_path / "packages" / "governed"
    target.mkdir(parents=True)
    (target / "module.py").write_text("VALUE = True\n", encoding="utf-8")
    subprocess.run(["git", "add", "--", "packages/governed/module.py"], cwd=tmp_path, check=True)
    link = tmp_path / "node_modules" / ".pnpm" / "node_modules" / "@workspace" / "governed"
    link.parent.mkdir(parents=True)
    link.symlink_to(target, target_is_directory=True)

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == []


def test_untracked_pnpm_workspace_link_cannot_hide_ungoverned_target_content(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    target = tmp_path / "packages" / "ungoverned"
    target.mkdir(parents=True)
    (target / "module.py").write_text("-----BEGIN PRIVATE KEY-----\nunknown-fixture\n", encoding="utf-8")
    link = tmp_path / "node_modules" / ".pnpm" / "node_modules" / "@workspace" / "ungoverned"
    link.parent.mkdir(parents=True)
    link.symlink_to(target, target_is_directory=True)

    findings = gateway_app.forbidden_runtime_file_findings(tmp_path)

    assert findings == [{"path": "packages/ungoverned/module.py", "rule": "private_key_material_marker"}]


def test_untracked_pnpm_workspace_link_to_clean_independently_scanned_target_is_allowed(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    target = tmp_path / "packages" / "ungoverned"
    target.mkdir(parents=True)
    (target / "module.py").write_text("VALUE = True\n", encoding="utf-8")
    link = tmp_path / "node_modules" / ".pnpm" / "node_modules" / "@workspace" / "ungoverned"
    link.parent.mkdir(parents=True)
    link.symlink_to(target, target_is_directory=True)

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == []


def test_untracked_node_modules_link_to_excluded_target_fails_closed(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    target = tmp_path / "tests" / "fixtures"
    target.mkdir(parents=True)
    link = tmp_path / "node_modules" / "fixture-package"
    link.parent.mkdir(parents=True)
    link.symlink_to(target, target_is_directory=True)

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == [
        {"path": "node_modules/fixture-package", "rule": "runtime_symlink_path"}
    ]


def test_untracked_node_modules_link_to_other_managed_root_fails_closed(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    target = tmp_path / ".cache" / "uv" / "archive"
    target.mkdir(parents=True)
    link = tmp_path / "node_modules" / "cache-package"
    link.parent.mkdir(parents=True)
    link.symlink_to(target, target_is_directory=True)

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == [
        {"path": "node_modules/cache-package", "rule": "runtime_symlink_path"}
    ]


def test_tracked_pnpm_link_fails_closed(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    target = tmp_path / "node_modules" / ".pnpm" / "package@1.0.0" / "node_modules" / "package"
    target.mkdir(parents=True)
    link = tmp_path / "node_modules" / "package"
    link.symlink_to(target, target_is_directory=True)
    subprocess.run(["git", "add", "-f", "--", "node_modules/package"], cwd=tmp_path, check=True)

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == [
        {"path": "node_modules/package", "rule": "runtime_symlink_path"}
    ]


def test_exact_untracked_broken_pulse_runtime_link_is_allowed(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    link = tmp_path / ".config" / "pulse" / "repl-runtime"
    link.parent.mkdir(parents=True)
    link.symlink_to("/tmp/pulse-runtime-socket")

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == []


def test_unknown_broken_runtime_link_fails_closed(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    link = tmp_path / ".config" / "unknown" / "repl-runtime"
    link.parent.mkdir(parents=True)
    link.symlink_to("/tmp/pulse-runtime-socket")

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == [
        {"path": ".config/unknown/repl-runtime", "rule": "runtime_symlink_path"}
    ]


def test_head_tracked_file_cannot_become_managed_after_index_removal(tmp_path: Path) -> None:
    _init_git_repo(tmp_path)
    relative_path = ".cache/uv/stale.key"
    artifact = tmp_path / relative_path
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("not-a-real-secret\n", encoding="utf-8")
    subprocess.run(["git", "add", "-f", "--", relative_path], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "track managed-looking file"], cwd=tmp_path, check=True)
    subprocess.run(["git", "rm", "--cached", "-q", "--", relative_path], cwd=tmp_path, check=True)

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == [
        {"path": relative_path, "rule": "private_key_file"}
    ]


def test_runtime_scan_git_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _init_git_repo(tmp_path)

    class FailedGitResult:
        returncode = 1
        stdout = b""
        stderr = b"git failed"

    monkeypatch.setattr(gateway_app.subprocess, "run", lambda *args, **kwargs: FailedGitResult())

    with pytest.raises(PolicyRegistryError, match="runtime_scan_git_index_unavailable"):
        gateway_app.forbidden_runtime_file_findings(tmp_path)


def test_runtime_scan_rejects_malformed_git_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _init_git_repo(tmp_path)

    class MalformedGitResult:
        returncode = 0
        stdout = b"/outside\\0"
        stderr = b""

    monkeypatch.setattr(gateway_app, "_validate_runtime_git_identity", lambda root: None)
    monkeypatch.setattr(gateway_app.subprocess, "run", lambda *args, **kwargs: MalformedGitResult())

    with pytest.raises(PolicyRegistryError, match="runtime_scan_git_paths_invalid"):
        gateway_app.forbidden_runtime_file_findings(tmp_path)


def test_runtime_scan_uses_only_batched_git_queries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _init_git_repo(tmp_path)
    artifact = tmp_path / "application" / "module.py"
    artifact.parent.mkdir()
    artifact.write_text("VALUE = True\n", encoding="utf-8")
    actual_run = gateway_app.subprocess.run
    calls = []
    environments = []

    def recording_run(command, **kwargs):
        calls.append(command)
        environments.append(kwargs.get("env", {}))
        return actual_run(command, **kwargs)

    monkeypatch.setattr(gateway_app.subprocess, "run", recording_run)

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == []
    assert len(calls) == 5
    assert calls[0][3:6] == ("rev-parse", "--show-toplevel", "--absolute-git-dir")
    assert calls[1][3:6] == ("ls-files", "-z", "--cached")
    assert calls[2][3:7] == ("ls-tree", "-rz", "--name-only", "HEAD")
    assert calls[3][3:6] == ("ls-files", "-z", "--cached")
    assert calls[4][3:7] == ("ls-tree", "-rz", "--name-only", "HEAD")
    assert all(not key.upper().startswith("GIT_") for environment in environments for key in environment)


def test_runtime_scan_ignores_inherited_git_repository_overrides(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _init_git_repo(tmp_path)
    artifact = tmp_path / ".cache" / "uv" / "tracked.key"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("not-a-real-secret\n", encoding="utf-8")
    subprocess.run(["git", "add", "-f", "--", ".cache/uv/tracked.key"], cwd=tmp_path, check=True)
    alternate = tmp_path.parent / f"{tmp_path.name}-alternate"
    try:
        alternate.mkdir()
        _init_git_repo(alternate)
        monkeypatch.setenv("GIT_DIR", str(alternate / ".git"))
        monkeypatch.setenv("GIT_WORK_TREE", str(alternate))
        monkeypatch.setenv("GIT_INDEX_FILE", str(alternate / ".git" / "index"))

        assert gateway_app.forbidden_runtime_file_findings(tmp_path) == [
            {"path": ".cache/uv/tracked.key", "rule": "private_key_file"}
        ]
    finally:
        shutil.rmtree(alternate, ignore_errors=True)


def test_runtime_scan_fails_if_git_authority_changes_during_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _init_git_repo(tmp_path)
    actual_governed_paths = gateway_app._governed_runtime_paths
    call_count = 0

    def changing_governed_paths(root):
        nonlocal call_count
        call_count += 1
        paths = actual_governed_paths(root)
        if call_count == 2:
            return paths | {"changed-during-scan"}
        return paths

    monkeypatch.setattr(gateway_app, "_governed_runtime_paths", changing_governed_paths)

    with pytest.raises(PolicyRegistryError, match="runtime_scan_git_state_changed"):
        gateway_app.forbidden_runtime_file_findings(tmp_path)


def test_runtime_scan_file_read_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _init_git_repo(tmp_path)
    artifact = tmp_path / "application" / "module.py"
    artifact.parent.mkdir()
    artifact.write_text("VALUE = True\n", encoding="utf-8")
    actual_read_text = Path.read_text

    def failing_read_text(path, *args, **kwargs):
        if path == artifact:
            raise OSError("read blocked")
        return actual_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", failing_read_text)

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == [
        {"path": "application/module.py", "rule": "runtime_file_read_failed"}
    ]


def test_runtime_scan_traversal_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _init_git_repo(tmp_path)

    def failing_walk(root, **kwargs):
        error = OSError("traversal blocked")
        error.filename = str(Path(root) / "blocked")
        kwargs["onerror"](error)
        return iter(())

    monkeypatch.setattr(gateway_app.os, "walk", failing_walk)

    assert gateway_app.forbidden_runtime_file_findings(tmp_path) == [
        {"path": "blocked", "rule": "runtime_traversal_failed"}
    ]


def test_public_release_check_fails_on_env_file(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("TOKEN=not-real\n", encoding="utf-8")

    findings = run_checks(tmp_path, include_tests=False)

    assert "env_file:.env" in findings


def test_public_release_check_fails_on_private_key(tmp_path: Path) -> None:
    (tmp_path / "actor_private.key").write_text("local-dev-private-material\n", encoding="utf-8")

    findings = run_checks(tmp_path, include_tests=False)

    assert any(finding.startswith("private_key_file:actor_private.key") for finding in findings)


def _init_history_repo(repo: Path) -> None:
    subprocess.run(["git", "init"], cwd=repo, text=True, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "USBAY Test"], cwd=repo, check=True)


def test_public_release_history_scan_allows_approved_public_key_material(tmp_path: Path) -> None:
    _init_history_repo(tmp_path)
    public_key = tmp_path / "policy" / "public_key.pem"
    public_key.parent.mkdir(parents=True)
    public_key.write_text("-----BEGIN PUBLIC KEY-----\nnot-real\n-----END PUBLIC KEY-----\n", encoding="utf-8")
    raw_public_key = tmp_path / "governance" / "keys" / "actor_public.key"
    raw_public_key.parent.mkdir(parents=True)
    raw_public_key.write_bytes(b"\x01" * 32)
    subprocess.run(["git", "add", "policy/public_key.pem", "governance/keys/actor_public.key"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "add public verification keys"], cwd=tmp_path, text=True, capture_output=True, check=True)

    assert scan_git_history(tmp_path) == []


def test_public_release_history_scan_still_blocks_private_key_material(tmp_path: Path) -> None:
    _init_history_repo(tmp_path)
    private_key = tmp_path / "policy" / "public_key.pem"
    private_key.parent.mkdir(parents=True)
    private_key.write_text(
        "-----BEGIN " + "PRIVATE KEY-----\nnot-real\n-----END " + "PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "policy/public_key.pem"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "add invalid public key"], cwd=tmp_path, text=True, capture_output=True, check=True)

    assert scan_git_history(tmp_path) == ["git_history_secret_path:policy/public_key.pem"]


def test_public_release_history_scan_fails_closed_when_blob_cannot_be_read(tmp_path: Path, monkeypatch) -> None:
    _init_history_repo(tmp_path)
    public_key = tmp_path / "policy" / "public_key.pem"
    public_key.parent.mkdir(parents=True)
    public_key.write_text("-----BEGIN PUBLIC KEY-----\nnot-real\n-----END PUBLIC KEY-----\n", encoding="utf-8")
    subprocess.run(["git", "add", "policy/public_key.pem"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "add public key"], cwd=tmp_path, text=True, capture_output=True, check=True)

    real_run = subprocess.run

    def fail_cat_file(args, **kwargs):
        if args[:3] == ["git", "cat-file", "-p"]:
            return subprocess.CompletedProcess(args, 1, stdout=b"", stderr=b"boom")
        return real_run(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", fail_cat_file)

    assert scan_git_history(tmp_path) == ["git_history_secret_path:policy/public_key.pem"]


def test_public_release_shell_scan_blocks_unbounded_rm_rf(tmp_path: Path) -> None:
    script = tmp_path / "scripts" / "unsafe.sh"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\nrm -rf docs/publication policy/publication\n", encoding="utf-8")

    assert scan_unsafe_shell(tmp_path) == ["unsafe_rm_rf:scripts/unsafe.sh:2"]


def test_public_release_shell_scan_allows_bounded_and_nonexecuting_rm_rf_examples(tmp_path: Path) -> None:
    doc = tmp_path / "docs" / "release.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("rm -rf /private/tmp/usbay_release_package /tmp/usbay_release_source\n", encoding="utf-8")
    test_file = tmp_path / "tests" / "test_policy.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text('assert classify_command("rm -rf /tmp/example")["risk_level"] == "high"\n', encoding="utf-8")

    assert scan_unsafe_shell(tmp_path) == []


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
