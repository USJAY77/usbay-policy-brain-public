from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from security import deployment_attestation
from security.deployment_attestation import (
    DeploymentAttestationError,
    PROVENANCE_SOURCE_GIT,
    PROVENANCE_SOURCE_RUNTIME_COMMIT_STAMP,
    RUNTIME_COMMIT_STAMP_PATH,
    current_commit_source,
    current_git_commit,
)


FAKE_SHA = "a" * 40


def _force_git_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*_args, **_kwargs):
        raise subprocess.CalledProcessError(returncode=128, cmd=["git", "rev-parse", "HEAD"])

    monkeypatch.setattr(deployment_attestation.subprocess, "run", _raise)


def _force_stamp_path(monkeypatch: pytest.MonkeyPatch, repo_root: Path) -> None:
    monkeypatch.setattr(
        deployment_attestation,
        "_read_runtime_commit_stamp",
        lambda _root: deployment_attestation._read_runtime_commit_stamp.__wrapped__(repo_root)
        if hasattr(deployment_attestation._read_runtime_commit_stamp, "__wrapped__")
        else None,
    )


def test_current_git_commit_uses_git_when_available() -> None:
    commit = current_git_commit()
    assert len(commit) == 40
    assert all(c in "0123456789abcdef" for c in commit)
    assert current_commit_source() == PROVENANCE_SOURCE_GIT


def test_current_git_commit_falls_back_to_stamp_when_git_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stamp_dir = tmp_path / "governance"
    stamp_dir.mkdir()
    (stamp_dir / "runtime_commit.txt").write_text(FAKE_SHA + "\n", encoding="utf-8")

    _force_git_failure(monkeypatch)
    monkeypatch.setattr(
        deployment_attestation,
        "_read_runtime_commit_stamp",
        lambda _repo_root: FAKE_SHA,
    )

    commit = current_git_commit()
    assert commit == FAKE_SHA
    assert current_commit_source() == PROVENANCE_SOURCE_RUNTIME_COMMIT_STAMP


def test_current_git_commit_fails_closed_when_neither_source_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_git_failure(monkeypatch)
    monkeypatch.setattr(
        deployment_attestation,
        "_read_runtime_commit_stamp",
        lambda _repo_root: None,
    )

    with pytest.raises(DeploymentAttestationError, match="git_commit_unavailable"):
        current_git_commit()


def test_read_runtime_commit_stamp_validates_sha_format(tmp_path: Path) -> None:
    stamp_dir = tmp_path / "governance"
    stamp_dir.mkdir()

    # Missing file -> None
    assert deployment_attestation._read_runtime_commit_stamp(tmp_path) is None

    # Invalid contents -> None (validator rejects)
    (stamp_dir / "runtime_commit.txt").write_text("not-a-sha\n", encoding="utf-8")
    assert deployment_attestation._read_runtime_commit_stamp(tmp_path) is None

    # Valid 40-char hex -> returns lower-cased sha
    (stamp_dir / "runtime_commit.txt").write_text(FAKE_SHA.upper() + "\n", encoding="utf-8")
    assert deployment_attestation._read_runtime_commit_stamp(tmp_path) == FAKE_SHA


def test_runtime_commit_stamp_path_constant() -> None:
    assert RUNTIME_COMMIT_STAMP_PATH == Path("governance/runtime_commit.txt")


# ---------------------------------------------------------------------------
# Startup stamping: verify governance/runtime_commit.txt matches git HEAD
# ---------------------------------------------------------------------------

def test_stamp_matches_git_head_after_startup() -> None:
    """After _stamp_runtime_commit_at_startup() runs, the stamp file must
    hold the current git HEAD and current_git_commit() must agree with it.

    This test only asserts the stamp path in the workspace environment where
    git is available.  If git is unavailable (CI without checkout, Docker
    image) the test is skipped rather than failing.
    """
    import subprocess as _sp
    from pathlib import Path as _Path

    repo_root = _Path(__file__).resolve().parents[1]

    # Determine HEAD from git directly; skip if git is unavailable.
    try:
        result = _sp.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            text=True,
            capture_output=True,
            check=True,
        )
        expected_head = result.stdout.strip().lower()
    except Exception:
        pytest.skip("git unavailable in this environment")

    assert len(expected_head) == 40, "git HEAD must be a 40-char hex SHA"

    # Import the startup stamper and run it.
    import importlib, sys

    # Ensure gateway.app can be imported without starting the server.
    # We only need the stamp helper, so import it from the module namespace.
    # Use a lightweight import that avoids triggering uvicorn/lifespan.
    import scripts.stamp_runtime_commit as _stamp_mod

    rc = _stamp_mod.main([])
    assert rc == 0, f"stamp_runtime_commit.main() returned non-zero exit: {rc}"

    stamp_path = repo_root / "governance" / "runtime_commit.txt"
    assert stamp_path.exists(), "runtime_commit.txt must exist after stamping"
    stamped = stamp_path.read_text(encoding="utf-8").strip()
    assert stamped == expected_head, (
        f"stamp mismatch: stamp={stamped!r} HEAD={expected_head!r}"
    )

    # current_git_commit() must also return HEAD (it prefers git over stamp).
    resolved = current_git_commit()
    assert resolved == expected_head, (
        f"current_git_commit() returned {resolved!r}, expected HEAD {expected_head!r}"
    )


def test_stamp_main_accepts_commit_arg(tmp_path: pytest.MonkeyPatch) -> None:
    """--commit <sha> bypasses git and writes the provided SHA directly."""
    import scripts.stamp_runtime_commit as _stamp_mod

    fake_sha = "b" * 40
    # Temporarily redirect STAMP_PATH to tmp_path.
    original_stamp = _stamp_mod.STAMP_PATH
    _stamp_mod.STAMP_PATH = tmp_path / "governance" / "runtime_commit.txt"
    try:
        rc = _stamp_mod.main(["--commit", fake_sha])
        assert rc == 0
        written = _stamp_mod.STAMP_PATH.read_text(encoding="utf-8").strip()
        assert written == fake_sha
    finally:
        _stamp_mod.STAMP_PATH = original_stamp


def test_stamp_main_rejects_invalid_commit_arg(tmp_path: pytest.MonkeyPatch) -> None:
    """--commit with an invalid SHA must return exit code 3."""
    import scripts.stamp_runtime_commit as _stamp_mod

    rc = _stamp_mod.main(["--commit", "not-a-valid-sha"])
    assert rc == 3


# ---------------------------------------------------------------------------
# Fail-closed: no-git + invalid/missing stamp → dashboard shows "UNKNOWN"
# ---------------------------------------------------------------------------

def test_dashboard_git_commit_is_unknown_when_no_valid_stamp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When no valid commit is resolvable (git unavailable, stamp contains the
    'UNKNOWN' sentinel written by the Dockerfile else-branch), the dashboard
    path must surface 'UNKNOWN' — never a stale SHA, never blank '—'.

    This patches current_git_commit only in the gateway.app namespace, which
    is the exact import the runtime_status_snapshot() wrapper uses.  Patching
    at that level avoids collateral damage to the policy-registry chain (which
    calls current_git_commit() through a separate import in deployment_attestation).
    """
    import gateway.app as _app

    # Simulate: git unavailable AND stamp contains invalid sentinel "UNKNOWN"
    # (the value printf'd by the Dockerfile else-branch, which fails hex
    # validation in _read_runtime_commit_stamp and makes current_git_commit()
    # raise DeploymentAttestationError).
    def _no_commit() -> str:
        raise DeploymentAttestationError("git_commit_unavailable")

    monkeypatch.setattr(_app, "current_git_commit", _no_commit)

    # runtime_status_snapshot() must catch the error and return "UNKNOWN".
    snapshot = _app.runtime_status_snapshot()
    assert snapshot.get("git_commit") == "UNKNOWN", (
        f"expected 'UNKNOWN' in snapshot, got {snapshot.get('git_commit')!r}"
    )

    # The chip rendering logic derived from snapshot must also produce "UNKNOWN",
    # not "—" and not a partial hex string.  Mirror the exact logic from
    # governance_gateway_html() so this assertion stays in sync.
    git_commit_full = str(snapshot.get("git_commit") or "UNKNOWN")
    git_commit_short = (
        git_commit_full[:7]
        if git_commit_full not in ("", "UNKNOWN")
        else git_commit_full
    )
    assert git_commit_short == "UNKNOWN", (
        f"chip short value must be 'UNKNOWN', got {git_commit_short!r}"
    )
    assert git_commit_full != "—" and git_commit_short != "—", (
        "chip must never show '—'; it must show 'UNKNOWN' when no commit is resolvable"
    )
