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
