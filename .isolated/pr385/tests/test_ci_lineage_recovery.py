from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.resolve_ci_changed_files import NULL_SHA, resolve_changed_files
from scripts import generate_ci_evidence_manifest as evidence


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        capture_output=True,
        check=True,
    )
    return completed.stdout.strip()


def _init_repo(root: Path) -> tuple[str, str]:
    _git(root, "init")
    _git(root, "config", "user.email", "ci@example.invalid")
    _git(root, "config", "user.name", "CI")
    (root / "safe.txt").write_text("safe\n", encoding="utf-8")
    _git(root, "add", "safe.txt")
    _git(root, "commit", "-m", "base")
    base = _git(root, "rev-parse", "HEAD")
    (root / "changed.txt").write_text("changed\n", encoding="utf-8")
    _git(root, "add", "changed.txt")
    _git(root, "commit", "-m", "head")
    head = _git(root, "rev-parse", "HEAD")
    return base, head


@pytest.mark.governance
def test_pull_request_recreated_head_uses_current_canonical_tree(tmp_path: Path) -> None:
    base, head = _init_repo(tmp_path)
    missing_head = "f" * 40

    changed, diagnostics = resolve_changed_files(
        tmp_path,
        {
            "EVENT_NAME": "pull_request",
            "PR_BASE_SHA": base,
            "PR_HEAD_SHA": missing_head,
            "CURRENT_SHA": head,
        },
    )

    assert diagnostics["recovery_mode"] == "diff"
    assert diagnostics["lineage_status"] == "REWRITTEN_OR_ORPHANED"
    assert diagnostics["invalidation_status"] == "EXPIRED_INVALID"
    assert diagnostics["tampering_assessment"] == "transient_branch_rewrite"
    assert isinstance(diagnostics["diagnostic_hash"], str)
    assert diagnostics["stale_refs_expired"] == [f"pr_head:{missing_head}"]
    assert changed == ["changed.txt"]


@pytest.mark.governance
def test_push_orphan_before_expires_stale_lineage_and_scans_current_tree(tmp_path: Path) -> None:
    _base, head = _init_repo(tmp_path)
    missing_before = "e" * 40

    changed, diagnostics = resolve_changed_files(
        tmp_path,
        {
            "EVENT_NAME": "push",
            "PUSH_BEFORE_SHA": missing_before,
            "CURRENT_SHA": head,
        },
    )

    assert diagnostics["recovery_mode"] == "canonical_current_tree"
    assert diagnostics["invalidation_reason"] == "stale_or_orphaned_git_reference"
    assert diagnostics["stale_refs_expired"] == [f"push_before:{missing_before}"]
    assert changed == ["changed.txt", "safe.txt"]


@pytest.mark.governance
def test_new_branch_null_before_scans_current_tree(tmp_path: Path) -> None:
    _base, head = _init_repo(tmp_path)

    changed, diagnostics = resolve_changed_files(
        tmp_path,
        {
            "EVENT_NAME": "push",
            "PUSH_BEFORE_SHA": NULL_SHA,
            "CURRENT_SHA": head,
        },
    )

    assert diagnostics["recovery_mode"] == "canonical_current_tree"
    assert diagnostics["stale_refs_expired"] == []
    assert changed == ["changed.txt", "safe.txt"]


@pytest.mark.governance
def test_unresolvable_current_head_fails_closed_as_tampering_boundary(tmp_path: Path) -> None:
    _base, _head = _init_repo(tmp_path)

    with pytest.raises(SystemExit, match="CI_LINEAGE_HEAD_STALE"):
        resolve_changed_files(
            tmp_path,
            {
                "EVENT_NAME": "push",
                "PUSH_BEFORE_SHA": NULL_SHA,
                "CURRENT_SHA": "a" * 40,
            },
        )


@pytest.mark.governance
def test_evidence_manifest_records_orphaned_lineage_without_bypassing_chain(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "evidence.txt").write_text("evidence\n", encoding="utf-8")
    monkeypatch.setenv("GITHUB_SHA", "d" * 40)
    monkeypatch.setenv("GITHUB_HEAD_SHA", "c" * 40)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")

    manifest = evidence.build_manifest(tmp_path, ["evidence.txt"], generated_at="2026-05-17T00:00:00Z")

    assert manifest["records"][0]["previous_record_hash"] == evidence.GENESIS_HASH
    assert manifest["chain_head"] == manifest["records"][0]["current_record_hash"]
    assert manifest["lineage_recovery"]["canonical_rebuild_source"] == "current_branch_state"
    assert manifest["lineage_recovery"]["orphaned_lineage_detected"] is True
    assert sorted(manifest["lineage_recovery"]["stale_refs_expired"]) == ["github_head_sha", "github_sha"]


@pytest.mark.governance
def test_stale_lineage_invalidation_record_is_hash_only_and_replay_safe(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_SHA", "d" * 40)
    monkeypatch.setenv("GITHUB_HEAD_SHA", "c" * 40)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")

    record = evidence.write_stale_lineage_invalidation(tmp_path)
    path = tmp_path / evidence.STALE_LINEAGE_INVALIDATION_PATH

    assert path.is_file()
    assert record["status"] == "EXPIRED_INVALID"
    assert record["lineage_status"] == "REWRITTEN_OR_ORPHANED"
    assert record["invalidation_reason"] == "stale_or_orphaned_git_reference"
    assert record["tampering_assessment"] == "transient_branch_rewrite"
    assert record["record_hash"] == evidence._sha256_text(evidence._canonical_json({k: v for k, v in record.items() if k != "record_hash"}))
    assert "PRIVATE KEY" not in path.read_text(encoding="utf-8")
