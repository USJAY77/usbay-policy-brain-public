"""Tests for .githooks/pre-commit — governance_release*.json rejection guard.

Runs the hook script's Python logic directly (no subprocess git dependency)
so the tests are hermetic and fast.  The guard must fire on any repo-root
governance_release*.json staged file, including force-added ones, and must
pass cleanly when no such file is staged.
"""
from __future__ import annotations

import fnmatch
import importlib
import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HOOK_PATH = REPO_ROOT / ".githooks" / "pre-commit"


# ---------------------------------------------------------------------------
# Helpers — isolate the guard logic without running the full hook subprocess
# ---------------------------------------------------------------------------

def _release_guard(staged: list[str]) -> list[str]:
    """Return the list of blocked files using the same logic as the hook."""
    return [
        p for p in staged
        if "/" not in p and fnmatch.fnmatch(p, "governance_release*.json")
    ]


# ---------------------------------------------------------------------------
# Unit tests for the guard logic
# ---------------------------------------------------------------------------

class TestGovernanceReleaseGuardLogic:
    def test_blocks_exact_name(self):
        assert _release_guard(["governance_release.json"]) == ["governance_release.json"]

    def test_blocks_suffixed_name(self):
        assert _release_guard(["governance_release_v2.json"]) == ["governance_release_v2.json"]

    def test_blocks_force_added(self):
        # force-add produces the same staged output; guard must not care how it arrived
        staged = ["governance_release.json", "README.md"]
        assert _release_guard(staged) == ["governance_release.json"]

    def test_passes_when_not_staged(self):
        assert _release_guard([]) == []

    def test_passes_for_unrelated_files(self):
        staged = ["gateway/app.py", "tests/test_smoke.py", "README.md"]
        assert _release_guard(staged) == []

    def test_does_not_block_nested_path(self):
        # Only repo-root files are covered; sub-directory paths are not blocked
        # by this guard (they can't be the runaway release file).
        staged = ["security/governance_release_internal.json"]
        assert _release_guard(staged) == []

    def test_does_not_block_unrelated_json(self):
        assert _release_guard(["governance_policy.json"]) == []


# ---------------------------------------------------------------------------
# Integration test — run the hook script itself via subprocess
# ---------------------------------------------------------------------------

class TestHookScriptIntegration:
    """Execute the hook's embedded Python block directly to confirm the guard
    is present in the versioned file at .githooks/pre-commit."""

    def _run_guard_block(self, staged: list[str]) -> subprocess.CompletedProcess:
        """Run only the governance_release guard section of the hook with staged_files() stubbed.

        The hook is structured as a bash script wrapping a Python heredoc.  The
        guard block starts at the sentinel comment and runs to the end of the
        heredoc.  We extract that slice so the stub is never overridden by the
        real staged_files() definition that lives earlier in the heredoc.
        """
        hook_text = HOOK_PATH.read_text(encoding="utf-8")

        sentinel = "# --- governance_release*.json guard ---\n"
        assert sentinel in hook_text, (
            "governance_release guard sentinel not found in .githooks/pre-commit"
        )

        # Extract from the sentinel to the closing heredoc marker
        guard_start = hook_text.index(sentinel)
        end = hook_text.rindex("\nPY")
        guard_body = hook_text[guard_start:end]

        stub = textwrap.dedent(f"""\
            import fnmatch, sys

            def staged_files():
                return {staged!r}

        """)
        script = stub + guard_body

        return subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
        )

    def test_hook_file_exists_and_is_executable(self):
        assert HOOK_PATH.is_file(), f"hook not found at {HOOK_PATH}"
        assert HOOK_PATH.stat().st_mode & 0o111, "hook is not executable"

    def test_hook_blocks_governance_release(self):
        result = self._run_guard_block(["governance_release.json"])
        assert result.returncode == 1
        assert "governance_release_staged" in result.stderr

    def test_hook_blocks_suffixed_governance_release(self):
        result = self._run_guard_block(["governance_release_tenant42.json"])
        assert result.returncode == 1
        assert "governance_release_staged" in result.stderr

    def test_hook_passes_when_clean(self):
        result = self._run_guard_block(["gateway/app.py", "README.md"])
        assert result.returncode == 0

    def test_hook_passes_empty_staged(self):
        result = self._run_guard_block([])
        assert result.returncode == 0

    def test_hook_error_message_includes_regeneration_hint(self):
        result = self._run_guard_block(["governance_release.json"])
        assert "write-release" in result.stderr

    def test_hook_guard_present_in_versioned_file(self):
        """Confirm the guard block is in .githooks/pre-commit, not just .git/hooks/."""
        content = HOOK_PATH.read_text(encoding="utf-8")
        assert "governance_release_staged" in content, (
            "Guard phrase 'governance_release_staged' not found in .githooks/pre-commit"
        )
        assert "governance_release*.json" in content, (
            "Pattern 'governance_release*.json' not found in .githooks/pre-commit"
        )
