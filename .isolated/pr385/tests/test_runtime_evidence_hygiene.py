from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path


TRACKED_EVIDENCE_PATHS = (
    "audit",
    "governance/evidence",
)


def _tracked_evidence_files() -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", *TRACKED_EVIDENCE_PATHS],
        check=True,
        capture_output=True,
        text=True,
    )
    return [Path(line) for line in completed.stdout.splitlines() if line.strip()]


def _snapshot(paths: list[Path]) -> dict[str, str]:
    return {
        path.as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
        if path.is_file()
    }


def _assert_snapshot_unchanged(before: dict[str, str]) -> None:
    after = _snapshot([Path(path) for path in before])
    assert after == before


def _run_local_validation(command: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("PYTEST_CURRENT_TEST", None)
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_live_pilot_verifier_does_not_mutate_tracked_audit_or_evidence_files() -> None:
    tracked = _tracked_evidence_files()
    before = _snapshot(tracked)

    result = _run_local_validation([sys.executable, "scripts/verify_live_pilot_v1.py"])

    assert result.returncode == 0
    assert "LIVE_PILOT_READY=true" in result.stdout
    assert "FAIL_CLOSED_RUNTIME_VALID=true" in result.stdout
    _assert_snapshot_unchanged(before)


def test_production_readiness_guard_does_not_mutate_tracked_audit_or_evidence_files() -> None:
    tracked = _tracked_evidence_files()
    before = _snapshot(tracked)

    result = _run_local_validation(
        [
            sys.executable,
            "scripts/verify_production_readiness.py",
            "--lane",
            "fast-contract",
            "--event",
            "pull_request",
        ]
    )

    assert result.returncode == 0
    assert "PRODUCTION_READINESS_FAST_CONTRACT=true" in result.stdout
    assert "FAIL_CLOSED_BEHAVIOR_PRESERVED=true" in result.stdout
    _assert_snapshot_unchanged(before)
