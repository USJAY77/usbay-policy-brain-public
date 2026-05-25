from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from scripts.run_bounded_validation import _timeout_for_lane, main


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.critical
@pytest.mark.governance
def test_bounded_validation_pass_writes_hash_only_evidence(tmp_path: Path) -> None:
    evidence = tmp_path / "validation.json"

    result = main(
        [
            "--lane",
            "fast_pr",
            "--timeout-seconds",
            "10",
            "--evidence-output",
            str(evidence),
            "--",
            sys.executable,
            "-c",
            "print('ok')",
        ]
    )

    record = _read(evidence)
    assert result == 0
    assert record["status"] == "PASS"
    assert record["reason_code"] == "VALIDATION_PASSED"
    assert record["fail_closed"] is False
    assert "command_sha256" in record
    assert "print('ok')" not in json.dumps(record)


@pytest.mark.critical
@pytest.mark.governance
def test_bounded_validation_timeout_fails_closed_with_reason_code(tmp_path: Path) -> None:
    evidence = tmp_path / "timeout.json"

    result = main(
        [
            "--lane",
            "fast_pr",
            "--timeout-seconds",
            "1",
            "--evidence-output",
            str(evidence),
            "--",
            sys.executable,
            "-c",
            "import time; time.sleep(5)",
        ]
    )

    record = _read(evidence)
    assert result == 124
    assert record["status"] == "TIMEOUT"
    assert record["reason_code"] == "VALIDATION_TIMEOUT_FAST_PR"
    assert record["fail_closed"] is True
    assert record["partial_audit_preserved"] is True


@pytest.mark.critical
@pytest.mark.governance
def test_bounded_validation_failed_command_fails_closed(tmp_path: Path) -> None:
    evidence = tmp_path / "failed.json"

    result = main(
        [
            "--lane",
            "dependency",
            "--timeout-seconds",
            "10",
            "--evidence-output",
            str(evidence),
            "--",
            sys.executable,
            "-c",
            "raise SystemExit(7)",
        ]
    )

    record = _read(evidence)
    assert result == 7
    assert record["status"] == "FAIL"
    assert record["reason_code"] == "VALIDATION_COMMAND_FAILED"
    assert record["fail_closed"] is True


def test_bounded_validation_rejects_timeout_above_lane_max() -> None:
    with pytest.raises(SystemExit, match="VALIDATION_TIMEOUT_EXCEEDS_LANE_MAX"):
        _timeout_for_lane("fast_pr", 601)


def test_bounded_validation_rejects_unsafe_command(tmp_path: Path) -> None:
    evidence = tmp_path / "unsafe.json"

    with pytest.raises(SystemExit, match="VALIDATION_COMMAND_UNSAFE"):
        main(
            [
                "--lane",
                "fast_pr",
                "--timeout-seconds",
                "10",
                "--evidence-output",
                str(evidence),
                "--",
                sys.executable,
                "-c",
                "print('PRIVATE KEY')",
            ]
        )
