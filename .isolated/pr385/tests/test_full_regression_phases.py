from __future__ import annotations

import json
from pathlib import Path

import scripts.run_full_regression_phases as phases


def _write_phase(path: Path, *, status: str, reason_code: str, exit_code: int = 0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "status": status,
                "reason_code": reason_code,
                "exit_code": exit_code,
                "evidence_hash": f"hash-{path.stem}",
            }
        ),
        encoding="utf-8",
    )


def test_full_regression_phase_runner_writes_pass_aggregate(monkeypatch, tmp_path: Path) -> None:
    def fake_run_bounded(command, *, lane, timeout_seconds, evidence_output):
        _write_phase(evidence_output, status="PASS", reason_code="VALIDATION_PASSED")
        return 0

    monkeypatch.setattr(phases, "run_bounded", fake_run_bounded)

    result = phases.run_phases(
        evidence_output=tmp_path / "validation" / "full-regression-validation.json",
        phase_dir=tmp_path / "validation" / "full-regression",
    )

    record = json.loads((tmp_path / "validation" / "full-regression-validation.json").read_text(encoding="utf-8"))
    assert result == 0
    assert record["status"] == "PASS"
    assert record["reason_code"] == "PASS_FULL_REGRESSION"
    assert record["fail_closed"] is False
    assert record["phase_count"] == 4
    assert "evidence_hash" in record


def test_full_regression_phase_runner_fails_closed_on_timeout(monkeypatch, tmp_path: Path) -> None:
    calls = {"count": 0}

    def fake_run_bounded(command, *, lane, timeout_seconds, evidence_output):
        calls["count"] += 1
        if calls["count"] == 2:
            _write_phase(evidence_output, status="TIMEOUT", reason_code="PHASE_TIMEOUT_publication_runtime_tests", exit_code=124)
            return 124
        _write_phase(evidence_output, status="PASS", reason_code="VALIDATION_PASSED")
        return 0

    monkeypatch.setattr(phases, "run_bounded", fake_run_bounded)

    result = phases.run_phases(
        evidence_output=tmp_path / "validation" / "full-regression-validation.json",
        phase_dir=tmp_path / "validation" / "full-regression",
    )

    record = json.loads((tmp_path / "validation" / "full-regression-validation.json").read_text(encoding="utf-8"))
    assert result == 124
    assert record["status"] == "TIMEOUT"
    assert record["reason_code"] == "PHASE_TIMEOUT_publication_runtime_tests"
    assert record["fail_closed"] is True
    assert record["partial_audit_preserved"] is True


def test_full_regression_phase_runner_fails_closed_on_test_failure(monkeypatch, tmp_path: Path) -> None:
    calls = {"count": 0}

    def fake_run_bounded(command, *, lane, timeout_seconds, evidence_output):
        calls["count"] += 1
        if calls["count"] == 3:
            _write_phase(evidence_output, status="FAIL", reason_code="VALIDATION_COMMAND_FAILED", exit_code=7)
            return 7
        _write_phase(evidence_output, status="PASS", reason_code="VALIDATION_PASSED")
        return 0

    monkeypatch.setattr(phases, "run_bounded", fake_run_bounded)

    result = phases.run_phases(
        evidence_output=tmp_path / "validation" / "full-regression-validation.json",
        phase_dir=tmp_path / "validation" / "full-regression",
    )

    record = json.loads((tmp_path / "validation" / "full-regression-validation.json").read_text(encoding="utf-8"))
    assert result == 7
    assert record["status"] == "FAIL"
    assert record["reason_code"] == "TEST_FAILURE_gateway_security_governance_tests"
    assert record["fail_closed"] is True
