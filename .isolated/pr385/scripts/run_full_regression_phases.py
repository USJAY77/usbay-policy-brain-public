#!/usr/bin/env python3
"""Run full regression as bounded, auditable validation phases."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts.run_bounded_validation import _canonical_json, _sha256_text, run_bounded


SCHEMA = "usbay.full_regression_phase_evidence.v1"


@dataclass(frozen=True)
class Phase:
    name: str
    lane: str
    timeout_seconds: int
    command: tuple[str, ...]


PHASES = (
    Phase(
        name="compile_import",
        lane="full_regression_compile",
        timeout_seconds=900,
        command=(
            "bash",
            "-c",
            "python3.11 -m py_compile scripts/*.py publication/*.py gateway/*.py security/*.py governance/*.py",
        ),
    ),
    Phase(
        name="publication_runtime_tests",
        lane="full_regression_publication",
        timeout_seconds=900,
        command=("bash", "-c", "python3.11 -m pytest -q tests/test_publication_*.py"),
    ),
    Phase(
        name="gateway_security_governance_tests",
        lane="full_regression_gateway_security_governance",
        timeout_seconds=2400,
        command=("python3.11", "-m", "pytest", "-q", "-m", "critical or governance or dependency"),
    ),
    Phase(
        name="heavy_slow_tests",
        lane="full_regression_heavy_slow",
        timeout_seconds=2400,
        command=("python3.11", "-m", "pytest", "-q", "-m", "heavy or slow or resilience or stress"),
    ),
)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    record = dict(payload)
    record["evidence_hash"] = _sha256_text(_canonical_json(record))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _phase_reason(phase_name: str, record: dict[str, Any]) -> str:
    if record.get("status") == "TIMEOUT":
        return f"PHASE_TIMEOUT_{phase_name}"
    if record.get("status") == "FAIL":
        return f"TEST_FAILURE_{phase_name}"
    return str(record.get("reason_code", "VALIDATION_PHASE_UNKNOWN"))


def run_phases(*, evidence_output: Path, phase_dir: Path) -> int:
    phase_results: list[dict[str, Any]] = []
    final_status = "PASS"
    final_reason = "PASS_FULL_REGRESSION"
    exit_code = 0

    for phase in PHASES:
        evidence_path = phase_dir / f"{phase.name}.json"
        result = run_bounded(
            list(phase.command),
            lane=phase.lane,
            timeout_seconds=phase.timeout_seconds,
            evidence_output=evidence_path,
        )
        phase_record = _read_json(evidence_path)
        phase_results.append(
            {
                "phase": phase.name,
                "lane": phase.lane,
                "status": phase_record["status"],
                "reason_code": _phase_reason(phase.name, phase_record),
                "exit_code": phase_record["exit_code"],
                "timeout_seconds": phase.timeout_seconds,
                "evidence_path": str(evidence_path),
                "evidence_hash": phase_record["evidence_hash"],
            }
        )
        if result != 0 and exit_code == 0:
            exit_code = result
            final_status = "TIMEOUT" if phase_record["status"] == "TIMEOUT" else "FAIL"
            final_reason = _phase_reason(phase.name, phase_record)

    aggregate = {
        "schema": SCHEMA,
        "status": final_status,
        "reason_code": final_reason,
        "fail_closed": final_status != "PASS",
        "phase_count": len(PHASES),
        "phases": phase_results,
        "partial_audit_preserved": True,
    }
    _write_json(evidence_output, aggregate)
    print(f"FULL_REGRESSION_STATUS={final_status}", flush=True)
    print(f"FULL_REGRESSION_REASON_CODE={final_reason}", flush=True)
    print(f"FULL_REGRESSION_EVIDENCE={evidence_output}", flush=True)
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run fail-closed full regression validation phases")
    parser.add_argument("--evidence-output", type=Path, default=Path("validation/full-regression-validation.json"))
    parser.add_argument("--phase-dir", type=Path, default=Path("validation/full-regression"))
    args = parser.parse_args(argv)
    return run_phases(evidence_output=args.evidence_output, phase_dir=args.phase_dir)


if __name__ == "__main__":
    raise SystemExit(main())
