#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LANE_LIMITS_SECONDS = {
    "fast_pr": 600,
    "dependency": 600,
    "production_readiness": 1200,
    "full_regression": 7200,
    "full_regression_compile": 900,
    "full_regression_publication": 900,
    "full_regression_gateway_security_governance": 2400,
    "full_regression_heavy_slow": 2400,
}

TIMEOUT_REASON_CODES = {
    "fast_pr": "VALIDATION_TIMEOUT_FAST_PR",
    "dependency": "VALIDATION_TIMEOUT_DEPENDENCY",
    "production_readiness": "VALIDATION_TIMEOUT_PRODUCTION_READINESS",
    "full_regression": "VALIDATION_TIMEOUT_FULL_REGRESSION",
    "full_regression_compile": "PHASE_TIMEOUT_compile_import",
    "full_regression_publication": "PHASE_TIMEOUT_publication_runtime_tests",
    "full_regression_gateway_security_governance": "PHASE_TIMEOUT_gateway_security_governance_tests",
    "full_regression_heavy_slow": "PHASE_TIMEOUT_heavy_slow_tests",
}

VALIDATION_SCHEMA = "usbay.bounded_validation_evidence.v1"
SECRET_MARKERS = (
    "PRIVATE KEY",
    "BEGIN PRIVATE",
    "ACCESS_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "USBAY_SECRET",
    "approval_contents",
    "raw_payload",
)


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _assert_safe_command(command: list[str]) -> None:
    joined = " ".join(command)
    lowered = joined.lower()
    if any(marker.lower() in lowered for marker in SECRET_MARKERS):
        raise SystemExit("VALIDATION_COMMAND_UNSAFE")


def _write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    payload = dict(evidence)
    payload["evidence_hash"] = _sha256_text(_canonical_json(payload))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _timeout_for_lane(lane: str, requested: int | None) -> int:
    if lane not in LANE_LIMITS_SECONDS:
        raise SystemExit("VALIDATION_LANE_UNKNOWN")
    maximum = LANE_LIMITS_SECONDS[lane]
    if requested is None:
        return maximum
    if requested <= 0:
        raise SystemExit("VALIDATION_TIMEOUT_INVALID")
    if requested > maximum:
        raise SystemExit("VALIDATION_TIMEOUT_EXCEEDS_LANE_MAX")
    return requested


def run_bounded(command: list[str], *, lane: str, timeout_seconds: int, evidence_output: Path) -> int:
    _assert_safe_command(command)
    started = time.monotonic()
    started_at = _now_utc()
    process = subprocess.Popen(command, start_new_session=True)
    timed_out = False
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        return_code = 124

    duration_ms = int((time.monotonic() - started) * 1000)
    if timed_out:
        validation_status = "TIMEOUT"
        reason_code = TIMEOUT_REASON_CODES[lane]
        fail_closed = True
    elif return_code == 0:
        validation_status = "PASS"
        reason_code = "VALIDATION_PASSED"
        fail_closed = False
    else:
        validation_status = "FAIL"
        reason_code = "VALIDATION_COMMAND_FAILED"
        fail_closed = True

    evidence = {
        "schema": VALIDATION_SCHEMA,
        "lane": lane,
        "status": validation_status,
        "reason_code": reason_code,
        "fail_closed": fail_closed,
        "command_sha256": _sha256_text(_canonical_json({"argv": command})),
        "command_arg_count": len(command),
        "started_at_utc": started_at,
        "finished_at_utc": _now_utc(),
        "duration_ms": duration_ms,
        "timeout_seconds": timeout_seconds,
        "exit_code": return_code,
        "partial_audit_preserved": True,
    }
    _write_evidence(evidence_output, evidence)
    print(f"VALIDATION_LANE={lane}", flush=True)
    print(f"VALIDATION_STATUS={validation_status}", flush=True)
    print(f"VALIDATION_REASON_CODE={reason_code}", flush=True)
    print(f"VALIDATION_EVIDENCE={evidence_output}", flush=True)
    return 124 if timed_out else return_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a validation command with governed bounded execution")
    parser.add_argument("--lane", choices=sorted(LANE_LIMITS_SECONDS), required=True)
    parser.add_argument("--timeout-seconds", type=int)
    parser.add_argument("--evidence-output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("VALIDATION_COMMAND_MISSING")
    timeout_seconds = _timeout_for_lane(args.lane, args.timeout_seconds)
    return run_bounded(command, lane=args.lane, timeout_seconds=timeout_seconds, evidence_output=args.evidence_output)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
