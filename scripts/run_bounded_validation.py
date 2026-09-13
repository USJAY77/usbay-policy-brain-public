#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import signal
import shutil
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

OBSERVABILITY_SCHEMA = "usbay.ci_nondeterminism_observability.v1"
OBSERVABILITY_ENV_ALLOWLIST = (
    "CI",
    "GITHUB_ACTIONS",
    "GITHUB_BASE_REF",
    "GITHUB_EVENT_NAME",
    "GITHUB_HEAD_REF",
    "GITHUB_JOB",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REPOSITORY",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_RUN_ID",
    "GITHUB_SHA",
    "GITHUB_WORKFLOW",
    "ImageOS",
    "ImageVersion",
    "RUNNER_ARCH",
    "RUNNER_ENVIRONMENT",
    "RUNNER_OS",
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


def _hash_file(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"present": False, "reason": "COLLECTION_FILE_NOT_CONFIGURED"}
    if not path.exists() or not path.is_file():
        return {"present": False, "reason": "COLLECTION_FILE_MISSING"}
    data = path.read_bytes()
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    test_lines = [line.strip() for line in lines if line.strip().startswith("tests/") and "::test_" in line]
    return {
        "present": True,
        "path_hash": _sha256_text(str(path)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "line_count": len(lines),
        "test_node_count": len(test_lines),
        "test_order_sha256": _sha256_text(_canonical_json({"tests": test_lines})),
    }


def _command_stdout(command: list[str]) -> str:
    try:
        completed = subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
    except Exception:
        return ""
    return completed.stdout.strip()


def _dependency_fingerprint() -> dict[str, Any]:
    python = sys.executable
    pip = _command_stdout([python, "-m", "pip", "--version"])
    freeze = _command_stdout([python, "-m", "pip", "freeze", "--all"])
    if not freeze:
        return {
            "available": False,
            "python_executable_hash": _sha256_text(python),
            "pip_version_hash": _sha256_text(pip),
            "freeze_sha256": "",
            "package_count": 0,
        }
    packages = [line for line in freeze.splitlines() if line.strip()]
    return {
        "available": True,
        "python_executable_hash": _sha256_text(python),
        "pip_version_hash": _sha256_text(pip),
        "freeze_sha256": _sha256_text("\n".join(packages)),
        "package_count": len(packages),
    }


def _git_value(args: list[str]) -> str:
    git = shutil.which("git")
    if not git:
        return ""
    return _command_stdout([git, *args])


def _environment_presence() -> dict[str, Any]:
    present = sorted(name for name in OBSERVABILITY_ENV_ALLOWLIST if os.getenv(name, "") != "")
    return {
        "allowlist": list(OBSERVABILITY_ENV_ALLOWLIST),
        "present": present,
        "present_count": len(present),
        "presence_sha256": _sha256_text(_canonical_json({"present": present})),
        "raw_values_persisted": False,
    }


def _observability_payload(
    *,
    command: list[str],
    lane: str,
    timeout_seconds: int,
    started_at: str,
    finished_at: str,
    duration_ms: int,
    return_code: int,
    validation_status: str,
    reason_code: str,
    collection_file: Path | None,
) -> dict[str, Any]:
    environment = _environment_presence()
    payload = {
        "schema": OBSERVABILITY_SCHEMA,
        "lane": lane,
        "status": validation_status,
        "reason_code": reason_code,
        "exit_code": return_code,
        "fail_closed": validation_status != "PASS",
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "duration_ms": duration_ms,
        "timeout_seconds": timeout_seconds,
        "command_sha256": _sha256_text(_canonical_json({"argv": command})),
        "command_arg_count": len(command),
        "tested_sha": _git_value(["rev-parse", "HEAD"]),
        "workflow_context": environment,
        "workflow_context_sha256": _sha256_text(_canonical_json(environment)),
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable_hash": _sha256_text(sys.executable),
        },
        "runner": {
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "dependency_fingerprint": _dependency_fingerprint(),
        "collection_fingerprint": _hash_file(collection_file),
        "privacy_boundary": {
            "raw_environment_values_allowlisted": False,
            "environment_presence_only": True,
            "raw_command_persisted": False,
            "secret_values_persisted": False,
            "raw_packets_persisted": False,
            "private_key_material_persisted": False,
        },
    }
    payload["observability_hash"] = _sha256_text(_canonical_json(payload))
    return payload


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


def run_bounded(
    command: list[str],
    *,
    lane: str,
    timeout_seconds: int,
    evidence_output: Path,
    observability_output: Path | None = None,
    collection_file: Path | None = None,
) -> int:
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
    if observability_output is not None:
        observability = _observability_payload(
            command=command,
            lane=lane,
            timeout_seconds=timeout_seconds,
            started_at=started_at,
            finished_at=evidence["finished_at_utc"],
            duration_ms=duration_ms,
            return_code=return_code,
            validation_status=validation_status,
            reason_code=reason_code,
            collection_file=collection_file,
        )
        _write_evidence(observability_output, observability)
        print(f"VALIDATION_OBSERVABILITY={observability_output}", flush=True)
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
    parser.add_argument("--observability-output", type=Path)
    parser.add_argument("--collection-file", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("VALIDATION_COMMAND_MISSING")
    timeout_seconds = _timeout_for_lane(args.lane, args.timeout_seconds)
    return run_bounded(
        command,
        lane=args.lane,
        timeout_seconds=timeout_seconds,
        evidence_output=args.evidence_output,
        observability_output=args.observability_output,
        collection_file=args.collection_file,
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
