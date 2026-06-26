from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from terminal.command_governance import (
    DEFAULT_POLICY_HASH,
    SENSITIVE_PATH_MARKERS,
    classify_command,
    normalize_command,
    sha256_json,
    sha256_text,
)


VERIFICATION_HARNESS_VERSION = "pb258-safe-verification-command-harness-v1"
SENSITIVE_OUTPUT_MARKERS = ("secret", "token", "password", "private key", "customer data", "personal data")


def _contains_sensitive_output(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in SENSITIVE_OUTPUT_MARKERS)


def execute_verification_command(
    command: str | list[str],
    *,
    cwd: str | Path = ".",
    timeout_seconds: float = 10.0,
    policy_hash: str = DEFAULT_POLICY_HASH,
) -> dict[str, Any]:
    classification = classify_command(command)
    if classification.get("decision") != "ALLOW_READ_ONLY":
        return _fail_closed(command, classification.get("reason", "UNKNOWN_COMMAND"), policy_hash=policy_hash)
    try:
        parts = normalize_command(command)
        completed = subprocess.run(
            list(parts),
            cwd=Path(cwd),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _fail_closed(command, "TIMEOUT", policy_hash=policy_hash)
    except Exception:
        return _fail_closed(command, "COMMAND_EXECUTION_ERROR", policy_hash=policy_hash)

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    sensitive = _contains_sensitive_output(stdout) or _contains_sensitive_output(stderr)
    return {
        "decision": "VERIFIED",
        "command": " ".join(parts),
        "exit_code": completed.returncode,
        "stdout_hash": sha256_text(stdout),
        "stderr_hash": sha256_text(stderr),
        "stdout_stored": "" if sensitive else stdout[:200],
        "stderr_stored": "" if sensitive else stderr[:200],
        "sensitive_output_detected": sensitive,
        "timestamp": _timestamp(),
        "policy_hash": policy_hash,
        "contract_version": VERIFICATION_HARNESS_VERSION,
    }


def _fail_closed(command: str | list[str], reason: str, *, policy_hash: str) -> dict[str, Any]:
    return {
        "decision": "FAIL_CLOSED",
        "command": command if isinstance(command, str) else " ".join(command),
        "exit_code": None,
        "stdout_hash": sha256_text(""),
        "stderr_hash": sha256_text(reason),
        "stdout_stored": "",
        "stderr_stored": "",
        "sensitive_output_detected": any(marker in str(command).lower() for marker in SENSITIVE_PATH_MARKERS),
        "timestamp": _timestamp(),
        "policy_hash": policy_hash,
        "blocked_reason": reason,
        "contract_version": VERIFICATION_HARNESS_VERSION,
    }


def _timestamp() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def append_terminal_evidence_chain(records: list[dict[str, Any]]) -> dict[str, Any]:
    chain: list[dict[str, Any]] = []
    previous_hash = "GENESIS"
    for index, record in enumerate(records):
        payload = {
            "index": index,
            "previous_hash": previous_hash,
            "record_hash": sha256_json(record),
        }
        current_hash = sha256_json(payload)
        chain.append({**payload, "current_hash": current_hash})
        previous_hash = current_hash
    return {
        "decision": "VERIFIED",
        "hash_chain": chain,
        "record_count": len(chain),
        "latest_hash": previous_hash,
        "sensitive_output_stored": False,
        "contract_version": VERIFICATION_HARNESS_VERSION,
    }
