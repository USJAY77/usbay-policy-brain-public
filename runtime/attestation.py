#!/usr/bin/env python3
"""
USBAY execution attestation helpers.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audit import ledger
import runtime.security_guard as security_guard


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest().lower()


def _execution_hash(*, command: dict, stdout: str, stderr: str, exit_code: int) -> str:
    payload = {
        "command": command,
        "stdout_hash": _sha256_text(stdout),
        "stderr_hash": _sha256_text(stderr),
        "exit_code": exit_code,
    }
    return hashlib.sha256(ledger.canonical_json_bytes(payload)).hexdigest().lower()


def generate_execution_attestation(
    *,
    command_id: str,
    command: dict,
    stdout: str,
    stderr: str,
    exit_code: int,
    signer_adapter: Any,
    key_id: str,
    cwd: Path,
    attestation_path: Path,
    signature_path: Path,
) -> dict:
    attestation = {
        "command_id": command_id,
        "execution_hash": _execution_hash(
            command=command,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
        ),
        "stdout_hash": _sha256_text(stdout),
        "stderr_hash": _sha256_text(stderr),
        "exit_code": int(exit_code),
        "timestamp": _utc_now(),
        "key_id": key_id,
        "signer_type": signer_adapter.signer_type,
        "signature_status": "signed",
    }
    security_guard.write_guarded_bytes(attestation_path, ledger.canonical_json_bytes(attestation))
    security_guard.guard_runtime_write_path(signature_path)
    signer_adapter.sign_file(payload_path=attestation_path, signature_path=signature_path, cwd=cwd)
    return attestation
