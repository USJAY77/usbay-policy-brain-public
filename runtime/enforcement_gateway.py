#!/usr/bin/env python3
"""Governance enforcement gateway preflight checks.

Fail-closed behavior: if any control cannot be confirmed, exit non-zero.
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path

from policy_validator import validate_policy_integrity


REPO_ROOT = Path(__file__).resolve().parent.parent
PRIVATE_KEY_PATH = REPO_ROOT / "private_key.pem"
AUDIT_LOG_DIR = REPO_ROOT / "audit" / "logs"


def _fail(message: str, code: int = 1) -> int:
    print(f"ENFORCEMENT_GATEWAY_FAILED: {message}")
    return code


def _directory_has_write_bits(path: Path) -> bool:
    mode = path.stat().st_mode
    return bool(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def run_startup_checks() -> int:
    if PRIVATE_KEY_PATH.exists():
        return _fail(f"disallowed private key detected: {PRIVATE_KEY_PATH.name}")

    if not AUDIT_LOG_DIR.exists() or not AUDIT_LOG_DIR.is_dir():
        return _fail(f"audit log directory missing: {AUDIT_LOG_DIR}")

    try:
        if not _directory_has_write_bits(AUDIT_LOG_DIR):
            return _fail("audit/logs is not writable per permission bits")
    except OSError as exc:
        return _fail(f"cannot inspect audit/logs permissions: {exc}")

    validation_code = validate_policy_integrity()
    if validation_code != 0:
        return _fail("policy validation preflight failed")

    print("ENFORCEMENT_GATEWAY_OK")
    return 0


if __name__ == "__main__":
    sys.exit(run_startup_checks())
