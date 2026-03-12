#!/usr/bin/env python3


#!/usr/bin/env python3
"""
Governance enforcement gateway preflight checks.

Fail-closed behavior:
- if any control cannot be confirmed, exit non-zero
- do not continue on uncertainty
- do not log sensitive payloads
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
AUDIT_LOG_DIR = ROOT / "audit" / "logs"
POLICY_VALIDATOR = ROOT / "runtime" / "policy_validator.py"
FORBIDDEN_PRIVATE_KEY = ROOT / "private_key.pem"


def _fail(message: str, code: int = 1) -> int:
    print(f"ENFORCEMENT_GATEWAY_FAILED: {message}")
    return code


def check_private_key_not_present() -> None:
    """
    Runtime repo/worktree must not contain signing private key material.
    Public verification is allowed; private signing material is not.
    """
    if FORBIDDEN_PRIVATE_KEY.exists():
        raise RuntimeError(
            f"forbidden private key material present: {FORBIDDEN_PRIVATE_KEY}"
        )


def check_audit_log_writability() -> None:
    """
    Verify the audit log directory exists and is practically writable.
    A real write/delete probe is safer than only checking mode bits.
    """
    if not AUDIT_LOG_DIR.exists() or not AUDIT_LOG_DIR.is_dir():
        raise RuntimeError(f"audit log directory missing: {AUDIT_LOG_DIR}")

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=AUDIT_LOG_DIR,
            prefix=".writecheck_",
            delete=True,
            encoding="utf-8",
        ) as handle:
            handle.write("audit write probe\n")
            handle.flush()
    except OSError as exc:
        raise RuntimeError(
            f"audit log directory not writable in practice: {AUDIT_LOG_DIR} ({exc})"
        ) from exc


def run_policy_validation() -> None:
    """
    Run the policy validator as a hard preflight requirement.
    Any non-zero result is treated as deny/fail-closed.
    """
    if not POLICY_VALIDATOR.exists():
        raise RuntimeError(f"policy validator missing: {POLICY_VALIDATOR}")

    result = subprocess.run(
        [sys.executable, str(POLICY_VALIDATOR)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()
        detail = " | ".join(part for part in [stdout, stderr] if part)
        if not detail:
            detail = "policy validator returned non-zero exit code"
        raise RuntimeError(detail)


def main() -> int:
    try:
        check_private_key_not_present()
        check_audit_log_writability()
        run_policy_validation()
    except Exception as exc:
        return _fail(str(exc), code=1)

    print("ENFORCEMENT_GATEWAY_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())