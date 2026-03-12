#!/usr/bin/env python3
"""
Validate policy integrity for USBAY governance.

Fail-closed behavior:
- any missing artifact, parse issue, digest mismatch, or signature failure returns non-zero
- no uncertain or partially validated policy is accepted
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
POLICY_JSON = ROOT / "policy" / "policy.json"
POLICY_SHA256 = ROOT / "policy" / "policy.sha256"
POLICY_SIG = ROOT / "policy" / "policy.sig"
PUBLIC_KEY = ROOT / "policy" / "public_key.pem"


def _fail(message: str, code: int = 1) -> int:
    print(f"POLICY_VALIDATION_FAILED: {message}")
    return code


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"unable to read {path}: {exc}") from exc


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"unable to read {path}: {exc}") from exc


def _require_file(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"missing required file: {path}")
    if not path.is_file():
        raise RuntimeError(f"required path is not a file: {path}")


def validate_required_files() -> None:
    _require_file(POLICY_JSON)
    _require_file(POLICY_SHA256)
    _require_file(POLICY_SIG)
    _require_file(PUBLIC_KEY)


def validate_policy_json() -> None:
    raw = _read_text(POLICY_JSON)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {POLICY_JSON}: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValueError("policy.json must contain a JSON object at top level")

    if not parsed:
        raise ValueError("policy.json must not be empty")


def validate_sha256() -> None:
    policy_bytes = _read_bytes(POLICY_JSON)
    expected_raw = _read_text(POLICY_SHA256)

    # accepteer zowel "<hash>" als "<hash>  filename"
    expected_hash = expected_raw.split()[0].strip().lower()
    actual_hash = hashlib.sha256(policy_bytes).hexdigest().lower()

    if len(expected_hash) != 64:
        raise ValueError(f"invalid sha256 format in {POLICY_SHA256}")

    if actual_hash != expected_hash:
        raise ValueError(
            f"sha256 mismatch for {POLICY_JSON}: expected {expected_hash}, got {actual_hash}"
        )


def validate_signature() -> None:
    command = [
        "openssl",
        "dgst",
        "-sha256",
        "-verify",
        str(PUBLIC_KEY),
        "-signature",
        str(POLICY_SIG),
        str(POLICY_JSON),
    ]

    try:
        result = subprocess.run(
            command,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("openssl not available for signature verification") from exc
    except OSError as exc:
        raise RuntimeError(f"failed to execute openssl: {exc}") from exc

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()

    if result.returncode != 0:
        detail = " | ".join(part for part in [stdout, stderr] if part)
        if not detail:
            detail = "openssl signature verification returned non-zero exit code"
        raise RuntimeError(f"signature verification failed: {detail}")

    normalized_stdout = stdout.lower()
    if "verified ok" not in normalized_stdout:
        detail = " | ".join(part for part in [stdout, stderr] if part)
        raise RuntimeError(f"unexpected openssl verification output: {detail}")


def main() -> int:
    try:
        validate_required_files()
        validate_policy_json()
        validate_sha256()
        validate_signature()
    except Exception as exc:
        return _fail(str(exc), code=1)

    print("POLICY_VALIDATION_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())