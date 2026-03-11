#!/usr/bin/env python3
"""Policy validation entry point for governance checks.

Fail-closed behavior: any uncertainty or missing artifact is treated as invalid.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = REPO_ROOT / "policy" / "policy.json"
POLICY_HASH_PATH = REPO_ROOT / "policy" / "policy.sha256"


def _fail(message: str, code: int = 1) -> int:
    print(f"POLICY_VALIDATION_FAILED: {message}")
    return code


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"unable to read {path}: {exc}") from exc


def validate_policy_integrity() -> int:
    if not POLICY_PATH.exists():
        return _fail(f"missing policy file at {POLICY_PATH}")
    if not POLICY_HASH_PATH.exists():
        return _fail(f"missing policy hash at {POLICY_HASH_PATH}")

    try:
        policy_raw = POLICY_PATH.read_bytes()
    except OSError as exc:
        return _fail(f"cannot read policy file: {exc}")

    try:
        json.loads(policy_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _fail(f"policy JSON parse error: {exc}")

    actual_hash = hashlib.sha256(policy_raw).hexdigest()

    try:
        expected_hash = _read_text(POLICY_HASH_PATH)
    except RuntimeError as exc:
        return _fail(str(exc))

    if len(expected_hash) != 64 or any(c not in "0123456789abcdef" for c in expected_hash.lower()):
        return _fail("policy.sha256 does not contain a valid sha256 digest")

    if actual_hash != expected_hash.lower():
        return _fail("policy hash mismatch")

    print("POLICY_VALIDATION_OK")
    return 0


if __name__ == "__main__":
    sys.exit(validate_policy_integrity())
