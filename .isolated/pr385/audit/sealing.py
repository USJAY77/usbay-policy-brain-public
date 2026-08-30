#!/usr/bin/env python3
"""
USBAY audit seal helpers.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from audit import ledger


def sign_path(*, private_key: Path, payload_path: Path, signature_path: Path, cwd: Path) -> None:
    command = [
        "openssl",
        "dgst",
        "-sha256",
        "-sign",
        str(private_key),
        "-out",
        str(signature_path),
        str(payload_path),
    ]
    try:
        result = subprocess.run(command, cwd=str(cwd), capture_output=True, text=True, check=False)
    except OSError as exc:
        raise RuntimeError(f"failed to execute openssl: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip() or "openssl signing failed"
        raise RuntimeError(detail)


def verify_path(*, public_key: Path, payload_path: Path, signature_path: Path, cwd: Path) -> None:
    command = [
        "openssl",
        "dgst",
        "-sha256",
        "-verify",
        str(public_key),
        "-signature",
        str(signature_path),
        str(payload_path),
    ]
    try:
        result = subprocess.run(command, cwd=str(cwd), capture_output=True, text=True, check=False)
    except OSError as exc:
        raise RuntimeError(f"failed to execute openssl: {exc}") from exc
    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if result.returncode != 0:
        detail = " | ".join(part for part in [stdout, stderr] if part) or "openssl signature verification returned non-zero exit code"
        raise RuntimeError(detail)
    if "verified ok" not in stdout.lower():
        detail = " | ".join(part for part in [stdout, stderr] if part)
        raise RuntimeError(f"unexpected openssl verification output: {detail}")


def write_seal(
    *,
    seal_path: Path,
    signature_path: Path,
    private_key: Path,
    cwd: Path,
    latest_entry_hash: str,
    entry_count: int,
    sealed_at: str,
    commit_sha: str,
) -> dict:
    payload = {
        "latest_entry_hash": latest_entry_hash,
        "entry_count": entry_count,
        "sealed_at": sealed_at,
        "commit_sha": commit_sha,
    }
    seal_path.write_bytes(ledger.canonical_json_bytes(payload))
    sign_path(private_key=private_key, payload_path=seal_path, signature_path=signature_path, cwd=cwd)
    return payload


def verify_seal(
    *,
    seal_path: Path,
    signature_path: Path,
    public_key: Path,
    cwd: Path,
) -> dict:
    try:
        payload = json.loads(seal_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON in {seal_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"{seal_path} must contain a JSON object at top level")
    required = {"latest_entry_hash", "entry_count", "sealed_at", "commit_sha"}
    missing = sorted(required - set(payload.keys()))
    if missing:
        raise RuntimeError(f"audit seal missing required fields: {missing}")
    verify_path(public_key=public_key, payload_path=seal_path, signature_path=signature_path, cwd=cwd)
    return payload
