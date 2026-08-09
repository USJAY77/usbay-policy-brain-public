#!/usr/bin/env python3
"""
USBAY governance action-token helpers.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from audit import ledger, sealing
import runtime.security_guard as security_guard


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _isoformat(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value: str, *, label: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception as exc:
        raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: invalid {label}: {exc}") from exc


def canonical_token_bytes(token: dict) -> bytes:
    return ledger.canonical_json_bytes(token)


def command_hash(command: dict) -> str:
    return hashlib.sha256(canonical_token_bytes(command)).hexdigest().lower()


def generate_action_token(
    *,
    command: dict,
    policy_hash: str,
    approvals_hash: str,
    evidence_hash: str,
    signer_adapter: Any,
    cwd: Path,
    token_path: Path,
    signature_path: Path,
    ttl_seconds: int = 300,
) -> dict:
    issued_at = _utc_now()
    token = {
        "command_id": str(uuid.uuid4()),
        "policy_hash": policy_hash,
        "approvals_hash": approvals_hash,
        "evidence_hash": evidence_hash,
        "allowed_entrypoint": str(command["entrypoint"]),
        "command_hash": command_hash(command),
        "issued_at": _isoformat(issued_at),
        "expires_at": _isoformat(issued_at + timedelta(seconds=ttl_seconds)),
    }
    security_guard.write_guarded_bytes(token_path, canonical_token_bytes(token))
    security_guard.guard_runtime_write_path(signature_path)
    signer_adapter.sign_file(payload_path=token_path, signature_path=signature_path, cwd=cwd)
    return token


def load_action_token(token_path: Path) -> dict:
    try:
        token = json.loads(token_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: missing action token") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: invalid action token JSON: {exc}") from exc
    if not isinstance(token, dict):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: action token must be a JSON object")
    return token


def verify_action_token(
    *,
    command: dict,
    token_path: Path,
    signature_path: Path,
    public_key: Path,
    cwd: Path,
    now: datetime | None = None,
) -> dict:
    if not token_path.exists():
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: missing action token")
    if not signature_path.exists():
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: missing action token signature")
    try:
        sealing.verify_path(
            public_key=public_key,
            payload_path=token_path,
            signature_path=signature_path,
            cwd=cwd,
        )
    except Exception as exc:
        raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: {exc}") from exc
    token = load_action_token(token_path)
    required = {
        "command_id",
        "policy_hash",
        "approvals_hash",
        "evidence_hash",
        "allowed_entrypoint",
        "command_hash",
        "issued_at",
        "expires_at",
    }
    missing = sorted(required - set(token.keys()))
    if missing:
        raise RuntimeError(
            f"EXECUTOR_VALIDATION_FAILED: action token missing required fields: {missing}"
        )
    if str(token["allowed_entrypoint"]) != str(command["entrypoint"]):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: action token entrypoint mismatch")
    if str(token["command_hash"]).lower() != command_hash(command):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: action token command binding mismatch")
    current_time = now or _utc_now()
    issued_at = _parse_timestamp(str(token["issued_at"]), label="issued_at")
    expires_at = _parse_timestamp(str(token["expires_at"]), label="expires_at")
    if expires_at <= issued_at:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: action token expiry is invalid")
    if current_time > expires_at:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: action token expired")
    return token
