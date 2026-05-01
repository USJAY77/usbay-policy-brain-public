#!/usr/bin/env python3
"""
USBAY remote command request validation.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import runtime.policy_validator as policy_validator
import runtime.security_guard as security_guard


REQUIRED_REQUEST_FIELDS = {
    "actor",
    "actor_id",
    "actor_role",
    "actor_type",
    "device_id",
    "reason",
    "command",
    "tenant_id",
    "token_key_id",
    "policy_hash",
    "policy_version",
    "nonce",
    "timestamp",
}
OPTIONAL_REQUEST_FIELDS = {"request_id", "session_id", "simulation_mode", "device_fingerprint"}
ALLOWED_REQUEST_FIELDS = REQUIRED_REQUEST_FIELDS | OPTIONAL_REQUEST_FIELDS


class CommandModel:
    REQUIRED_FIELDS = policy_validator.COMMAND_REQUEST_REQUIRED_FIELDS

    def validate_command_request_payload(self, payload: dict) -> bool:
        return policy_validator.validate_command_request_payload(payload)

    def load_command_request(self, path: Path) -> dict:
        return load_command_request(path)


def _read_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"missing command request: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON in {path}: {exc}") from exc
    except OSError as exc:
        raise RuntimeError(f"unable to read {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"expected JSON object in {path}")
    return payload


def validate_command(command: dict) -> dict:
    if not isinstance(command, dict):
        raise RuntimeError("command must be a JSON object")
    return security_guard.guard_command_spec(command)


def validate_remote_command_request_payload(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise RuntimeError("missing required fields")
    unknown = sorted(set(payload.keys()) - ALLOWED_REQUEST_FIELDS)
    if unknown:
        raise RuntimeError(f"command request contains unexpected fields: {', '.join(unknown)}")
    payload = dict(payload)
    actor = str(payload.get("actor", "")).strip()
    actor_id = str(payload.get("actor_id", "")).strip()
    actor_type = str(payload.get("actor_type", "")).strip().lower()
    actor_role = str(payload.get("actor_role", "")).strip().lower()
    if actor and actor_id and actor != actor_id:
        raise RuntimeError("ACTOR_IDENTITY_MISMATCH")
    if actor_type and actor_role and actor_type != actor_role:
        raise RuntimeError("ACTOR_ROLE_MISMATCH")
    payload["actor"] = actor
    payload["actor_id"] = actor_id or actor
    payload["actor_type"] = actor_type
    payload["actor_role"] = actor_role or actor_type
    missing = [field for field in sorted(REQUIRED_REQUEST_FIELDS) if not payload.get(field)]
    if missing:
        raise RuntimeError(f"command request missing required fields: {', '.join(missing)}")
    payload["request_id"] = str(payload.get("request_id", "")).strip() or str(uuid.uuid4())
    payload["tenant_id"] = str(payload.get("tenant_id", "")).strip()
    payload["token_key_id"] = str(payload.get("token_key_id", "")).strip()
    payload["policy_hash"] = str(payload.get("policy_hash", "")).strip().lower()
    payload["policy_version"] = str(payload.get("policy_version", "")).strip()
    payload["session_id"] = str(payload.get("session_id", "")).strip() or payload["request_id"]
    payload["nonce"] = str(payload.get("nonce", "")).strip()
    payload["timestamp"] = str(payload.get("timestamp", "")).strip()
    payload["simulation_mode"] = bool(payload.get("simulation_mode", False))
    payload["device_fingerprint"] = str(payload.get("device_fingerprint", "")).strip()
    payload["command"] = validate_command(payload["command"])
    payload["action"] = "remote_execute"
    return payload


def load_command_request(path: Path) -> dict:
    payload = _read_json(path)
    return validate_remote_command_request_payload(payload)


def validate_command_request_payload(payload: dict) -> bool:
    return command_model.validate_command_request_payload(payload)


command_model = CommandModel()
