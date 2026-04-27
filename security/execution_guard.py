from __future__ import annotations

import hashlib
import hmac
import json
import os
import shlex
import subprocess
import time
import uuid
from urllib import error, request


DEFAULT_GATEWAY_URL = "http://127.0.0.1:8000/execute"
DEFAULT_TENANT_ID = "t1"
DEFAULT_DEVICE = "laptop-1"


def canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def request_signature_message(payload: dict) -> str:
    unsigned = payload.copy()
    unsigned.pop("signature", None)
    return canonical(unsigned)


def command_hash(cmd: str) -> str:
    return hashlib.sha256(cmd.encode("utf-8")).hexdigest()


def build_execution_payload(cmd: str, metadata: dict) -> dict:
    payload = {
        "type": "execution",
        "action": "execute_command",
        "command": cmd,
        "command_hash": command_hash(cmd),
        "timestamp": int(time.time()),
        "nonce": uuid.uuid4().hex,
        "tenant_id": metadata.get("tenant_id", DEFAULT_TENANT_ID),
        "device": metadata.get("device", DEFAULT_DEVICE),
    }
    if metadata.get("user_id") is not None:
        payload["user_id"] = metadata["user_id"]
    if metadata.get("policy_version") is not None:
        payload["policy_version"] = metadata["policy_version"]
    return payload


def sign_payload(payload: dict, metadata: dict) -> dict:
    secret = metadata.get("device_key") or os.getenv("USBAY_EXECUTION_DEVICE_KEY")
    if not secret:
        raise RuntimeError("EXECUTION_GUARD_FAIL_CLOSED: missing signing key")
    signed = payload.copy()
    signed["signature"] = hmac.new(
        str(secret).encode("utf-8"),
        request_signature_message(signed).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return signed


def _post_to_gateway(payload: dict, metadata: dict) -> tuple[int, dict]:
    gateway_client = metadata.get("gateway_client")
    if gateway_client is not None:
        response = gateway_client.post("/execute", json=payload)
        return response.status_code, response.json()

    body = json.dumps(payload).encode("utf-8")
    http_request = request.Request(
        metadata.get("gateway_url", DEFAULT_GATEWAY_URL),
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(http_request, timeout=float(metadata.get("timeout", 5.0))) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        response_body = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(response_body)
        except json.JSONDecodeError:
            return exc.code, {"error": "gateway_denied"}


def _run_command(cmd: str) -> dict:
    try:
        env = os.environ.copy()
        env.setdefault("PYTHONPYCACHEPREFIX", "/tmp/usbay-pycache")
        os.makedirs(env["PYTHONPYCACHEPREFIX"], exist_ok=True)
        completed = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
    except Exception as exc:
        return {
            "error": "execution_failed",
            "detail": str(exc),
            "command_hash": command_hash(cmd),
        }

    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "command_hash": command_hash(cmd),
    }


def execute_command(cmd: str, metadata: dict) -> dict:
    metadata = metadata or {}
    try:
        payload = build_execution_payload(cmd, metadata)
        signed_payload = sign_payload(payload, metadata)
        status_code, gateway_response = _post_to_gateway(signed_payload, metadata)
    except Exception:
        return {"error": "execution_denied", "command_hash": command_hash(cmd)}

    if status_code != 200 or gateway_response.get("status") != "EXECUTED":
        return {"error": "execution_denied", "command_hash": command_hash(cmd)}

    return _run_command(cmd)
