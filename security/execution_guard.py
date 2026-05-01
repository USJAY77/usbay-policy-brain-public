from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import time
import uuid
from urllib import error, request

from security.request_signing import sign_request_payload


DEFAULT_GATEWAY_URL = "http://127.0.0.1:8000/execute"
DEFAULT_TENANT_ID = "t1"
DEFAULT_DEVICE = "laptop-1"
DEFAULT_POLICY_VERSION = "local-policy-v1"


def canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def request_signature_message(payload: dict) -> str:
    unsigned = payload.copy()
    unsigned.pop("signature", None)
    unsigned.pop("decision_id", None)
    unsigned.pop("decision_signature", None)
    unsigned.pop("decision_signature_classic", None)
    unsigned.pop("decision_signature_pqc", None)
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
        "actor_id": metadata.get("actor_id", metadata.get("user_id", "execution-actor")),
        "tenant_id": metadata.get("tenant_id", DEFAULT_TENANT_ID),
        "device": metadata.get("device", DEFAULT_DEVICE),
        "compute_target": metadata.get("compute_target", "cpu"),
        "compute_risk_level": metadata.get("compute_risk_level", "low"),
        "data_sensitivity": metadata.get("data_sensitivity", "low"),
        "execution_location": metadata.get("execution_location", "local"),
    }
    if metadata.get("user_id") is not None:
        payload["user_id"] = metadata["user_id"]
    payload["policy_version"] = metadata.get("policy_version", DEFAULT_POLICY_VERSION)
    return payload


def sign_payload(payload: dict, metadata: dict) -> dict:
    private_key = metadata.get("request_private_key") or os.getenv("USBAY_REQUEST_SIGNING_KEY")
    pubkey_id = metadata.get("pubkey_id") or os.getenv("USBAY_REQUEST_PUBKEY_ID", "request_key_2026_01")
    if not private_key:
        raise RuntimeError("EXECUTION_GUARD_FAIL_CLOSED: missing request signing key")
    return sign_request_payload(payload, private_key, pubkey_id)


def _gateway_url(metadata: dict, path: str) -> str:
    base = metadata.get("gateway_url", DEFAULT_GATEWAY_URL)
    if base.endswith("/execute"):
        base = base[: -len("/execute")]
    return f"{base}{path}"


def _post_to_gateway(payload: dict, metadata: dict, path: str = "/execute") -> tuple[int, dict]:
    gateway_client = metadata.get("gateway_client")
    if gateway_client is not None:
        response = gateway_client.post(path, json=payload)
        return response.status_code, response.json()

    body = json.dumps(payload).encode("utf-8")
    http_request = request.Request(
        _gateway_url(metadata, path),
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


def _get_gateway_health(metadata: dict) -> tuple[int, dict]:
    gateway_client = metadata.get("gateway_client")
    if gateway_client is not None:
        response = gateway_client.get("/health")
        return response.status_code, response.json()

    http_request = request.Request(
        _gateway_url(metadata, "/health"),
        headers={"Content-Type": "application/json"},
        method="GET",
    )
    try:
        with request.urlopen(http_request, timeout=float(metadata.get("timeout", 5.0))) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        response_body = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(response_body)
        except json.JSONDecodeError:
            return exc.code, {"error": "gateway_unavailable"}


def redis_required() -> bool:
    return os.getenv("REQUIRE_REDIS", "").lower() == "true"


def _redis_dependency_allows_execution(metadata: dict) -> bool:
    if not redis_required():
        return True
    status_code, health = _get_gateway_health(metadata)
    if status_code >= 500:
        return False
    if health.get("redis_available") is not True:
        return False
    if health.get("replay_protection_active") is not True:
        return False
    if health.get("mode") != "NORMAL":
        return False
    return True


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
        if not _redis_dependency_allows_execution(metadata):
            return {"error": "execution_denied", "reason": "redis_unavailable", "command_hash": command_hash(cmd)}
        payload = build_execution_payload(cmd, metadata)
        signed_payload = sign_payload(payload, metadata)
        decide_status, decide_response = _post_to_gateway(signed_payload, metadata, "/decide")
        if decide_status != 200 or decide_response.get("decision") != "ALLOW":
            return {"error": "execution_denied", "command_hash": command_hash(cmd)}

        signed_payload["decision_id"] = decide_response.get("decision_id")
        signed_payload["decision_signature"] = decide_response.get("decision_signature")
        signed_payload["decision_signature_classic"] = decide_response.get("decision_signature_classic")
        signed_payload["decision_signature_pqc"] = decide_response.get("decision_signature_pqc")
        status_code, gateway_response = _post_to_gateway(signed_payload, metadata)
    except Exception:
        return {"error": "execution_denied", "command_hash": command_hash(cmd)}

    if status_code != 200 or gateway_response.get("status") != "EXECUTED":
        return {"error": "execution_denied", "command_hash": command_hash(cmd)}

    return _run_command(cmd)
