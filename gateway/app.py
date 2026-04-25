from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pathlib import Path
from typing import Any, Dict, Optional
import json
import hashlib
import hmac
import logging
import time
import os

from audit.decision_logger import write_audit_event
from utils.canonical import canonical_json
from utils.keystore import KeyStore

app = FastAPI()
keystore = KeyStore()
logger = logging.getLogger("usbay.gateway")


class VerificationFailure(RuntimeError):
    pass


def fail_closed_response(status_code: int = 500) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": "FAIL_CLOSED"})


def request_fields_present(payload: Optional[Dict[str, Any]]) -> Dict[str, bool]:
    fields = ("action", "user_id", "device", "tenant_id", "timestamp", "signature")
    if not isinstance(payload, dict):
        return {field: False for field in fields}
    return {field: payload.get(field) is not None for field in fields}


def safe_exception_message(exc: Exception) -> str:
    message = str(exc)
    if message.startswith("FAIL_CLOSED"):
        return "FAIL_CLOSED"
    return "<redacted>"


def log_execute_failure(exc: Exception, payload: Optional[Dict[str, Any]]) -> None:
    signature = payload.get("signature") if isinstance(payload, dict) else None
    logger.warning(
        "execute failed fail_closed exception_class=%s safe_message=%s fields_present=%s signature_prefix=%s",
        exc.__class__.__name__,
        safe_exception_message(exc),
        request_fields_present(payload),
        mask_signature(signature),
    )

# =========================
# MODE (DEV / PROD)
# =========================
def get_mode() -> str:
    mode = os.getenv("USBAY_MODE")
    if mode not in ("PROD",):
        raise RuntimeError("FAIL_CLOSED:MODE_NOT_SET")
    return mode


get_mode()
print("USBAY MODE: PROD")

# =========================
# CONFIG
# =========================
POLICY_ROOT = Path("policy")
SECRETS_ROOT = Path("secrets")
AUDIT_ROOT = Path("audit")
POLICY_SIGNING_KEY_PATH = Path("secrets/policy.key")
MIN_POLICY_VERSION_PATH = Path("policy/min_policy_version.txt")

POLICY_VERSION = "v1"

# =========================
# REQUEST MODEL
# =========================
class CommandRequest(BaseModel):
    action: str
    user_id: str
    device: str
    tenant_id: str
    timestamp: Optional[int] = None
    signature: Optional[str] = None


@app.exception_handler(RequestValidationError)
def fail_closed_validation_error(request, exc):
    log_execute_failure(exc, None)
    return fail_closed_response(status_code=403)

# =========================
# VERSION
# =========================
def parse_version(v: str) -> int:
    if not isinstance(v, str) or not v.startswith("v"):
        raise RuntimeError("FAIL_CLOSED")
    return int(v[1:])


def safe_component(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeError("FAIL_CLOSED")
    if not all(ch.isalnum() or ch in {"-", "_"} for ch in value):
        raise RuntimeError("FAIL_CLOSED")
    return value


def tenant_policy_path(tenant_id: str) -> Path:
    return POLICY_ROOT / safe_component(tenant_id) / "policy.json"


def tenant_sig_path(tenant_id: str) -> Path:
    return POLICY_ROOT / safe_component(tenant_id) / "policy.sig"


def tenant_audit_log_path(tenant_id: str) -> Path:
    return AUDIT_ROOT / f"{safe_component(tenant_id)}.log"

# =========================
# POLICY VALIDATION
# =========================
def validate_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(policy, dict):
        raise RuntimeError("FAIL_CLOSED")

    version = policy.get("policy_version")
    if not isinstance(version, str):
        raise RuntimeError("FAIL_CLOSED")

    if version != POLICY_VERSION:
        raise RuntimeError("FAIL_CLOSED")

    min_version = MIN_POLICY_VERSION_PATH.read_text().strip()

    if parse_version(version) < parse_version(min_version):
        raise RuntimeError("FAIL_CLOSED")

    rules = policy.get("rules")
    if not isinstance(rules, list):
        raise RuntimeError("FAIL_CLOSED")

    for r in rules:
        if not isinstance(r, dict):
            raise RuntimeError("FAIL_CLOSED")
        if not isinstance(r.get("action"), str):
            raise RuntimeError("FAIL_CLOSED")
        if r.get("effect") not in ("ALLOW", "BLOCK"):
            raise RuntimeError("FAIL_CLOSED")

    return policy

# =========================
# POLICY SIGNATURE
# =========================
def verify_policy(tenant_id: str) -> Dict[str, Any]:
    policy_path = tenant_policy_path(tenant_id)
    sig_path = tenant_sig_path(tenant_id)

    if not policy_path.exists() or not sig_path.exists() or not POLICY_SIGNING_KEY_PATH.exists():
        raise RuntimeError("FAIL_CLOSED")

    policy_data = json.loads(policy_path.read_text(encoding="utf-8"))
    canonical = canonical_json(policy_data)

    key = POLICY_SIGNING_KEY_PATH.read_bytes().strip()
    expected = sig_path.read_text().strip()

    digest = hashlib.sha256(canonical).digest()
    actual = hmac.new(key, digest, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(actual, expected):
        raise RuntimeError("FAIL_CLOSED")

    return validate_policy(policy_data)

# =========================
# REQUEST SIGNATURE
# =========================
def mask_signature(signature: Optional[str]) -> str:
    if not signature:
        return "<missing>"
    return signature[:6]


def request_signature_message(payload: Dict[str, Any]) -> bytes:
    return canonical_json(
        {
            "action": payload["action"],
            "user_id": payload["user_id"],
            "device": payload["device"],
            "tenant_id": payload["tenant_id"],
            "timestamp": payload["timestamp"],
        }
    )


def hmac_bytes(value: Any) -> bytes:
    if value is None:
        raise VerificationFailure("FAIL_CLOSED")
    if isinstance(value, str):
        value = value.encode("utf-8")
    value_bytes = bytes(value)
    if not value_bytes:
        raise VerificationFailure("FAIL_CLOSED")
    return value_bytes


def verify_request(payload: Dict[str, Any]) -> None:
    tenant_id = payload.get("tenant_id")
    device = payload.get("device")
    signature = payload.get("signature")
    timestamp = payload.get("timestamp")

    if not tenant_id or not device or not signature or not timestamp:
        raise VerificationFailure("FAIL_CLOSED")

    if abs(time.time() - timestamp) > 5:
        raise VerificationFailure("FAIL_CLOSED")

    try:
        message = request_signature_message(payload)
        message_bytes = hmac_bytes(message)
    except Exception as exc:
        raise VerificationFailure("FAIL_CLOSED") from exc

    logger.debug(
        "request signature message format: %s",
        message_bytes.decode("utf-8"),
    )

    try:
        with keystore.use_device_key(safe_component(tenant_id), safe_component(device)) as key:
            key_bytes = hmac_bytes(key)
            expected = hmac.new(key_bytes, message_bytes, hashlib.sha256).hexdigest()
    except Exception as exc:
        raise VerificationFailure("FAIL_CLOSED") from exc

    logger.debug(
        "request signature comparison: computed=%s received=%s",
        mask_signature(expected),
        mask_signature(signature),
    )

    if not hmac.compare_digest(expected, signature):
        raise VerificationFailure("FAIL_CLOSED")

# =========================
# POLICY ENGINE
# =========================
def evaluate_policy(payload: Dict[str, Any]) -> str:
    policy = verify_policy(payload["tenant_id"])
    action = payload.get("action")

    for rule in policy["rules"]:
        if rule["action"] == action or rule["action"] == "*":
            return rule["effect"]

    return "BLOCK"

# =========================
# AUDIT
# =========================
def write_decision(payload: Dict[str, str], decision: str):
    tenant_id = payload["tenant_id"]
    audit_log_path = tenant_audit_log_path(tenant_id)
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    return write_audit_event(
        event_type="policy_decision",
        actor=payload["user_id"],
        decision=decision,
        policy_version=POLICY_VERSION,
        execution_origin="gateway",
        workspace="api",
        input_payload=payload,
        log_path=audit_log_path,
        tenant_id=tenant_id,
    )

# =========================
# ENDPOINT
# =========================
@app.post("/execute")
def execute(cmd: CommandRequest):
    payload: Optional[Dict[str, Any]] = None
    try:
        payload = cmd.model_dump()

        get_mode()
        if not payload.get("signature") or not payload.get("timestamp"):
            raise VerificationFailure("FAIL_CLOSED")
        verify_request(payload)

        if not payload.get("action") or not payload.get("user_id") or not payload.get("device") or not payload.get("tenant_id"):
            raise VerificationFailure("FAIL_CLOSED")

        decision = evaluate_policy(payload)

        if decision == "BLOCK":
            write_decision(payload, decision)
            raise HTTPException(status_code=403, detail="Blocked by policy")

        event = write_decision(payload, decision)

        return {
            "status": "ok",
            "decision": decision,
            "chain_hash": event.chain_hash,
        }

    except HTTPException:
        raise
    except VerificationFailure as exc:
        log_execute_failure(exc, payload)
        raise HTTPException(status_code=403, detail="FAIL_CLOSED")
    except Exception as exc:
        log_execute_failure(exc, payload)
        raise HTTPException(status_code=500, detail="FAIL_CLOSED")
