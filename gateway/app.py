from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pathlib import Path
from typing import Any
import hashlib
import hmac
import json

from audit.decision_logger import write_audit_event

app = FastAPI()

POLICY_PATH = Path("policy/policy.json")
SIG_PATH = Path("policy/policy.sig")
KEY_PATH = Path("secrets/policy.key")
MIN_POLICY_VERSION_PATH = Path("policy/min_policy_version.txt")
POLICY_VERSION = "v1"
AUDIT_LOG_PATH = Path("audit/audit_log.jsonl")


class CommandRequest(BaseModel):
    action: str
    user_id: str
    device: str


# =========================
# VALIDATION
# =========================

def _canonical_policy_bytes(policy: Any) -> bytes:
    return json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_policy_version(value: str) -> int:
    if not isinstance(value, str) or not value.startswith("v"):
        raise RuntimeError("FAIL_CLOSED")

    try:
        return int(value[1:])
    except ValueError as exc:
        raise RuntimeError("FAIL_CLOSED") from exc


def _validate_policy_version(policy: dict[str, Any]) -> None:
    policy_version = policy.get("policy_version")
    if not isinstance(policy_version, str):
        raise RuntimeError("FAIL_CLOSED")

    if policy_version != POLICY_VERSION:
        raise RuntimeError("FAIL_CLOSED")

    try:
        minimum_version = MIN_POLICY_VERSION_PATH.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError("FAIL_CLOSED") from exc

    if _parse_policy_version(policy_version) < _parse_policy_version(minimum_version):
        raise RuntimeError("FAIL_CLOSED")


def _validate_policy(policy: Any) -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise RuntimeError("FAIL_CLOSED")

    _validate_policy_version(policy)

    rules = policy.get("rules")

    if not isinstance(rules, list):
        raise RuntimeError("FAIL_CLOSED")

    for rule in rules:
        if not isinstance(rule, dict):
            raise RuntimeError("FAIL_CLOSED")

        if not isinstance(rule.get("action"), str):
            raise RuntimeError("FAIL_CLOSED")

        if rule.get("effect") not in {"ALLOW", "BLOCK"}:
            raise RuntimeError("FAIL_CLOSED")

    return {"policy_version": policy["policy_version"], "rules": rules}


def verify_policy() -> None:
    if not POLICY_PATH.exists() or not SIG_PATH.exists() or not KEY_PATH.exists():
        raise RuntimeError("FAIL_CLOSED")

    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        policy_bytes = _canonical_policy_bytes(policy)
        key = KEY_PATH.read_bytes().strip()
        expected = SIG_PATH.read_text(encoding="utf-8").strip()
    except Exception as exc:
        raise RuntimeError("FAIL_CLOSED") from exc

    digest = hashlib.sha256(policy_bytes).digest()
    actual = hmac.new(key, digest, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(actual, expected):
        raise RuntimeError("FAIL_CLOSED")


def load_policy() -> dict[str, Any]:
    verify_policy()

    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except Exception:
        raise RuntimeError("FAIL_CLOSED")

    return _validate_policy(policy)


# =========================
# ENGINE
# =========================

def evaluate_policy(payload: dict[str, Any]) -> str:
    policy = load_policy()
    action = payload.get("action")

    for rule in policy["rules"]:
        if rule["action"] in {action, "*"}:
            return rule["effect"]

    return "BLOCK"


def validate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if not payload.get("action") or not payload.get("user_id") or not payload.get("device"):
        raise RuntimeError("FAIL_CLOSED")

    return payload


# =========================
# ENDPOINT
# =========================

@app.exception_handler(RuntimeError)
def fail_closed_runtime_error_handler(request: Request, exc: RuntimeError):
    return JSONResponse(status_code=500, content={"detail": "FAIL_CLOSED"})


@app.post("/execute")
def execute(cmd: CommandRequest):
    try:
        payload = validate_payload(cmd.model_dump())
        decision = evaluate_policy(payload)

        event = write_audit_event(
            event_type="policy_decision",
            actor=payload["user_id"],
            decision=decision,
            policy_version=POLICY_VERSION,
            execution_origin="gateway",
            workspace="api",
            input_payload=payload,
            log_path=AUDIT_LOG_PATH,
        )

        if decision == "BLOCK":
            raise HTTPException(status_code=403, detail="Blocked by policy")

        return {
            "status": "ok",
            "decision": decision,
            "chain_hash": event.chain_hash,
        }

    except HTTPException:
        raise

    except RuntimeError:
        # CRUCIAAL: geen audit, pure fail-closed
        raise HTTPException(status_code=500, detail="FAIL_CLOSED")

    except Exception:
        raise HTTPException(status_code=500, detail="FAIL_CLOSED")
