from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import time
import uuid
from pathlib import Path
from urllib import error, request

from audit.immutable_ledger import append_evidence_event
from security.request_signing import sign_request_payload
from security.tenant_context import tenant_hash


DEFAULT_GATEWAY_URL = "http://127.0.0.1:8000/execute"
DEFAULT_TENANT_ID = "t1"
DEFAULT_DEVICE = "laptop-1"
DEFAULT_POLICY_VERSION = "local-policy-v1"
DEFAULT_EXECUTION_EVIDENCE_PATH = Path("/tmp/usbay-execution-governance/evidence.jsonl")
SAFE_COMMAND_PREFIXES = (
    ("python3", "-m", "py_compile"),
    ("python", "-m", "py_compile"),
)
NETWORK_COMMANDS = {
    "curl",
    "wget",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "nc",
    "netcat",
    "telnet",
}
NETWORK_GIT_ACTIONS = {"clone", "fetch", "pull", "push", "remote"}
CHAIN_TOKENS = {"&&", "||", ";", "|", "&"}
SHELL_CHAIN_COMMANDS = {"bash", "sh", "zsh", "fish"}
APPROVAL_REQUIRED_REASONS = {
    "rm_rf",
    "network_access",
    "unsandboxed_execution",
    "subprocess_chain",
    "sandbox_escalation",
}
EXECUTION_TIERS = {"T0", "T1", "T2", "T3"}


class ExecutionGovernanceError(RuntimeError):
    pass


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


def _safe_metadata(metadata: dict) -> dict:
    safe = {}
    for key in ("actor_id", "user_id", "tenant_id", "device", "policy_version", "execution_location"):
        if metadata.get(key) not in (None, ""):
            safe[key] = str(metadata[key])
    return safe


def _explicit_approval_present(metadata: dict) -> bool:
    approval = metadata.get("execution_governance_approval") or metadata.get("approval")
    if approval is True:
        return True
    if isinstance(approval, dict):
        return (
            approval.get("approved") is True
            and bool(str(approval.get("approved_by", "")).strip())
            and bool(str(approval.get("reason", "")).strip())
        )
    return False


def _has_rm_rf(parts: list[str]) -> bool:
    for index, part in enumerate(parts):
        if part == "rm":
            for candidate in parts[index + 1:]:
                if candidate.startswith("-") and "r" in candidate and "f" in candidate:
                    return True
    return False


def _has_chain_tokens(command: str, parts: list[str]) -> bool:
    if any(token in command for token in ("&&", "||", ";", "|")):
        return True
    if parts and Path(parts[0]).name in SHELL_CHAIN_COMMANDS and any(part in {"-c", "-lc"} for part in parts[1:3]):
        return True
    return any(part in CHAIN_TOKENS for part in parts)


def _has_network_access(parts: list[str]) -> bool:
    if not parts:
        return False
    executable = Path(parts[0]).name
    if executable in NETWORK_COMMANDS:
        return True
    if executable == "git" and len(parts) > 1 and parts[1] in NETWORK_GIT_ACTIONS:
        return True
    return False


def _is_safe_command(parts: list[str]) -> bool:
    return any(tuple(parts[: len(prefix)]) == prefix for prefix in SAFE_COMMAND_PREFIXES)


def classify_execution_tier(cmd: str) -> dict:
    try:
        parts = shlex.split(str(cmd))
    except ValueError as exc:
        raise ExecutionGovernanceError("command_parse_failed") from exc
    if not parts:
        raise ExecutionGovernanceError("execution_tier_unknown")
    executable = Path(parts[0]).name
    if executable in {"python", "python3"} and len(parts) >= 3 and parts[1:3] == ["-m", "py_compile"]:
        return {"execution_tier": "T1", "tier_name": "compile_lint", "tier_risk": "low"}
    if executable in {"python", "python3"} and len(parts) >= 3 and parts[1:3] == ["-m", "pytest"]:
        return {"execution_tier": "T2", "tier_name": "sandboxed_tests", "tier_risk": "medium"}
    if executable in {"pytest", "ruff", "mypy"}:
        return {"execution_tier": "T2", "tier_name": "sandboxed_tests", "tier_risk": "medium"}
    if executable in {"python", "python3"} and any(part in {"-c", "-"} for part in parts[1:2]):
        return {"execution_tier": "T3", "tier_name": "approved_runtime_execution", "tier_risk": "high"}
    if executable == "rm" or executable in NETWORK_COMMANDS or executable in SHELL_CHAIN_COMMANDS:
        return {"execution_tier": "T3", "tier_name": "approved_runtime_execution", "tier_risk": "high"}
    if executable == "git" and len(parts) > 1 and parts[1] in NETWORK_GIT_ACTIONS:
        return {"execution_tier": "T3", "tier_name": "approved_runtime_execution", "tier_risk": "high"}
    if _is_safe_command(parts):
        return {"execution_tier": "T1", "tier_name": "compile_lint", "tier_risk": "low"}
    raise ExecutionGovernanceError("execution_tier_unknown")


def classify_command(cmd: str, metadata: dict | None = None) -> dict:
    metadata = metadata or {}
    if metadata.get("policy_engine_unavailable") is True:
        raise ExecutionGovernanceError("policy_engine_unavailable")
    try:
        parts = shlex.split(str(cmd))
    except ValueError as exc:
        raise ExecutionGovernanceError("command_parse_failed") from exc
    if not parts:
        raise ExecutionGovernanceError("command_empty")
    tier = classify_execution_tier(cmd)
    reasons: list[str] = []
    if _has_rm_rf(parts):
        reasons.append("rm_rf")
    if _has_network_access(parts):
        reasons.append("network_access")
    if metadata.get("sandboxed") is False or str(metadata.get("sandbox_mode", "")).lower() in {"unsandboxed", "none", "host"}:
        reasons.append("unsandboxed_execution")
    if _has_chain_tokens(str(cmd), parts):
        reasons.append("subprocess_chain")
    if reasons:
        return {
            "risk_level": "high",
            "classification": "approval_required",
            "reasons": sorted(set(reasons)),
            "command_hash": command_hash(str(cmd)),
            **tier,
        }
    if _is_safe_command(parts):
        return {
            "risk_level": "low",
            "classification": "allowable",
            "reasons": ["safe_prefix"],
            "command_hash": command_hash(str(cmd)),
            **tier,
        }
    return {
        "risk_level": "unknown",
        "classification": "unknown",
        "reasons": ["unknown_classification"],
        "command_hash": command_hash(str(cmd)),
        **tier,
    }


def _execution_evidence_path(metadata: dict) -> Path:
    return Path(metadata.get("execution_evidence_path") or os.getenv("USBAY_EXECUTION_EVIDENCE_PATH", str(DEFAULT_EXECUTION_EVIDENCE_PATH)))


def _audit_execution_policy_event(cmd: str, metadata: dict, policy: dict, decision: str, reason: str) -> dict:
    tenant_id = str(metadata.get("tenant_id", DEFAULT_TENANT_ID))
    event = {
        "node_id": "local-command-governance",
        "tenant_id": tenant_id,
        "tenant_hash": tenant_hash(tenant_id),
        "policy_hash": str(metadata.get("policy_hash", "local-execution-governance-v1")),
        "consensus_result": decision.upper(),
        "command_hash": command_hash(str(cmd)),
        "risk_level": policy.get("risk_level", "unknown"),
        "classification": policy.get("classification", "unknown"),
        "reasons": policy.get("reasons", []),
        "decision": decision.upper(),
        "reason": reason,
        "actor": str(metadata.get("actor_id", metadata.get("user_id", "execution-actor"))),
        "device": str(metadata.get("device", DEFAULT_DEVICE)),
        "policy_version": str(metadata.get("policy_version", DEFAULT_POLICY_VERSION)),
        "metadata": _safe_metadata(metadata),
    }
    return append_evidence_event(_execution_evidence_path(metadata), action="local_execution_governance", decision=event)


def enforce_local_execution_policy(cmd: str, metadata: dict) -> dict:
    try:
        policy = classify_command(cmd, metadata)
    except Exception as exc:
        policy = {
            "risk_level": "unknown",
            "classification": "policy_unavailable",
            "reasons": [str(exc) or "policy_engine_unavailable"],
            "command_hash": command_hash(str(cmd)),
        }
        try:
            _audit_execution_policy_event(cmd, metadata, policy, "DENY", "policy_engine_unavailable")
        except Exception:
            pass
        return {"allowed": False, "reason": "policy_engine_unavailable", "policy": policy}

    classification = str(policy.get("classification", "unknown"))
    reasons = set(policy.get("reasons", []))
    if classification == "unknown":
        decision = {"allowed": False, "reason": "unknown_classification", "policy": policy}
    elif reasons.intersection(APPROVAL_REQUIRED_REASONS) and not _explicit_approval_present(metadata):
        decision = {"allowed": False, "reason": "explicit_approval_required", "policy": policy}
    else:
        decision = {"allowed": True, "reason": "policy_allowed", "policy": policy}

    try:
        block = _audit_execution_policy_event(
            cmd,
            metadata,
            policy,
            "ALLOW" if decision["allowed"] else "DENY",
            str(decision["reason"]),
        )
    except Exception as exc:
        return {"allowed": False, "reason": "execution_evidence_unavailable", "policy": policy, "detail": str(exc)}
    decision["audit_event_hash"] = block["current_event_hash"]
    decision["audit_event_id"] = block["event_id"]
    return decision


def build_escalation_request(cmd: str, sandbox_failure_reason: str, metadata: dict | None = None) -> dict:
    metadata = metadata or {}
    try:
        policy = classify_command(cmd, {**metadata, "sandboxed": False})
    except Exception as exc:
        policy = {
            "risk_level": "unknown",
            "classification": "unknown",
            "reasons": [str(exc) or "execution_tier_unknown"],
            "execution_tier": "UNKNOWN",
            "command_hash": command_hash(str(cmd)),
        }
    reasons = sorted(set(policy.get("reasons", [])) | {"sandbox_escalation"})
    return {
        "type": "sandbox_escalation_request",
        "command_hash": command_hash(str(cmd)),
        "risk_level": "high" if policy.get("risk_level") != "unknown" else "unknown",
        "classification": "approval_required" if policy.get("risk_level") != "unknown" else "unknown",
        "sandbox_failure_reason": str(sandbox_failure_reason),
        "execution_tier": policy.get("execution_tier", "UNKNOWN"),
        "reasons": reasons,
        "requires_policy_approval": True,
    }


def govern_escalation_request(request_payload: dict, metadata: dict | None = None) -> dict:
    metadata = metadata or {}
    attempts = int(metadata.get("escalation_attempts", request_payload.get("escalation_attempts", 0)) or 0)
    if attempts > 0:
        return {"allowed": False, "reason": "repeated_escalation_loop_denied"}
    if request_payload.get("type") != "sandbox_escalation_request":
        return {"allowed": False, "reason": "unknown_escalation_request"}
    if request_payload.get("classification") == "unknown" or request_payload.get("execution_tier") not in EXECUTION_TIERS:
        return {"allowed": False, "reason": "unknown_escalation_classification"}
    if request_payload.get("requires_policy_approval") is not True:
        return {"allowed": False, "reason": "missing_policy_approval_requirement"}
    if not _explicit_approval_present(metadata):
        return {"allowed": False, "reason": "policy_approval_required"}
    return {
        "allowed": True,
        "reason": "policy_approved",
        "risk_level": request_payload["risk_level"],
        "execution_tier": request_payload["execution_tier"],
    }


def handle_sandbox_tool_rejection(cmd: str, tool_failure_output: str, metadata: dict | None = None) -> dict:
    metadata = metadata or {}
    try:
        tier = classify_execution_tier(cmd)
    except Exception:
        tier = {"execution_tier": "UNKNOWN", "tier_name": "unknown", "tier_risk": "unknown"}
    source = "Codex exec_command tool harness: CreateProcess rejection before Python starts"
    if tier.get("execution_tier") == "T1":
        return {
            "allowed": False,
            "reason": "t1_compile_lint_no_unsandboxed_escalation",
            "execution_tier": "T1",
            "sandbox_failure_source": source,
            "sandbox_failure_reason": str(tool_failure_output),
            "escalation_request_created": False,
        }
    request_payload = build_escalation_request(cmd, tool_failure_output, metadata)
    decision = govern_escalation_request(request_payload, metadata)
    decision["sandbox_failure_source"] = source
    decision["escalation_request_created"] = True
    return decision


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
        local_policy = enforce_local_execution_policy(cmd, metadata)
        if local_policy.get("allowed") is not True:
            return {
                "error": "execution_denied",
                "reason": local_policy.get("reason", "local_execution_policy_denied"),
                "command_hash": command_hash(cmd),
            }
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
