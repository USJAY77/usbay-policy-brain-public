from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from governance.runtime_governance_state import runtime_governance_state_snapshot


POLICY_PATH = Path("governance/deployment_runtime_policy.json")
SCHEMA_VERSION = "usbay.deployment_runtime_health.v1"
STARTUP_VERIFIED = "STARTUP_VERIFIED"
STARTUP_FAILED = "STARTUP_FAILED"
AUDIT_DB_IGNORED = "AUDIT_DB_IGNORED"
DEPLOYMENT_RUNTIME_READY = "DEPLOYMENT_RUNTIME_READY"
DEPLOYMENT_RUNTIME_BLOCKED = "DEPLOYMENT_RUNTIME_BLOCKED"
FORBIDDEN_DIAGNOSTIC_TERMS = (
    "PRIVATE " + "KEY",
    "approval_" + "contents",
    "raw_" + "payload",
    "secret",
    "token",
)


class DeploymentRuntimeHealthError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _replit_run_command(replit: str) -> str:
    lines = replit.splitlines()
    in_deployment = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_deployment = stripped == "[deployment]"
            continue
        if in_deployment and stripped.startswith("run = "):
            try:
                value = json.loads(stripped.removeprefix("run = ").strip())
            except json.JSONDecodeError:
                return ""
            if isinstance(value, list) and all(isinstance(item, str) for item in value):
                if len(value) == 3 and value[:2] == ["sh", "-c"]:
                    return f"sh -c '{value[2]}'"
                return " ".join(value)
            return value if isinstance(value, str) else ""
    return ""


def load_deployment_runtime_policy(root: Path) -> dict[str, Any]:
    policy_file = root / POLICY_PATH
    if not policy_file.is_file():
        raise DeploymentRuntimeHealthError("deployment_runtime_policy_missing")
    try:
        policy = json.loads(policy_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise DeploymentRuntimeHealthError("deployment_runtime_policy_malformed") from exc
    if not isinstance(policy, dict) or policy.get("schema_version") != "usbay.deployment_runtime_policy.v1":
        raise DeploymentRuntimeHealthError("deployment_runtime_policy_invalid")
    return policy


def _safe_payload(payload: dict[str, Any]) -> dict[str, Any]:
    text = canonical_json(payload)
    if any(term.lower() in text.lower() for term in FORBIDDEN_DIAGNOSTIC_TERMS):
        raise DeploymentRuntimeHealthError("deployment_runtime_diagnostics_unsafe")
    return payload


def deployment_runtime_health(
    *,
    root: Path,
    runtime_snapshot: dict[str, Any],
    runtime_governance_state: dict[str, Any] | None = None,
    audit_chain_entries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        policy = load_deployment_runtime_policy(root)
        runtime_ok = (
            runtime_snapshot.get("status") == "OK"
            and runtime_snapshot.get("mode") == "NORMAL"
            and runtime_snapshot.get("policy_signature_valid") is True
            and runtime_snapshot.get("replay_protection_active") is True
        )
        parity = runtime_snapshot.get("runtime_parity") if isinstance(runtime_snapshot.get("runtime_parity"), dict) else {}
        parity_ok = parity.get("runtime_parity_status") == "VERIFIED"
        governance_state = runtime_governance_state if isinstance(runtime_governance_state, dict) else None
        if governance_state is None and isinstance(runtime_snapshot.get("runtime_governance"), dict):
            governance_state = runtime_snapshot.get("runtime_governance")
        if governance_state is None:
            governance_state = runtime_governance_state_snapshot(root=root)
        if not isinstance(governance_state, dict):
            governance_state = {}
        governance_ready = (
            governance_state.get("status") == "READY"
            and governance_state.get("promote_state") == "PROMOTE_READY"
            and governance_state.get("fail_closed") is False
        )
        if runtime_ok and parity_ok and governance_ready:
            reason_codes.append(STARTUP_VERIFIED)
        else:
            reason_codes.append(STARTUP_FAILED)
        if governance_ready:
            reason_codes.append("RUNTIME_GOVERNANCE_READY")
        else:
            reason_codes.append("RUNTIME_GOVERNANCE_BLOCKED")

        reason_codes.append(AUDIT_DB_IGNORED)
        audit_state = "FRESH_INITIALIZED" if not audit_chain_entries else "APPEND_ONLY_EXISTING"
        ready = runtime_ok and parity_ok and governance_ready
        reason_codes.append(DEPLOYMENT_RUNTIME_READY if ready else DEPLOYMENT_RUNTIME_BLOCKED)

        payload = {
            "schema_version": SCHEMA_VERSION,
            "status": "READY" if ready else "BLOCKED",
            "startup_status": "VERIFIED" if runtime_ok and parity_ok else "FAILED",
            "startup_command_hash": sha256_text(str(policy.get("startup_command", ""))),
            "app_import": policy.get("app_import"),
            "port_binding": {
                "host": policy.get("host"),
                "port_source": policy.get("port_env_var"),
                "port_required": policy.get("port_required") is True,
            },
            "dashboard_routes": policy.get("dashboard_routes", []),
            "health_routes": policy.get("health_routes", []),
            "runtime_governance": governance_state,
            "audit_db_handling": {
                "status": "IGNORED",
                "state": audit_state,
                "forbidden_artifact_patterns_hash": sha256_text(
                    canonical_json(policy.get("forbidden_deployment_artifacts", []))
                ),
            },
            "reason_codes": reason_codes,
        }
        payload["health_evidence_hash"] = sha256_text(canonical_json(payload))
        return _safe_payload(payload)
    except DeploymentRuntimeHealthError:
        raise
    except Exception as exc:
        raise DeploymentRuntimeHealthError("deployment_runtime_health_failed") from exc


def validate_deployment_packaging(root: Path) -> dict[str, Any]:
    policy = load_deployment_runtime_policy(root)
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8", errors="replace")
    replit = (root / ".replit").read_text(encoding="utf-8", errors="replace")
    replit_run_command = _replit_run_command(replit)
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8", errors="replace")
    required_packages = tuple(str(package) for package in policy.get("required_source_packages", ()))
    forbidden_artifacts = tuple(str(pattern) for pattern in policy.get("forbidden_deployment_artifacts", ()))
    startup_command = str(policy.get("startup_command", ""))
    port_env_var = str(policy.get("port_env_var", ""))
    top_level_run_count = 0
    for line in replit.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            break
        if stripped.startswith("run = "):
            top_level_run_count += 1
    deployment_run_count = sum(
        1
        for index, line in enumerate(replit.splitlines())
        if line.strip().startswith("run = ")
        and any(previous.strip() == "[deployment]" for previous in replit.splitlines()[:index])
    )

    failures: list[str] = []
    if replit_run_command != startup_command:
        failures.append("STARTUP_FAILED:replit_startup_command_mismatch")
    if top_level_run_count:
        failures.append("STARTUP_FAILED:top_level_run_command_configured")
    if deployment_run_count != 1:
        failures.append("STARTUP_FAILED:deployment_run_command_count_invalid")
    if f'deploymentTarget = "{policy.get("deployment_target")}"' not in replit:
        failures.append("STARTUP_FAILED:deployment_target_mismatch")
    if "gateway.app:app" not in dockerfile or f'--port \\"${port_env_var}\\"' not in dockerfile:
        failures.append("STARTUP_FAILED:docker_startup_command_mismatch")
    if "${PORT:-" in replit or "${PORT:-" in dockerfile or "${PORT:-" in startup_command:
        failures.append("STARTUP_FAILED:default_port_fallback_configured")
    if policy.get("default_port"):
        failures.append("STARTUP_FAILED:default_port_policy_configured")
    if "EXPOSE 8000" in dockerfile or "--port 8000" in dockerfile or ":24185" in dockerfile or "24185" in replit:
        failures.append("STARTUP_FAILED:hardcoded_port_configured")
    if "127.0.0.1" in startup_command or "localhost" in startup_command:
        failures.append("STARTUP_FAILED:localhost_secondary_bind_configured")
    if startup_command.count("uvicorn") != 1 or dockerfile.count("uvicorn") != 1 or replit.count("uvicorn") != 1:
        failures.append("STARTUP_FAILED:duplicate_uvicorn_startup_configured")
    if policy.get("single_port_gateway_only") is not True or policy.get("port_required") is not True:
        failures.append("STARTUP_FAILED:single_port_gateway_policy_missing")
    for package in required_packages:
        if f"COPY {package} ./{package}" not in dockerfile:
            failures.append(f"STARTUP_FAILED:docker_package_missing:{package}")
    if any(line.strip() in {"runtime/", "runtime/*"} for line in dockerignore.splitlines()):
        failures.append("STARTUP_FAILED:runtime_source_excluded")
    for pattern in forbidden_artifacts:
        if pattern not in dockerignore:
            failures.append(f"STARTUP_FAILED:forbidden_artifact_not_ignored:{pattern}")
    if "COPY tmp" in dockerfile or ".db" in dockerfile or "usbay_audit.db" in dockerfile:
        failures.append("STARTUP_FAILED:local_audit_db_copied")

    ready = not failures
    reason_codes = [STARTUP_VERIFIED if ready else STARTUP_FAILED, AUDIT_DB_IGNORED]
    reason_codes.append(DEPLOYMENT_RUNTIME_READY if ready else DEPLOYMENT_RUNTIME_BLOCKED)
    payload = {
        "schema_version": "usbay.deployment_packaging_health.v1",
        "status": "READY" if ready else "BLOCKED",
        "startup_command_hash": sha256_text(startup_command),
        "required_source_package_count": len(required_packages),
        "forbidden_artifact_patterns_hash": sha256_text(canonical_json(forbidden_artifacts)),
        "failures": failures,
        "reason_codes": reason_codes,
    }
    payload["packaging_evidence_hash"] = sha256_text(canonical_json(payload))
    return _safe_payload(payload)
