from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


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
        if runtime_ok and parity_ok:
            reason_codes.append(STARTUP_VERIFIED)
        else:
            reason_codes.append(STARTUP_FAILED)

        reason_codes.append(AUDIT_DB_IGNORED)
        audit_state = "FRESH_INITIALIZED" if not audit_chain_entries else "APPEND_ONLY_EXISTING"
        ready = runtime_ok and parity_ok
        reason_codes.append(DEPLOYMENT_RUNTIME_READY if ready else DEPLOYMENT_RUNTIME_BLOCKED)

        payload = {
            "schema_version": SCHEMA_VERSION,
            "status": "READY" if ready else "BLOCKED",
            "startup_status": "VERIFIED" if runtime_ok and parity_ok else "FAILED",
            "startup_command_hash": sha256_text(str(policy.get("startup_command", ""))),
            "app_import": policy.get("app_import"),
            "port_binding": {
                "host": policy.get("host"),
                "port_source": "PORT_OR_DEFAULT",
                "default_port": policy.get("default_port"),
            },
            "dashboard_routes": policy.get("dashboard_routes", []),
            "health_routes": policy.get("health_routes", []),
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
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8", errors="replace")
    required_packages = tuple(str(package) for package in policy.get("required_source_packages", ()))
    forbidden_artifacts = tuple(str(pattern) for pattern in policy.get("forbidden_deployment_artifacts", ()))
    startup_command = str(policy.get("startup_command", ""))

    failures: list[str] = []
    if startup_command not in replit:
        failures.append("STARTUP_FAILED:replit_startup_command_mismatch")
    if "gateway.app:app" not in dockerfile or "${PORT:-8000}" not in dockerfile:
        failures.append("STARTUP_FAILED:docker_startup_command_mismatch")
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
