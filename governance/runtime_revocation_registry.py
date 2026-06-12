from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "usbay.runtime_revocation_registry.v1"
REGISTRY_ACTIVE = "ACTIVE"
DECISION_DENY = "DENY"
DECISION_NEXT_CHECK = "NEXT_CHECK"
REASON_OK = "ok"
REASON_REGISTRY_UNAVAILABLE = "runtime_revocation_registry_unavailable"
REASON_REGISTRY_UNKNOWN_STATE = "runtime_revocation_registry_unknown_state"
REASON_RUNTIME_REVOKED = "runtime_id_revoked"
REASON_DEVICE_REVOKED = "device_id_revoked"
REASON_ATTESTATION_REVOKED = "attestation_id_revoked"
REASON_OPERATOR_REVOKED = "operator_id_revoked"


class RuntimeRevocationRegistryError(RuntimeError):
    pass


def _canonical(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _sha256(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _safe_set(registry: dict[str, Any], key: str) -> set[str]:
    values = registry.get(key)
    if not isinstance(values, list):
        raise RuntimeRevocationRegistryError(REASON_REGISTRY_UNAVAILABLE)
    return {str(value).strip() for value in values if str(value).strip()}


def load_runtime_revocation_registry(path: Path) -> dict[str, Any]:
    try:
        registry = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeRevocationRegistryError(REASON_REGISTRY_UNAVAILABLE) from exc
    if not isinstance(registry, dict):
        raise RuntimeRevocationRegistryError(REASON_REGISTRY_UNAVAILABLE)
    if registry.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeRevocationRegistryError(REASON_REGISTRY_UNAVAILABLE)
    state = str(registry.get("registry_state", "")).upper()
    if state != REGISTRY_ACTIVE:
        raise RuntimeRevocationRegistryError(REASON_REGISTRY_UNKNOWN_STATE)
    for key in ("revoked_runtime_ids", "revoked_device_ids", "revoked_attestation_ids", "revoked_operator_ids"):
        _safe_set(registry, key)
    return registry


def _audit_evidence(
    *,
    reason_code: str,
    registry_state: str,
    runtime_id: str,
    device_id: str,
    attestation_id: str,
    operator_id: str,
    timestamp: str,
) -> dict[str, Any]:
    evidence = {
        "schema_version": "usbay.runtime_revocation_decision.v1",
        "reason_code": reason_code,
        "registry_state": registry_state,
        "runtime_id_hash": _sha256(runtime_id) if runtime_id else "",
        "device_id_hash": _sha256(device_id) if device_id else "",
        "attestation_id_hash": _sha256(attestation_id) if attestation_id else "",
        "operator_id_hash": _sha256(operator_id) if operator_id else "",
        "timestamp": timestamp,
    }
    evidence["audit_hash"] = _sha256(_canonical(evidence))
    return evidence


def runtime_revocation_result(
    *,
    decision: str,
    reason_code: str,
    registry_state: str,
    runtime_id: str = "",
    device_id: str = "",
    attestation_id: str = "",
    operator_id: str = "",
    timestamp: str,
) -> dict[str, Any]:
    return {
        "decision": decision,
        "reason_code": reason_code,
        "audit_evidence": _audit_evidence(
            reason_code=reason_code,
            registry_state=registry_state,
            runtime_id=runtime_id,
            device_id=device_id,
            attestation_id=attestation_id,
            operator_id=operator_id,
            timestamp=timestamp,
        ),
    }


def evaluate_runtime_revocation(
    registry: dict[str, Any],
    *,
    runtime_id: str = "",
    device_id: str = "",
    attestation_id: str = "",
    operator_id: str = "",
    timestamp: str,
) -> dict[str, Any]:
    state = str(registry.get("registry_state", "")).upper()
    if state != REGISTRY_ACTIVE:
        return runtime_revocation_result(
            decision=DECISION_DENY,
            reason_code=REASON_REGISTRY_UNKNOWN_STATE,
            registry_state=state,
            runtime_id=runtime_id,
            device_id=device_id,
            attestation_id=attestation_id,
            operator_id=operator_id,
            timestamp=timestamp,
        )
    if runtime_id and runtime_id in _safe_set(registry, "revoked_runtime_ids"):
        reason = REASON_RUNTIME_REVOKED
    elif device_id and device_id in _safe_set(registry, "revoked_device_ids"):
        reason = REASON_DEVICE_REVOKED
    elif attestation_id and attestation_id in _safe_set(registry, "revoked_attestation_ids"):
        reason = REASON_ATTESTATION_REVOKED
    elif operator_id and operator_id in _safe_set(registry, "revoked_operator_ids"):
        reason = REASON_OPERATOR_REVOKED
    else:
        return runtime_revocation_result(
            decision=DECISION_NEXT_CHECK,
            reason_code=REASON_OK,
            registry_state=state,
            runtime_id=runtime_id,
            device_id=device_id,
            attestation_id=attestation_id,
            operator_id=operator_id,
            timestamp=timestamp,
        )
    return runtime_revocation_result(
        decision=DECISION_DENY,
        reason_code=reason,
        registry_state=state,
        runtime_id=runtime_id,
        device_id=device_id,
        attestation_id=attestation_id,
        operator_id=operator_id,
        timestamp=timestamp,
    )
