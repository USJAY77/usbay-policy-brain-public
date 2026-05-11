from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


DEFAULT_NODE_ATTESTATION_POLICY_PATH = Path("governance/node_attestation_policy.json")


class NodeIdentityError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def public_identity_hash(public_identity: dict[str, Any]) -> str:
    if not isinstance(public_identity, dict) or not public_identity:
        raise NodeIdentityError("invalid_public_identity")
    forbidden = {"raw_device_id", "device_serial", "private" + "_" + "key", "secret"}
    if any(key in public_identity for key in forbidden):
        raise NodeIdentityError("forbidden_identity_material")
    return sha256_text(canonical_json(public_identity))


def generate_node_id(public_identity: dict[str, Any]) -> str:
    return f"usbay-node-{public_identity_hash(public_identity)[:16]}"


def default_public_identity(logical_node_id: str) -> dict[str, str]:
    return {
        "vendor": "USBAY",
        "node_label": str(logical_node_id),
        "public_key_id": f"usbay-{str(logical_node_id).replace('_', '-')}",
    }


def load_node_attestation_policy(path: Path | str = DEFAULT_NODE_ATTESTATION_POLICY_PATH) -> dict[str, Any]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise NodeIdentityError("invalid_node_attestation_policy:unreadable") from exc
    if not isinstance(raw, dict):
        raise NodeIdentityError("invalid_node_attestation_policy:root")
    mode = str(raw.get("required_attestation_mode", ""))
    if mode not in {"mock_local", "tpm2", "secure_enclave", "external_attestation_service"}:
        raise NodeIdentityError("invalid_node_attestation_policy:required_attestation_mode")
    allowed_roles = raw.get("allowed_node_roles")
    if not isinstance(allowed_roles, list) or not all(isinstance(role, str) and role for role in allowed_roles):
        raise NodeIdentityError("invalid_node_attestation_policy:allowed_node_roles")
    try:
        ttl = int(raw.get("attestation_ttl_seconds"))
    except Exception as exc:
        raise NodeIdentityError("invalid_node_attestation_policy:attestation_ttl_seconds") from exc
    if ttl <= 0:
        raise NodeIdentityError("invalid_node_attestation_policy:attestation_ttl_seconds")
    if not isinstance(raw.get("require_hardware_backing"), bool):
        raise NodeIdentityError("invalid_node_attestation_policy:require_hardware_backing")
    if not isinstance(raw.get("production_rejects_mock"), bool):
        raise NodeIdentityError("invalid_node_attestation_policy:production_rejects_mock")
    enrolled = raw.get("enrolled_nodes")
    if not isinstance(enrolled, dict) or not enrolled:
        raise NodeIdentityError("invalid_node_attestation_policy:enrolled_nodes")
    normalized_nodes = {}
    for logical_node_id, entry in enrolled.items():
        if not isinstance(entry, dict):
            raise NodeIdentityError("invalid_node_attestation_policy:enrolled_node")
        role = str(entry.get("role", ""))
        if role not in allowed_roles:
            raise NodeIdentityError("invalid_node_attestation_policy:enrolled_role")
        public_identity = entry.get("public_identity")
        if not isinstance(public_identity, dict):
            raise NodeIdentityError("invalid_node_attestation_policy:public_identity")
        normalized_nodes[str(logical_node_id)] = {
            "role": role,
            "public_identity": public_identity,
            "public_identity_hash": public_identity_hash(public_identity),
            "node_id": generate_node_id(public_identity),
        }
    return {
        "required_attestation_mode": mode,
        "allowed_node_roles": list(allowed_roles),
        "attestation_ttl_seconds": ttl,
        "require_hardware_backing": bool(raw["require_hardware_backing"]),
        "production_rejects_mock": bool(raw["production_rejects_mock"]),
        "enrolled_nodes": normalized_nodes,
    }
