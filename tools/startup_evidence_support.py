"""Synthetic startup data and observations; no runtime validation is replaced."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from unittest.mock import patch


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True))


def synthetic_policy_inputs(directory: Path) -> dict:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from security import policy_registry as registry

    directory.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()  # Test-only in memory, never serialized.
    public = key.public_key()
    key_id = registry.policy_pubkey_id(public)
    now = datetime.now(timezone.utc)
    roles = {
        "policy_author": "synthetic-author-only",
        "policy_signer": "synthetic-signer-only",
        "deployment_operator": "synthetic-operator-only",
    }
    policy = {
        "version": "synthetic-startup-test", "critical_infrastructure": [],
        "last_updated": now.isoformat(), "authority": "human_policy_owner",
        "policy_pubkey_id": key_id, "policy_sequence": 1, **roles,
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(hours=1)).isoformat(),
    }
    paths = {
        "POLICY_REGISTRY_PATH": directory / "policy_registry.json",
        "POLICY_REGISTRY_SIGNATURE_PATH": directory / "policy_registry.sig",
        "POLICY_REGISTRY_PUBLIC_KEY_PATH": directory / "policy_public.pub",
        "POLICY_KEY_CONFIG_PATH": directory / "policy_key_config.json",
        "POLICY_RELEASE_MANIFEST_PATH": directory / "policy_release_manifest.json",
        "POLICY_AUTHORITY_PATH": directory / "policy_authority.json",
    }
    write_json(paths["POLICY_REGISTRY_PATH"], policy)
    paths["POLICY_REGISTRY_SIGNATURE_PATH"].write_text(registry.encode_policy_signature(policy, key))
    paths["POLICY_REGISTRY_PUBLIC_KEY_PATH"].write_bytes(public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    write_json(paths["POLICY_KEY_CONFIG_PATH"], {
        "active_keys": [key_id], "revoked_keys": [], "drift_window_seconds": 0,
        "key_map": {key_id: paths["POLICY_REGISTRY_PUBLIC_KEY_PATH"].name},
        "public_key_sha256": {key_id: registry.public_key_sha256(public)},
    })
    write_json(paths["POLICY_RELEASE_MANIFEST_PATH"], {
        "policy_version": policy["version"], "policy_hash": registry.policy_hash(policy),
        "policy_pubkey_id": key_id, "created_at": now.isoformat(),
        "signed_by_human": "synthetic-review-only",
        "artifact_hashes": {
            "policy_registry.json": registry.file_sha256(paths["POLICY_REGISTRY_PATH"]),
            "policy_registry.json.sig": registry.file_sha256(paths["POLICY_REGISTRY_SIGNATURE_PATH"]),
        },
    })
    write_json(paths["POLICY_AUTHORITY_PATH"], {
        **roles, "release_signer": "synthetic-review-only",
        "rotation_policy": {"max_age_days": 1, "overlap_period": 0},
        "dispute_resolution_required": True, "dispute_owner_role": "human_policy_authority",
    })
    return paths


@contextmanager
def configured_startup(directory: Path):
    """Only fixture paths/caches change; actual validators remain intact."""
    import gateway.app as gateway
    from security import policy_registry
    from security import runtime_artifact_authority

    paths = synthetic_policy_inputs(directory)
    with ExitStack() as stack:
        for name, value in paths.items():
            stack.enter_context(patch.object(gateway, name, value))
        stack.enter_context(patch.object(gateway, "_policy_registry_cache", None))
        stack.enter_context(patch.object(gateway, "_policy_registry_cache_key", None))
        stack.enter_context(patch.object(runtime_artifact_authority, "_runtime_authority", None))
        policy_registry.reset_policy_sequence_tracker()
        try:
            yield paths
        finally:
            policy_registry.reset_policy_sequence_tracker()


def observe_startup() -> list[str]:
    """Wrap, never bypass, each original validator and enter the real lifespan."""
    import asyncio
    import gateway.app as gateway

    trace = []
    names = (
        "validate_no_forbidden_runtime_files", "runtime_provenance_authority",
        "load_tenant_policy", "validate_replay_policy_startup",
        "validate_hydra_consensus_startup", "assert_startup_release_integrity",
        "validate_runtime_governance_health", "assert_ledger_valid", "load_policy_registry",
    )

    def wrapper(name, original):
        def observed(*args, **kwargs):
            trace.append(name + ":entered")
            result = original(*args, **kwargs)
            trace.append(name + ":passed")
            return result
        return observed

    async def enter():
        async with gateway.lifespan(gateway.app):
            trace.append("lifespan:yielded")
        trace.append("lifespan:exited")

    with ExitStack() as stack:
        for name in names:
            stack.enter_context(patch.object(gateway, name, wrapper(name, getattr(gateway, name))))
        asyncio.run(enter())
    return trace


def artifact_descriptor(root: Path) -> tuple[dict, bytes]:
    """Content-address files AND manifest, not a mutable path or claimed image."""
    from security.runtime_artifact_authority import MANIFEST_NAME
    from security.runtime_artifact_provenance import canonical_bytes

    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("synthetic_artifact_symlink_denied")
        if path.is_file():
            raw = path.read_bytes()
            entries.append({
                "path": path.relative_to(root).as_posix(),
                "mode": "100755" if path.stat().st_mode & 0o111 else "100644",
                "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            })
    if not any(entry["path"] == MANIFEST_NAME for entry in entries):
        raise RuntimeError("synthetic_artifact_manifest_missing")
    descriptor = {
        "schema": "usbay.synthetic_local_artifact_inventory.v1",
        "NON_PRODUCTION": True, "files": entries,
    }
    return descriptor, canonical_bytes(descriptor)
