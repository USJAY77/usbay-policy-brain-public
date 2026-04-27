from __future__ import annotations

import json
from pathlib import Path

from audit.anchor import (
    DEFAULT_PRIVATE_KEY_PATH,
    DEFAULT_PUBLIC_KEY_PATH,
    ensure_keypair,
    public_key_id,
)


DEFAULT_KEY_VERSION = "v1"
DEFAULT_REGISTRY_PATH = Path("audit/key_registry.json")
DEFAULT_PRIVATE_KEY_DIR = Path("tmp/audit_keys")
DEFAULT_PUBLIC_KEY_DIR = Path("audit/public_keys")


def _read_registry(registry_path: Path | None = None) -> dict:
    registry_path = registry_path or DEFAULT_REGISTRY_PATH
    if not registry_path.exists():
        return {"keys": {}}
    return json.loads(registry_path.read_text(encoding="utf-8"))


def _write_registry(registry: dict, registry_path: Path | None = None) -> None:
    registry_path = registry_path or DEFAULT_REGISTRY_PATH
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(
        json.dumps(registry, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def register_public_key(
    public_key: str,
    key_version: str,
    registry_path: Path | None = None,
) -> str:
    key_id = public_key_id(public_key)
    registry = _read_registry(registry_path)
    registry.setdefault("keys", {})[key_id] = {
        "key_version": key_version,
        "public_key": public_key,
    }
    _write_registry(registry, registry_path)
    return key_id


def resolve_public_key(public_key_id: str, registry_path: Path | None = None) -> str:
    registry = _read_registry(registry_path)
    key_entry = registry.get("keys", {}).get(public_key_id)
    if key_entry and key_entry.get("public_key"):
        return str(key_entry["public_key"])

    if DEFAULT_PUBLIC_KEY_PATH.exists():
        public_key = DEFAULT_PUBLIC_KEY_PATH.read_text(encoding="utf-8")
        if public_key_id == globals()["public_key_id"](public_key):
            return public_key

    raise RuntimeError("unknown audit public key")


def key_paths_for_version(key_version: str) -> tuple[Path, Path]:
    if key_version == DEFAULT_KEY_VERSION:
        return DEFAULT_PRIVATE_KEY_PATH, DEFAULT_PUBLIC_KEY_PATH
    return (
        DEFAULT_PRIVATE_KEY_DIR / f"audit_private_key_{key_version}.pem",
        DEFAULT_PUBLIC_KEY_DIR / f"public_key_{key_version}.pem",
    )


def get_signing_key(key_version: str = DEFAULT_KEY_VERSION) -> dict:
    private_key_path, public_key_path = key_paths_for_version(key_version)
    private_key, public_key = ensure_keypair(private_key_path, public_key_path)
    key_id = register_public_key(public_key, key_version)
    return {
        "private_key": private_key,
        "public_key": public_key,
        "public_key_id": key_id,
        "key_version": key_version,
    }
