from __future__ import annotations

import json
import os
import re
from pathlib import Path

from audit.anchor import (
    DEFAULT_PRIVATE_KEY_PATH as ANCHOR_DEFAULT_PRIVATE_KEY_PATH,
    DEFAULT_PUBLIC_KEY_PATH as ANCHOR_DEFAULT_PUBLIC_KEY_PATH,
    ensure_keypair,
    public_key_id,
)


DEFAULT_KEY_VERSION = "v1"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY_PATH = Path(os.getenv("USBAY_AUDIT_KEY_REGISTRY_PATH", "audit/key_registry.json"))
DEFAULT_PRIVATE_KEY_PATH = Path(os.getenv("USBAY_AUDIT_PRIVATE_KEY_PATH", str(ANCHOR_DEFAULT_PRIVATE_KEY_PATH)))
DEFAULT_PUBLIC_KEY_PATH = Path(os.getenv("USBAY_AUDIT_PUBLIC_KEY_PATH", str(ANCHOR_DEFAULT_PUBLIC_KEY_PATH)))
DEFAULT_PRIVATE_KEY_DIR = Path(os.getenv("USBAY_AUDIT_PRIVATE_KEY_DIR", "tmp/audit_keys"))
DEFAULT_PUBLIC_KEY_DIR = Path(os.getenv("USBAY_AUDIT_PUBLIC_KEY_DIR", "audit/public_keys"))
DEFAULT_REGISTRY_ROOT = Path(os.getenv("USBAY_AUDIT_KEY_REGISTRY_ROOT", str(REPO_ROOT)))
DEFAULT_PRIVATE_KEY_ROOT = Path(os.getenv("USBAY_AUDIT_PRIVATE_KEY_ROOT", str(Path.home() / ".usbay" / "audit"))).expanduser()
DEFAULT_PUBLIC_KEY_ROOT = Path(os.getenv("USBAY_AUDIT_PUBLIC_KEY_ROOT", str(REPO_ROOT)))
TRACKED_REGISTRY_PATH = Path(__file__).resolve().parents[1] / "audit" / "key_registry.json"
KEY_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class AuditKeyPathError(RuntimeError):
    pass


def _path_root(path: Path, explicit_root: Path, default_path: Path) -> Path:
    if path == default_path:
        if explicit_root == REPO_ROOT / "audit" and default_path.is_absolute() and not _is_relative_to(default_path, explicit_root):
            return default_path.parent
        return explicit_root
    return explicit_root


def _resolve_bounded_path(path: Path | str, *, root: Path, reason_code: str) -> Path:
    if not isinstance(path, (Path, str)):
        raise AuditKeyPathError(reason_code)
    candidate = Path(path)
    if not str(path) or candidate == Path("."):
        raise AuditKeyPathError(reason_code)
    try:
        root_resolved = root.resolve(strict=False)
        target = candidate if candidate.is_absolute() else root_resolved / candidate
        target_resolved = target.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuditKeyPathError(reason_code) from exc
    if not _is_relative_to(target_resolved, root_resolved):
        raise AuditKeyPathError(reason_code)
    return target_resolved


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _registry_path(registry_path: Path | None = None) -> Path:
    requested = registry_path or DEFAULT_REGISTRY_PATH
    return _resolve_bounded_path(
        requested,
        root=_path_root(requested, DEFAULT_REGISTRY_ROOT, DEFAULT_REGISTRY_PATH),
        reason_code="audit_key_registry_path_invalid",
    )


def _bounded_private_key_path(path: Path) -> Path:
    if DEFAULT_PRIVATE_KEY_ROOT.exists() and DEFAULT_PRIVATE_KEY_ROOT.is_symlink():
        raise AuditKeyPathError("audit_private_key_root_invalid")
    return _resolve_bounded_path(
        path,
        root=_path_root(path, DEFAULT_PRIVATE_KEY_ROOT, DEFAULT_PRIVATE_KEY_PATH),
        reason_code="audit_private_key_path_invalid",
    )


def _bounded_public_key_path(path: Path) -> Path:
    return _resolve_bounded_path(
        path,
        root=_path_root(path, DEFAULT_PUBLIC_KEY_ROOT, DEFAULT_PUBLIC_KEY_PATH),
        reason_code="audit_public_key_path_invalid",
    )


def _read_registry(registry_path: Path | None = None) -> dict:
    registry_path = _registry_path(registry_path)
    if not registry_path.exists():
        return {"keys": {}}
    return json.loads(registry_path.read_text(encoding="utf-8"))


def _write_registry(registry: dict, registry_path: Path | None = None) -> None:
    registry_path = _registry_path(registry_path)
    _assert_test_registry_isolated(registry_path)
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(
        json.dumps(registry, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _assert_test_registry_isolated(registry_path: Path) -> None:
    if not os.getenv("PYTEST_CURRENT_TEST"):
        return
    candidate = registry_path if registry_path.is_absolute() else Path.cwd() / registry_path
    if candidate.resolve() == TRACKED_REGISTRY_PATH:
        raise RuntimeError("tracked_key_registry_write_blocked")


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

    default_public_key_path = _bounded_public_key_path(DEFAULT_PUBLIC_KEY_PATH)
    if default_public_key_path.exists():
        public_key = default_public_key_path.read_text(encoding="utf-8")
        if public_key_id == globals()["public_key_id"](public_key):
            return public_key

    raise RuntimeError("unknown audit public key")


def key_paths_for_version(key_version: str) -> tuple[Path, Path]:
    if not isinstance(key_version, str) or key_version in {"", ".", ".."} or not KEY_VERSION_RE.fullmatch(key_version):
        raise AuditKeyPathError("audit_key_version_invalid")
    if key_version == DEFAULT_KEY_VERSION:
        return _bounded_private_key_path(DEFAULT_PRIVATE_KEY_PATH), _bounded_public_key_path(DEFAULT_PUBLIC_KEY_PATH)
    return (
        _bounded_private_key_path(DEFAULT_PRIVATE_KEY_DIR / f"audit_private_key_{key_version}.pem"),
        _bounded_public_key_path(DEFAULT_PUBLIC_KEY_DIR / f"public_key_{key_version}.pem"),
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
