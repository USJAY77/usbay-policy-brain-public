#!/usr/bin/env python3
"""
USBAY runtime filesystem and integrity guards.
"""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RUNTIME_ROOT = ROOT / "runtime"
AUDIT_ROOT = ROOT / "audit"
AUDIT_LOG_ROOT = AUDIT_ROOT / "logs"
EVIDENCE_ROOT = ROOT / "evidence"
ALLOWED_WRITE_ROOTS = (AUDIT_ROOT, EVIDENCE_ROOT)
ALLOWED_EXECUTION_ROOTS = (RUNTIME_ROOT, AUDIT_ROOT)
FORBIDDEN_WRITE_SUFFIXES = (".pem",)
FORBIDDEN_WRITE_TOKENS = ("_key", "private_key")
ALLOWED_EXECUTION_RELATIVE_PATHS = {
    "runtime/enforcement_gateway.py",
    "runtime/replit_executor.py",
}


def _resolve_path(path: Path) -> Path:
    candidate = path if path.is_absolute() else (ROOT / path)
    return candidate.expanduser().resolve(strict=False)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def guard_runtime_write_path(path: Path) -> Path:
    resolved = _resolve_path(path)
    name = resolved.name.lower()
    if name.endswith(FORBIDDEN_WRITE_SUFFIXES) or any(token in name for token in FORBIDDEN_WRITE_TOKENS):
        raise RuntimeError(f"KEY_WRITE_BLOCKED: {resolved}")
    if not any(_is_within(resolved, root) for root in ALLOWED_WRITE_ROOTS):
        raise RuntimeError(f"EXTERNAL_PATH_ACCESS_DENIED: {resolved}")
    return resolved


def guard_runtime_write_dir(path: Path) -> Path:
    resolved = _resolve_path(path)
    if not any(_is_within(resolved, root) for root in ALLOWED_WRITE_ROOTS):
        raise RuntimeError(f"EXTERNAL_PATH_ACCESS_DENIED: {resolved}")
    return resolved


def write_guarded_bytes(path: Path, payload: bytes) -> Path:
    resolved = guard_runtime_write_path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_bytes(payload)
    return resolved


def write_guarded_text(path: Path, payload: str) -> Path:
    resolved = guard_runtime_write_path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(payload, encoding="utf-8")
    return resolved


def guard_execution_path(raw_path: str) -> Path:
    resolved = _resolve_path(Path(raw_path))
    if not any(_is_within(resolved, root) for root in ALLOWED_EXECUTION_ROOTS):
        raise RuntimeError(f"EXTERNAL_PATH_ACCESS_DENIED: {resolved}")
    return resolved


def guard_command_spec(command: dict) -> dict:
    entrypoint = str(command.get("entrypoint", "")).strip()
    if not entrypoint:
        raise RuntimeError("command entrypoint is required")
    guarded_entrypoint = guard_execution_path(entrypoint)
    relative_entrypoint = str(guarded_entrypoint.relative_to(ROOT))
    if relative_entrypoint not in ALLOWED_EXECUTION_RELATIVE_PATHS:
        raise RuntimeError(f"EXECUTION_PATH_BLOCKED: {guarded_entrypoint}")
    args = command.get("args", [])
    if not isinstance(args, list) or any(not isinstance(value, str) for value in args):
        raise RuntimeError("command args must be an array of strings")
    guarded_args: list[str] = []
    for value in args:
        candidate = str(value).strip()
        if candidate.startswith("/") or candidate.startswith(".") or "/" in candidate or ".." in candidate:
            guard_execution_path(candidate)
        guarded_args.append(candidate)
    return {
        "entrypoint": str(guarded_entrypoint),
        "args": guarded_args,
    }
