from __future__ import annotations

import hashlib
import json
import shlex
from enum import Enum
from typing import Any


TERMINAL_GOVERNANCE_VERSION = "pb256-260-terminal-governance-v1"
DEFAULT_POLICY_HASH = "88d1aaa62bbe011c9f51d7f159a7526a2fe283b94314e8c9b9cce73b199f04d1"


class CommandClass(str, Enum):
    READ_ONLY_STATUS = "READ_ONLY_STATUS"
    READ_ONLY_DIFF = "READ_ONLY_DIFF"
    READ_ONLY_TEST = "READ_ONLY_TEST"
    READ_ONLY_VALIDATION = "READ_ONLY_VALIDATION"
    PROPOSE_CORRECTION = "PROPOSE_CORRECTION"


class CommandRisk(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


ALLOWED_COMMAND_CLASSES = tuple(item.value for item in CommandClass)
BLOCKED_COMMAND_CLASSES = ("WRITE", "MERGE", "PUSH", "DELETE", "INSTALL", "NETWORK", "SECRET_READING")
SAFE_EXACT_COMMANDS = {
    ("git", "status"): CommandClass.READ_ONLY_STATUS,
    ("git", "diff", "--check"): CommandClass.READ_ONLY_DIFF,
    ("git", "diff", "--name-only"): CommandClass.READ_ONLY_DIFF,
}
SHELL_INJECTION_MARKERS = (";", "&&", "||", "|", "`", "$(", ">", "<")
SENSITIVE_PATH_MARKERS = (".env", "secret", "secrets", "token", "tokens", "password", "private_key", "credential", "credentials", ".pem", ".key")


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_json(data: Any) -> str:
    return sha256_text(canonical_json(data))


def terminal_capability_registry_json() -> dict[str, Any]:
    return {
        "contract_version": TERMINAL_GOVERNANCE_VERSION,
        "allowed_command_classes": list(ALLOWED_COMMAND_CLASSES),
        "blocked_command_classes": list(BLOCKED_COMMAND_CLASSES),
        "write_commands_default": "BLOCKED",
        "merge_commands_default": "BLOCKED",
        "push_commands_default": "BLOCKED",
        "delete_commands_default": "BLOCKED",
        "install_commands_default": "BLOCKED",
        "network_commands_default": "BLOCKED",
        "secret_reading_commands_default": "BLOCKED",
        "external_api_calls_allowed": False,
        "sensitive_output_storage_allowed": False,
    }


def _has_sensitive_path(parts: tuple[str, ...]) -> bool:
    normalized = " ".join(parts).lower()
    return any(marker in normalized for marker in SENSITIVE_PATH_MARKERS)


def _has_shell_injection(command: str | list[str] | tuple[str, ...]) -> bool:
    text = command if isinstance(command, str) else " ".join(command)
    return any(marker in text for marker in SHELL_INJECTION_MARKERS)


def normalize_command(command: str | list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if isinstance(command, str):
        return tuple(shlex.split(command))
    return tuple(str(part) for part in command)


def classify_command(command: str | list[str] | tuple[str, ...]) -> dict[str, Any]:
    try:
        parts = normalize_command(command)
    except ValueError:
        return _blocked("SHELL_PARSE_FAILED")
    if not parts:
        return _blocked("EMPTY_COMMAND")
    if _has_shell_injection(command):
        return _blocked("SHELL_INJECTION_PATTERN")
    if _has_sensitive_path(parts):
        return _blocked("SENSITIVE_PATH")

    first = parts[0]
    joined = " ".join(parts).lower()
    if first in {"curl", "wget"} or "http://" in joined or "https://" in joined:
        return _risk(CommandRisk.CRITICAL, "NETWORK_COMMAND_BLOCKED")
    if parts[:2] in {("pip", "install"), ("npm", "install")} or parts[:3] in {("python", "-m", "pip")}:
        return _risk(CommandRisk.CRITICAL, "INSTALL_COMMAND_BLOCKED")
    if first in {"rm", "rmdir", "chmod", "chown"}:
        return _risk(CommandRisk.CRITICAL, "DESTRUCTIVE_COMMAND_BLOCKED")
    if parts[:2] in {("git", "push"), ("git", "merge")}:
        return _risk(CommandRisk.CRITICAL, "GIT_REMOTE_OR_MERGE_BLOCKED")
    if parts[:2] in {("git", "add"), ("git", "commit"), ("git", "restore")}:
        return _risk(CommandRisk.HIGH, "HUMAN_APPROVAL_REQUIRED")
    if first in {"apply_patch"} or "patch" in joined:
        return _risk(CommandRisk.MEDIUM, "PROPOSE_CORRECTION_ONLY")
    if parts in SAFE_EXACT_COMMANDS:
        return _allowed(CommandRisk.LOW, SAFE_EXACT_COMMANDS[parts].value)
    if len(parts) >= 3 and parts[0] in {"python", "python3"} and parts[1:3] in {("-m", "json.tool"), ("-m", "py_compile")}:
        return _allowed(CommandRisk.LOW, CommandClass.READ_ONLY_VALIDATION.value)
    if parts and parts[0] in {"pytest", "python", "python3"} and "pytest" in parts:
        return _allowed(CommandRisk.LOW, CommandClass.READ_ONLY_TEST.value)
    return _blocked("UNKNOWN_COMMAND")


def _allowed(risk: CommandRisk, command_class: str) -> dict[str, Any]:
    return {
        "decision": "ALLOW_READ_ONLY",
        "risk_level": risk.value,
        "command_class": command_class,
        "approval_required": False,
        "execution_allowed": True,
        "contract_version": TERMINAL_GOVERNANCE_VERSION,
    }


def _risk(risk: CommandRisk, reason: str) -> dict[str, Any]:
    return {
        "decision": "BLOCKED" if risk == CommandRisk.CRITICAL else "HUMAN_APPROVAL_REQUIRED",
        "risk_level": risk.value,
        "reason": reason,
        "approval_required": risk == CommandRisk.HIGH,
        "execution_allowed": False,
        "contract_version": TERMINAL_GOVERNANCE_VERSION,
    }


def _blocked(reason: str) -> dict[str, Any]:
    return {
        "decision": "FAIL_CLOSED",
        "risk_level": CommandRisk.CRITICAL.value,
        "reason": reason,
        "approval_required": False,
        "execution_allowed": False,
        "contract_version": TERMINAL_GOVERNANCE_VERSION,
    }


def command_risk_classification_json() -> dict[str, Any]:
    return {
        "contract_version": TERMINAL_GOVERNANCE_VERSION,
        "LOW": [
            "git status",
            "git diff --check",
            "git diff --name-only",
            "python -m json.tool",
            "python -m py_compile",
            "pytest focused tests",
        ],
        "MEDIUM": ["generated correction patch", "formatting-only patch proposal"],
        "HIGH": ["git add", "git commit", "git restore", "file modification"],
        "CRITICAL": [
            "git push",
            "git merge",
            "rm/rmdir",
            "chmod/chown",
            "curl/wget",
            "pip install",
            "npm install",
            "reading .env, secrets, keys, tokens",
        ],
        "high_requires_human_approval": True,
        "critical_blocks": True,
    }
