#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from security.policy_registry import policy_hash, verify_policy_signature
from security.request_signing import (
    load_request_private_key,
    load_request_private_key_file,
    load_request_public_key,
    resolve_repo_path,
)


GENESIS_HASH = "0" * 64
DEFAULT_ACTOR_KEYS_PATH = REPO_ROOT / "governance" / "actor_keys.json"
DEFAULT_POLICY_PATH = REPO_ROOT / "governance" / "policy_registry.json"
DEFAULT_POLICY_SIGNATURE_PATH = REPO_ROOT / "governance" / "policy_registry.sig"
DEFAULT_POLICY_PUBLIC_KEY_PATH = REPO_ROOT / "governance" / "policy_public.key"
DEFAULT_RETENTION_PATH = REPO_ROOT / "governance" / "log_retention.json"


def canonical(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def actor_keys_path() -> Path:
    configured = os.getenv("USBAY_ACTOR_KEYS_PATH")
    return Path(configured) if configured else DEFAULT_ACTOR_KEYS_PATH


def load_actor_key_config(path: Path | None = None) -> dict[str, Any]:
    path = path or actor_keys_path()
    raw = load_json(path)
    active = raw.get("active_keys", [])
    revoked = raw.get("revoked_keys", [])
    key_map = raw.get("key_map", {})
    validity = raw.get("validity", {})
    if (
        not isinstance(active, list)
        or not isinstance(revoked, list)
        or not isinstance(key_map, dict)
        or not isinstance(validity, dict)
    ):
        raise ValueError("actor_key_config_invalid")
    return {
        "active_keys": set(active),
        "revoked_keys": set(revoked),
        "key_map": key_map,
        "validity": validity,
        "default_actor_pubkey_id": raw.get("default_actor_pubkey_id") or (active[0] if active else ""),
        "private_key_path": raw.get("private_key_path"),
        "max_clock_skew_seconds": int(raw.get("max_clock_skew_seconds", 60)),
        "_config_path": path,
    }


def resolve_actor_public_key_path(pubkey_id: str, config: dict[str, Any]) -> Path:
    mapped = config["key_map"].get(pubkey_id)
    if not mapped:
        raise ValueError("unknown_actor")
    return resolve_repo_path(mapped, config.get("_config_path", DEFAULT_ACTOR_KEYS_PATH))


def actor_key_is_valid(pubkey_id: str, verified_at_epoch: int, config: dict[str, Any]) -> bool:
    if pubkey_id not in config["active_keys"]:
        return False
    if pubkey_id in config["revoked_keys"]:
        return False
    window = config["validity"].get(pubkey_id)
    if not isinstance(window, dict):
        return False
    try:
        valid_from = int(window["valid_from"])
        valid_until = int(window["valid_until"])
    except Exception:
        return False
    return valid_from <= verified_at_epoch <= valid_until


def parse_timestamp_epoch(value: Any) -> int:
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp_invalid")
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def load_policy_anchor() -> tuple[str, str]:
    policy = load_json(DEFAULT_POLICY_PATH)
    signature = DEFAULT_POLICY_SIGNATURE_PATH.read_text(encoding="utf-8").strip()
    if not verify_policy_signature(policy, signature, DEFAULT_POLICY_PUBLIC_KEY_PATH):
        raise ValueError("policy_anchor_invalid")
    return policy_hash(policy), signature


def genesis_log_hash() -> str:
    policy_hash_value, signature = load_policy_anchor()
    return sha256_text(policy_hash_value + signature)


def verify_genesis_fields(entry: dict[str, Any]) -> bool:
    try:
        policy_hash_value, signature = load_policy_anchor()
    except Exception:
        return False
    return (
        entry.get("genesis_log_hash") == sha256_text(policy_hash_value + signature)
        and entry.get("genesis_policy_signature") == signature
    )


def actor_signature_payload(entry: dict[str, Any]) -> dict[str, Any]:
    payload = dict(entry)
    payload.pop("actor_signature", None)
    payload.pop("current_log_hash", None)
    return payload


def verify_actor_signature(entry: dict[str, Any], actor_config: dict[str, Any], now_epoch: int | None = None) -> bool:
    pubkey_id = entry.get("actor_pubkey_id")
    signature = entry.get("actor_signature")
    if not isinstance(pubkey_id, str) or not pubkey_id:
        return False
    if not isinstance(signature, str) or not signature:
        return False
    current_time = int(now_epoch if now_epoch is not None else time.time())
    try:
        entry_time = parse_timestamp_epoch(entry.get("timestamp"))
        max_skew = int(actor_config.get("max_clock_skew_seconds", 60))
    except Exception:
        return False
    if entry_time > current_time + max_skew:
        return False
    if not actor_key_is_valid(pubkey_id, entry_time, actor_config):
        return False
    try:
        public_key = load_request_public_key(resolve_actor_public_key_path(pubkey_id, actor_config))
        public_key.verify(
            base64.b64decode(signature, validate=True),
            canonical(actor_signature_payload(entry)).encode("utf-8"),
        )
        return True
    except (InvalidSignature, Exception):
        return False


def sign_reset_entry(entry: dict[str, Any], actor_config: dict[str, Any]) -> str:
    env_private_key = os.getenv("USBAY_ACTOR_SIGNING_KEY")
    if env_private_key:
        private_key = load_request_private_key(env_private_key.replace("\\n", "\n").encode("utf-8"))
        return base64.b64encode(private_key.sign(canonical(actor_signature_payload(entry)).encode("utf-8"))).decode("ascii")
    private_key_path = actor_config.get("private_key_path")
    if not isinstance(private_key_path, str) or not private_key_path:
        raise ValueError("missing_actor_private_key")
    private_key = load_request_private_key_file(resolve_repo_path(private_key_path, actor_config.get("_config_path", DEFAULT_ACTOR_KEYS_PATH)))
    return base64.b64encode(private_key.sign(canonical(actor_signature_payload(entry)).encode("utf-8"))).decode("ascii")


def expected_entry_hash(previous_hash: str, entry: dict[str, Any]) -> str:
    unsigned = dict(entry)
    unsigned.pop("current_log_hash", None)
    return sha256_text(previous_hash + canonical(unsigned))


def archive_anchor_is_valid(entry: dict[str, Any]) -> bool:
    archive_anchor = entry.get("archive_anchor")
    if not isinstance(archive_anchor, dict):
        return False
    if archive_anchor.get("anchor_policy") != "chain_hash":
        return False
    archive_file = archive_anchor.get("archive_file")
    archive_hash = archive_anchor.get("archive_hash")
    if not isinstance(archive_file, str) or not isinstance(archive_hash, str):
        return False
    if len(archive_hash) != 64:
        return False
    archive_path = resolve_repo_path(archive_file, DEFAULT_RETENTION_PATH)
    if not archive_path.exists() or not archive_path.is_file():
        return False
    try:
        return sha256_text(archive_path.read_text(encoding="utf-8")) == archive_hash
    except Exception:
        return False


def verify_reset_log(log_path: Path, now_epoch: int | None = None) -> bool:
    if not log_path.exists():
        return False
    actor_config = load_actor_key_config()
    previous = GENESIS_HASH
    try:
        lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            return False
        for index, line in enumerate(lines):
            entry = json.loads(line)
            required = {
                "timestamp",
                "event_type",
                "actor_id",
                "actor_pubkey_id",
                "file_list_deleted",
                "previous_log_hash",
                "current_log_hash",
                "actor_signature",
            }
            if any(entry.get(field) in (None, "") for field in required):
                return False
            if index == 0:
                if not verify_genesis_fields(entry):
                    return False
                if entry.get("previous_log_hash") != GENESIS_HASH:
                    if entry.get("event_type") != "rotation_anchor" or not archive_anchor_is_valid(entry):
                        return False
                    previous = str(entry["previous_log_hash"])
            if entry.get("previous_log_hash") != previous:
                return False
            if not verify_actor_signature(entry, actor_config, now_epoch=now_epoch):
                return False
            if entry.get("current_log_hash") != expected_entry_hash(previous, entry):
                return False
            previous = entry["current_log_hash"]
    except Exception:
        return False
    return True


def current_chain_hash(log_path: Path) -> str:
    previous = GENESIS_HASH
    if not log_path.exists():
        return previous
    lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for line in lines:
        entry = json.loads(line)
        previous = entry["current_log_hash"]
    return previous


def load_retention_policy(path: Path = DEFAULT_RETENTION_PATH) -> dict[str, Any]:
    policy = load_json(path)
    if policy.get("anchor_policy") != "chain_hash":
        raise ValueError("retention_policy_invalid")
    try:
        max_mb = float(policy["max_log_size_mb"])
    except Exception as exc:
        raise ValueError("retention_policy_invalid") from exc
    if max_mb <= 0:
        raise ValueError("retention_policy_invalid")
    archive_dir_value = Path(policy.get("archive_dir", "demos/edgeguard/archive"))
    archive_dir = archive_dir_value if archive_dir_value.is_absolute() else REPO_ROOT / archive_dir_value
    return {
        "max_log_size_mb": max_mb,
        "rotate_on_start": policy.get("rotate_on_start") is True,
        "archive_dir": archive_dir,
        "anchor_policy": "chain_hash",
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python scripts/verify_reset_log.py <reset_audit.log>", file=sys.stderr)
        return 2
    try:
        valid = verify_reset_log(Path(argv[1]))
    except Exception:
        valid = False
    print("VALID" if valid else "INVALID")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
