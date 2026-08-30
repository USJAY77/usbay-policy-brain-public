from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


SIGNATURE_ALG = "ed25519"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REQUEST_KEY_CONFIG_PATH = REPO_ROOT / "governance" / "request_signing_keys.json"
DEFAULT_REQUEST_PRIVATE_KEY_PATH = REPO_ROOT / "governance" / "keys" / "request_private.key"
DEFAULT_REQUEST_PUBLIC_KEY_PATH = REPO_ROOT / "governance" / "keys" / "request_public.key"
DEFAULT_REQUEST_PUBKEY_ID = "request_key_2026_01"


class RequestSignatureError(RuntimeError):
    pass


def canonical(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def request_signature_message(payload: dict[str, Any]) -> str:
    unsigned = payload.copy()
    unsigned.pop("signature", None)
    unsigned.pop("decision_id", None)
    unsigned.pop("decision_signature", None)
    unsigned.pop("decision_signature_classic", None)
    unsigned.pop("decision_signature_pqc", None)
    return canonical(unsigned)


def load_request_public_key(public_key_path: Path) -> Ed25519PublicKey:
    try:
        key_bytes = public_key_path.read_bytes()
    except FileNotFoundError as exc:
        raise RequestSignatureError("missing_request_signing_public_key") from exc
    except Exception as exc:
        raise RequestSignatureError("request_public_key_invalid") from exc
    try:
        if len(key_bytes) == 32:
            return Ed25519PublicKey.from_public_bytes(key_bytes)
        key = serialization.load_pem_public_key(key_bytes)
    except Exception as exc:
        raise RequestSignatureError("request_public_key_invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise RequestSignatureError("request_public_key_invalid")
    return key


def load_request_private_key(private_key_pem: str | bytes) -> Ed25519PrivateKey:
    key_bytes = private_key_pem.encode("utf-8") if isinstance(private_key_pem, str) else private_key_pem
    try:
        if len(key_bytes) == 32:
            return Ed25519PrivateKey.from_private_bytes(key_bytes)
        key = serialization.load_pem_private_key(key_bytes, password=None)
    except Exception as exc:
        raise RequestSignatureError("request_private_key_invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise RequestSignatureError("request_private_key_invalid")
    return key


def load_request_private_key_file(private_key_path: Path = DEFAULT_REQUEST_PRIVATE_KEY_PATH) -> Ed25519PrivateKey:
    try:
        return load_request_private_key(private_key_path.read_bytes())
    except FileNotFoundError as exc:
        raise RequestSignatureError("missing_request_signing_private_key") from exc


def load_request_key_config(config_path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RequestSignatureError("request_key_config_invalid") from exc
    if not isinstance(raw, dict):
        raise RequestSignatureError("request_key_config_invalid")
    active_keys = raw.get("active_keys", [])
    revoked_keys = raw.get("revoked_keys", [])
    key_map = raw.get("key_map", {})
    if (
        not isinstance(active_keys, list)
        or not all(isinstance(item, str) for item in active_keys)
        or not isinstance(revoked_keys, list)
        or not all(isinstance(item, str) for item in revoked_keys)
        or not isinstance(key_map, dict)
        or not all(isinstance(key, str) and isinstance(value, str) for key, value in key_map.items())
    ):
        raise RequestSignatureError("request_key_config_invalid")
    return {
        "active_keys": set(active_keys),
        "revoked_keys": set(revoked_keys),
        "key_map": key_map,
        "private_key_path": raw.get("private_key_path"),
        "default_pubkey_id": raw.get("default_pubkey_id") or DEFAULT_REQUEST_PUBKEY_ID,
    }


def resolve_repo_path(path_value: str | Path, config_path: Path | None = None) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    repo_candidate = REPO_ROOT / path
    if repo_candidate.exists() or str(path).startswith("governance/"):
        return repo_candidate
    if config_path is not None:
        return config_path.parent / path
    return repo_candidate


def resolve_request_public_key_path(pubkey_id: str, config: dict[str, Any], config_path: Path) -> Path:
    mapped = config["key_map"].get(pubkey_id)
    if not mapped:
        raise RequestSignatureError("unknown_pubkey_id")
    return resolve_repo_path(mapped, config_path)


def default_request_private_key_path(config_path: Path = DEFAULT_REQUEST_KEY_CONFIG_PATH) -> Path:
    try:
        config = load_request_key_config(config_path)
    except RequestSignatureError:
        return DEFAULT_REQUEST_PRIVATE_KEY_PATH
    configured_path = config.get("private_key_path")
    if isinstance(configured_path, str) and configured_path:
        return resolve_repo_path(configured_path, config_path)
    return DEFAULT_REQUEST_PRIVATE_KEY_PATH


def default_request_pubkey_id(config_path: Path = DEFAULT_REQUEST_KEY_CONFIG_PATH) -> str:
    try:
        config = load_request_key_config(config_path)
    except RequestSignatureError:
        return DEFAULT_REQUEST_PUBKEY_ID
    configured = config.get("default_pubkey_id")
    if isinstance(configured, str) and configured:
        return configured
    return DEFAULT_REQUEST_PUBKEY_ID


def validate_request_signature(payload: dict[str, Any], config_path: Path) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return False, "invalid_signature"
    if payload.get("signature_alg") != SIGNATURE_ALG:
        return False, "invalid_signature"
    signature = payload.get("signature")
    pubkey_id = payload.get("pubkey_id")
    if not isinstance(signature, str) or not signature:
        return False, "invalid_signature"
    if not isinstance(pubkey_id, str) or not pubkey_id:
        return False, "unknown_key"
    try:
        config = load_request_key_config(config_path)
        if pubkey_id in config["revoked_keys"]:
            return False, "unknown_key"
        if pubkey_id not in config["active_keys"]:
            return False, "unknown_key"
        public_key_path = resolve_request_public_key_path(pubkey_id, config, config_path)
        public_key = load_request_public_key(public_key_path)
        signature_bytes = base64.b64decode(signature, validate=True)
        public_key.verify(signature_bytes, request_signature_message(payload).encode("utf-8"))
        return True, "ok"
    except InvalidSignature:
        return False, "invalid_signature"
    except RequestSignatureError as exc:
        if str(exc) == "unknown_pubkey_id":
            return False, "unknown_key"
        return False, "invalid_signature"
    except Exception:
        return False, "invalid_signature"


def verify_request_signature(payload: dict[str, Any], config_path: Path) -> bool:
    valid, _reason = validate_request_signature(payload, config_path)
    return valid


def sign_request_payload(payload: dict[str, Any], private_key_pem: str | bytes, pubkey_id: str) -> dict[str, Any]:
    if not pubkey_id:
        raise RequestSignatureError("missing_pubkey_id")
    signed = payload.copy()
    signed["signature_alg"] = SIGNATURE_ALG
    signed["pubkey_id"] = pubkey_id
    private_key = load_request_private_key(private_key_pem)
    signature = private_key.sign(request_signature_message(signed).encode("utf-8"))
    signed["signature"] = base64.b64encode(signature).decode("ascii")
    return signed
