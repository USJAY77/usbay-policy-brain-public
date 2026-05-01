from __future__ import annotations

import hashlib
import json
import base64
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class PolicyRegistryError(RuntimeError):
    pass


DEFAULT_DRIFT_WINDOW_SECONDS = 300
_last_seen_policy_sequences: dict[str, int] = {}


def _csv_set(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def canonical_policy_bytes(policy: dict[str, Any]) -> bytes:
    return json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")


def policy_hash(policy: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_policy_bytes(policy)).hexdigest()


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    try:
        return _sha256_hex(path.read_bytes())
    except Exception as exc:
        raise PolicyRegistryError("policy_release_artifact_unavailable") from exc


def load_policy_public_key(public_key_path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(public_key_path.read_bytes())
    except Exception as exc:
        raise PolicyRegistryError("policy_public_key_invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise PolicyRegistryError("policy_public_key_invalid")
    return key


def policy_pubkey_id(public_key: Ed25519PublicKey) -> str:
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(public_bytes).hexdigest()


def public_key_sha256(public_key: Ed25519PublicKey) -> str:
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _sha256_hex(public_bytes)


def encode_policy_signature(policy: dict[str, Any], private_key: Any) -> str:
    signature = private_key.sign(canonical_policy_bytes(validate_policy_registry_shape(policy)))
    return base64.b64encode(signature).decode("ascii")


def verify_policy_signature(policy: dict[str, Any], signature: str, public_key_path: Path) -> bool:
    if not isinstance(policy, dict) or not isinstance(signature, str) or not signature:
        return False
    try:
        public_key = load_policy_public_key(public_key_path)
        signature_bytes = base64.b64decode(signature.strip(), validate=True)
        public_key.verify(signature_bytes, canonical_policy_bytes(validate_policy_registry_shape(policy)))
        return True
    except (InvalidSignature, Exception):
        return False


def parse_policy_time(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise PolicyRegistryError("policy_validity_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise PolicyRegistryError("policy_validity_invalid") from exc
    if parsed.tzinfo is None:
        raise PolicyRegistryError("policy_validity_invalid")
    return parsed.astimezone(timezone.utc)


def reset_policy_sequence_tracker() -> None:
    _last_seen_policy_sequences.clear()


def enforce_policy_sequence(policy_pubkey_id_value: str, policy_sequence: int) -> None:
    last_seen_sequence = _last_seen_policy_sequences.get(policy_pubkey_id_value)
    if last_seen_sequence is not None and policy_sequence < last_seen_sequence:
        raise PolicyRegistryError("rollback_detected")
    _last_seen_policy_sequences[policy_pubkey_id_value] = policy_sequence


def enforce_policy_validity_window(
    policy: dict[str, Any],
    now: datetime | None = None,
    drift_window_seconds: int = DEFAULT_DRIFT_WINDOW_SECONDS,
) -> None:
    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    valid_from = parse_policy_time(policy.get("valid_from", ""))
    valid_until = parse_policy_time(policy.get("valid_until", ""))
    try:
        drift_window = timedelta(seconds=int(drift_window_seconds))
    except Exception as exc:
        raise PolicyRegistryError("policy_key_config_invalid") from exc
    if drift_window.total_seconds() < 0:
        raise PolicyRegistryError("policy_key_config_invalid")
    if valid_from > valid_until:
        raise PolicyRegistryError("policy_validity_invalid")
    if current_time < valid_from - drift_window:
        raise PolicyRegistryError("policy_not_yet_valid")
    if current_time > valid_until + drift_window:
        raise PolicyRegistryError("policy_expired")


def validate_policy_registry_shape(policy: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise PolicyRegistryError("policy_registry_invalid")
    if not isinstance(policy.get("version"), str) or not policy.get("version"):
        raise PolicyRegistryError("policy_registry_invalid")
    if not isinstance(policy.get("critical_infrastructure"), list):
        raise PolicyRegistryError("policy_registry_invalid")
    if not isinstance(policy.get("last_updated"), str) or not policy.get("last_updated"):
        raise PolicyRegistryError("policy_registry_invalid")
    if policy.get("authority") != "human_policy_owner":
        raise PolicyRegistryError("policy_registry_invalid")
    if not isinstance(policy.get("policy_pubkey_id"), str) or not policy.get("policy_pubkey_id"):
        raise PolicyRegistryError("policy_registry_invalid")
    if not isinstance(policy.get("policy_sequence"), int) or policy.get("policy_sequence") < 0:
        raise PolicyRegistryError("policy_registry_invalid")
    for duty_field in ("policy_author", "policy_signer", "deployment_operator"):
        if not isinstance(policy.get(duty_field), str) or not policy.get(duty_field):
            raise PolicyRegistryError("policy_registry_invalid")
    if policy["policy_author"] == policy["policy_signer"]:
        raise PolicyRegistryError("separation_of_duties_violation")
    if policy["policy_signer"] == policy["deployment_operator"]:
        raise PolicyRegistryError("separation_of_duties_violation")
    valid_from = policy.get("valid_from")
    valid_until = policy.get("valid_until")
    parse_policy_time(valid_from)
    parse_policy_time(valid_until)
    normalized = {
        **policy,
        "critical_infrastructure": [
            str(system).lower() for system in policy["critical_infrastructure"]
            if isinstance(system, str) and system
        ],
    }
    return normalized


def load_policy_key_config(config_path: Path | None = None) -> dict[str, Any]:
    active_keys = _csv_set(os.getenv("USBAY_POLICY_ACTIVE_KEYS"))
    active_keys.update(_csv_set(os.getenv("USBAY_POLICY_PUBKEY_ALLOWLIST")))
    revoked_keys = _csv_set(os.getenv("USBAY_POLICY_REVOKED_KEYS"))
    revoked_keys.update(_csv_set(os.getenv("USBAY_POLICY_PUBKEY_REVOKED")))
    key_map: dict[str, str] = {}
    public_key_sha256_pins: dict[str, str] = {}
    drift_window_seconds = DEFAULT_DRIFT_WINDOW_SECONDS
    if os.getenv("USBAY_POLICY_DRIFT_WINDOW_SECONDS"):
        try:
            drift_window_seconds = int(os.getenv("USBAY_POLICY_DRIFT_WINDOW_SECONDS", ""))
        except Exception as exc:
            raise PolicyRegistryError("policy_key_config_invalid") from exc
    if config_path is not None and config_path.exists():
        try:
            raw_config = json.loads(config_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise PolicyRegistryError("policy_key_config_invalid") from exc
        if not isinstance(raw_config, dict):
            raise PolicyRegistryError("policy_key_config_invalid")
        if "active_keys" in raw_config:
            configured_active = raw_config["active_keys"]
            if not isinstance(configured_active, list) or not all(isinstance(item, str) for item in configured_active):
                raise PolicyRegistryError("policy_key_config_invalid")
            active_keys.update(configured_active)
        if "revoked_keys" in raw_config:
            configured_revoked = raw_config["revoked_keys"]
            if not isinstance(configured_revoked, list) or not all(isinstance(item, str) for item in configured_revoked):
                raise PolicyRegistryError("policy_key_config_invalid")
            revoked_keys.update(configured_revoked)
        if "key_map" in raw_config:
            configured_key_map = raw_config["key_map"]
            if (
                not isinstance(configured_key_map, dict)
                or not all(isinstance(key, str) and isinstance(value, str) for key, value in configured_key_map.items())
            ):
                raise PolicyRegistryError("policy_key_config_invalid")
            key_map.update(configured_key_map)
        if "public_key_sha256" in raw_config:
            configured_pins = raw_config["public_key_sha256"]
            if isinstance(configured_pins, str):
                if len(key_map) != 1:
                    raise PolicyRegistryError("policy_key_config_invalid")
                public_key_sha256_pins[next(iter(key_map))] = configured_pins
            elif isinstance(configured_pins, dict) and all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in configured_pins.items()
            ):
                public_key_sha256_pins.update(configured_pins)
            else:
                raise PolicyRegistryError("policy_key_config_invalid")
        if "drift_window_seconds" in raw_config:
            try:
                drift_window_seconds = int(raw_config["drift_window_seconds"])
            except Exception as exc:
                raise PolicyRegistryError("policy_key_config_invalid") from exc
        if "allowed_policy_pubkey_ids" in raw_config:
            allowed = raw_config["allowed_policy_pubkey_ids"]
            if not isinstance(allowed, list) or not all(isinstance(item, str) for item in allowed):
                raise PolicyRegistryError("policy_key_config_invalid")
            active_keys.update(allowed)
        if "revoked_policy_pubkey_ids" in raw_config:
            revoked_ids = raw_config["revoked_policy_pubkey_ids"]
            if not isinstance(revoked_ids, list) or not all(isinstance(item, str) for item in revoked_ids):
                raise PolicyRegistryError("policy_key_config_invalid")
            revoked_keys.update(revoked_ids)
    if drift_window_seconds < 0:
        raise PolicyRegistryError("policy_key_config_invalid")
    return {
        "active_keys": active_keys,
        "revoked_keys": revoked_keys,
        "key_map": key_map,
        "public_key_sha256": public_key_sha256_pins,
        "drift_window_seconds": drift_window_seconds,
    }


def resolve_policy_public_key_path(
    policy_pubkey_id_value: str,
    key_config: dict[str, Any],
    default_public_key_path: Path,
    config_path: Path | None = None,
) -> Path:
    mapped_key = key_config.get("key_map", {}).get(policy_pubkey_id_value)
    if not mapped_key:
        return default_public_key_path
    mapped_path = Path(mapped_key)
    if mapped_path.is_absolute():
        return mapped_path
    base_dir = config_path.parent if config_path is not None else default_public_key_path.parent
    return base_dir / mapped_path


def enforce_policy_key_trust(policy_pubkey_id_value: str, key_config: dict[str, Any]) -> None:
    if policy_pubkey_id_value in key_config.get("revoked_keys", set()):
        raise PolicyRegistryError("policy_public_key_revoked")
    active_keys = key_config.get("active_keys", set())
    if active_keys and policy_pubkey_id_value not in active_keys:
        raise PolicyRegistryError("policy_public_key_not_allowed")


def load_policy_authority(authority_path: Path | None = None) -> dict[str, Any]:
    path = authority_path or Path("governance/policy_authority.json")
    try:
        authority = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyRegistryError("policy_authority_unavailable") from exc
    if not isinstance(authority, dict):
        raise PolicyRegistryError("policy_authority_invalid")
    for field in ("policy_author", "policy_signer", "deployment_operator"):
        if not isinstance(authority.get(field), str) or not authority.get(field):
            raise PolicyRegistryError("policy_authority_invalid")
    if authority["policy_author"] == authority["policy_signer"]:
        raise PolicyRegistryError("separation_of_duties_violation")
    if authority["policy_signer"] == authority["deployment_operator"]:
        raise PolicyRegistryError("separation_of_duties_violation")
    rotation_policy = authority.get("rotation_policy")
    if not isinstance(rotation_policy, dict):
        raise PolicyRegistryError("policy_authority_invalid")
    try:
        max_age_days = int(rotation_policy.get("max_age_days"))
        overlap_period = int(rotation_policy.get("overlap_period"))
    except Exception as exc:
        raise PolicyRegistryError("policy_authority_invalid") from exc
    if max_age_days <= 0 or overlap_period < 0:
        raise PolicyRegistryError("policy_authority_invalid")
    if authority.get("dispute_resolution_required") is not True:
        raise PolicyRegistryError("policy_authority_invalid")
    if authority.get("dispute_owner_role") != "human_policy_authority":
        raise PolicyRegistryError("policy_authority_invalid")
    key_validity = authority.get("key_validity")
    if key_validity is not None and not isinstance(key_validity, dict):
        raise PolicyRegistryError("policy_authority_invalid")
    return authority


def enforce_policy_authority(
    policy: dict[str, Any],
    manifest: dict[str, Any],
    policy_pubkey_id_value: str,
    authority_path: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    authority = load_policy_authority(authority_path)
    for field in ("policy_author", "policy_signer", "deployment_operator"):
        if policy.get(field) != authority[field]:
            raise PolicyRegistryError("unauthorized_policy_change")
    release_signer = authority.get("release_signer")
    if release_signer and manifest.get("signed_by_human") != release_signer:
        raise PolicyRegistryError("unauthorized_policy_change")

    key_validity = authority.get("key_validity", {})
    key_window = key_validity.get(policy_pubkey_id_value)
    if key_window is not None:
        current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        created_at = parse_policy_time(key_window.get("created_at", ""))
        expires_at = parse_policy_time(key_window.get("expires_at", ""))
        if expires_at <= created_at:
            raise PolicyRegistryError("policy_key_expired")
        rotation_policy = authority["rotation_policy"]
        max_age_days = int(rotation_policy["max_age_days"])
        if expires_at > created_at + timedelta(days=max_age_days):
            raise PolicyRegistryError("policy_key_expired")
        if current_time > expires_at:
            raise PolicyRegistryError("policy_key_expired")
    return authority


def enforce_public_key_pin(
    policy_pubkey_id_value: str,
    public_key: Ed25519PublicKey,
    key_config: dict[str, Any],
) -> None:
    expected_pin = key_config.get("public_key_sha256", {}).get(policy_pubkey_id_value)
    if expected_pin and public_key_sha256(public_key) != expected_pin:
        raise PolicyRegistryError("public_key_pin_mismatch")


def load_policy_release_manifest(manifest_path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyRegistryError("policy_release_manifest_missing") from exc
    if not isinstance(manifest, dict):
        raise PolicyRegistryError("policy_release_manifest_invalid")
    return manifest


def validate_policy_release_manifest(
    policy: dict[str, Any],
    policy_path: Path,
    signature_path: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    manifest = load_policy_release_manifest(manifest_path)
    artifact_hashes = manifest.get("artifact_hashes")
    if not isinstance(artifact_hashes, dict):
        raise PolicyRegistryError("policy_release_manifest_invalid")
    if not isinstance(manifest.get("policy_version"), str) or not manifest.get("policy_version"):
        raise PolicyRegistryError("policy_release_manifest_invalid")
    if not isinstance(manifest.get("policy_hash"), str) or not manifest.get("policy_hash"):
        raise PolicyRegistryError("policy_release_manifest_invalid")
    if not isinstance(manifest.get("policy_pubkey_id"), str) or not manifest.get("policy_pubkey_id"):
        raise PolicyRegistryError("policy_release_manifest_invalid")
    if not isinstance(manifest.get("created_at"), str) or not manifest.get("created_at"):
        raise PolicyRegistryError("policy_release_manifest_invalid")
    if not isinstance(manifest.get("signed_by_human"), str) or not manifest.get("signed_by_human"):
        raise PolicyRegistryError("policy_release_manifest_invalid")
    if manifest["policy_version"] != policy.get("version"):
        raise PolicyRegistryError("policy_release_manifest_mismatch")
    if manifest["policy_hash"] != policy_hash(policy):
        raise PolicyRegistryError("policy_release_manifest_mismatch")
    if manifest["policy_pubkey_id"] != policy.get("policy_pubkey_id"):
        raise PolicyRegistryError("policy_release_manifest_mismatch")
    expected_artifacts = {
        "policy_registry.json": file_sha256(policy_path),
        "policy_registry.json.sig": file_sha256(signature_path),
    }
    for artifact_name, expected_hash in expected_artifacts.items():
        if artifact_hashes.get(artifact_name) != expected_hash:
            raise PolicyRegistryError("policy_release_manifest_mismatch")
    return manifest


def load_signed_policy_registry(
    policy_path: Path,
    signature_path: Path,
    public_key_path: Path,
    key_config_path: Path | None = None,
    release_manifest_path: Path | None = None,
    authority_path: Path | None = None,
) -> dict[str, Any]:
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyRegistryError("policy_registry_unavailable") from exc
    try:
        signature = signature_path.read_text(encoding="utf-8").strip()
    except Exception as exc:
        raise PolicyRegistryError("policy_registry_signature_missing") from exc
    normalized = validate_policy_registry_shape(policy)
    key_config = load_policy_key_config(key_config_path)
    policy_key_id = normalized["policy_pubkey_id"]
    enforce_policy_key_trust(policy_key_id, key_config)
    resolved_public_key_path = resolve_policy_public_key_path(
        policy_key_id,
        key_config,
        public_key_path,
        key_config_path,
    )
    public_key = load_policy_public_key(resolved_public_key_path)
    enforce_public_key_pin(policy_key_id, public_key, key_config)
    if not verify_policy_signature(normalized, signature, resolved_public_key_path):
        raise PolicyRegistryError("policy_registry_signature_invalid")
    manifest = None
    if release_manifest_path is not None:
        manifest = validate_policy_release_manifest(
            normalized,
            policy_path,
            signature_path,
            release_manifest_path,
        )
    if manifest is not None and authority_path is not None:
        enforce_policy_authority(normalized, manifest, policy_key_id, authority_path)
    enforce_policy_validity_window(
        normalized,
        drift_window_seconds=key_config["drift_window_seconds"],
    )
    enforce_policy_sequence(policy_key_id, normalized["policy_sequence"])
    return {
        **normalized,
        "policy_hash": policy_hash(normalized),
        "policy_signature_valid": True,
        "policy_pubkey_id": policy_key_id,
    }


def current_policy_key_config_fingerprint(config_path: Path | None = None) -> tuple:
    key_config = load_policy_key_config(config_path)
    return (
        tuple(sorted(key_config.get("active_keys", set()))),
        tuple(sorted(key_config.get("revoked_keys", set()))),
        tuple(sorted(key_config.get("key_map", {}).items())),
        tuple(sorted(key_config.get("public_key_sha256", {}).items())),
        key_config.get("drift_window_seconds"),
    )


POLICY_LOG_GENESIS = "0" * 64


def _policy_log_entry_hash(entry: dict[str, Any]) -> str:
    return _sha256_hex(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def append_policy_log(policy: dict[str, Any], log_path: Path, signature: str | None = None) -> dict[str, str]:
    if not signature:
        raise PolicyRegistryError("policy_log_signature_required")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    previous_hash = POLICY_LOG_GENESIS
    if log_path.exists():
        lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            try:
                previous_hash = _policy_log_entry_hash(json.loads(lines[-1]))
            except Exception as exc:
                raise PolicyRegistryError("policy_log_invalid") from exc
    normalized = validate_policy_registry_shape(policy)
    entry = {
        "policy_hash": policy_hash(normalized),
        "previous_hash": previous_hash,
        "policy_sequence": normalized["policy_sequence"],
        "policy_version": normalized["version"],
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "policy_pubkey_id": normalized["policy_pubkey_id"],
        "signature": signature,
    }
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
    return entry


def verify_policy_log(log_path: Path, expected_policy_hash: str | None = None) -> bool:
    if not log_path.exists():
        return False
    previous_hash = POLICY_LOG_GENESIS
    found_expected = expected_policy_hash is None
    try:
        lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            return False
        for line in lines:
            entry = json.loads(line)
            if set(entry) != {
                "policy_hash",
                "previous_hash",
                "policy_sequence",
                "policy_version",
                "timestamp",
                "policy_pubkey_id",
                "signature",
            }:
                return False
            if not isinstance(entry["policy_hash"], str) or len(entry["policy_hash"]) != 64:
                return False
            if entry["previous_hash"] != previous_hash:
                return False
            if not isinstance(entry["policy_sequence"], int) or entry["policy_sequence"] < 0:
                return False
            if not isinstance(entry["policy_version"], str) or not entry["policy_version"]:
                return False
            if not isinstance(entry["policy_pubkey_id"], str) or not entry["policy_pubkey_id"]:
                return False
            if not isinstance(entry["signature"], str) or not entry["signature"]:
                return False
            parse_policy_time(entry["timestamp"])
            if entry["policy_hash"] == expected_policy_hash:
                found_expected = True
            previous_hash = _policy_log_entry_hash(entry)
    except Exception:
        return False
    return found_expected
