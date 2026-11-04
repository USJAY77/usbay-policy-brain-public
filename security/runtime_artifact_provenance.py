"""Independent producer trust; this module does not authorize application startup.

No private-key loading, Git calls, key discovery, or trust-on-first-use is allowed
here. Consumers must retain their existing policy and forbidden-file controls.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PRODUCER_CONTRACT = "usbay.runtime_artifact_producer.v1"
MANIFEST_SCHEMA = "usbay.runtime_source_manifest.v1"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_MANAGED_FILES = 100_000
MAX_FILE_BYTES = 1024 * 1024 * 1024
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_KEY_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FIELDS = {
    "schema_version", "producer_contract", "producer_key_id", "producer_scope",
    "source_commit", "source_tree_reference", "managed_files", "managed_set_hash",
    "build_reference", "created_at", "manifest_id", "manifest_digest", "signature",
}


class RuntimeArtifactError(RuntimeError):
    """Only bounded, content-free error codes cross this boundary."""


def canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise RuntimeArtifactError("runtime_artifact_contract_invalid") from None


def public_key_id(raw_public_key: bytes) -> str:
    if type(raw_public_key) is not bytes or len(raw_public_key) != 32:
        raise RuntimeArtifactError("runtime_artifact_producer_trust_invalid")
    return "sha256:" + hashlib.sha256(raw_public_key).hexdigest()


def _decode_base64(value: object, length: int, code: str) -> bytes:
    try:
        if not isinstance(value, str):
            raise ValueError
        raw = base64.b64decode(value, validate=True)
        if len(raw) != length or base64.b64encode(raw).decode("ascii") != value:
            raise ValueError
        return raw
    except (ValueError, TypeError, UnicodeError):
        raise RuntimeArtifactError(code) from None


@dataclass(frozen=True)
class ProducerTrust:
    public_key: bytes
    key_id: str
    producer_scope: str
    mode: str = "production"

    def validate(self) -> None:
        if not isinstance(self.mode, str) or self.mode not in {"production", "test"}:
            raise RuntimeArtifactError("runtime_artifact_mode_invalid")
        if not isinstance(self.producer_scope, str) or self.producer_scope not in {"production", "test"}:
            raise RuntimeArtifactError("runtime_artifact_producer_trust_invalid")
        if self.mode == "production" and self.producer_scope == "test":
            raise RuntimeArtifactError("runtime_artifact_test_producer_denied")
        if self.key_id != public_key_id(self.public_key):
            raise RuntimeArtifactError("runtime_artifact_producer_key_id_mismatch")


def runtime_environment_mode(
    environment: Mapping[str, str] | None = None, *, default: str = "production",
) -> str:
    """One fail-closed interpretation of explicit runtime mode declarations."""
    config = os.environ if environment is None else environment
    aliases = {
        "production": "production", "prod": "production",
        "test": "test", "development": "test", "dev": "test",
    }
    modes = []
    for name in ("USBAY_ENV", "USBAY_ENVIRONMENT"):
        if name in config:
            raw = config[name]
            if not isinstance(raw, str) or raw.strip().lower() not in aliases:
                raise RuntimeArtifactError("runtime_artifact_mode_invalid")
            modes.append(aliases[raw.strip().lower()])
    if len(set(modes)) > 1:
        raise RuntimeArtifactError("runtime_artifact_mode_conflict")
    return modes[0] if modes else default


def producer_trust_from_environment(
    environment: Mapping[str, str] | None = None,
) -> ProducerTrust:
    """Read only public verifier configuration; no signing key is consulted."""
    config = os.environ if environment is None else environment
    public = config.get("USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY")
    key_id = config.get("USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID")
    scope = config.get("USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE")
    if not public or not key_id or not scope:
        raise RuntimeArtifactError("runtime_artifact_producer_trust_unavailable")
    mode = runtime_environment_mode(config)
    trust = ProducerTrust(
        _decode_base64(public, 32, "runtime_artifact_producer_trust_invalid"),
        key_id, scope, mode,
    )
    trust.validate()
    return trust


def validate_managed_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise RuntimeArtifactError("runtime_artifact_path_invalid")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise RuntimeArtifactError("runtime_artifact_path_invalid") from None
    parts = value.split("/")
    if (
        value.startswith("/") or "\\" in value or ":" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
        or any(part in {"", ".", "..", ".git"} for part in parts)
    ):
        raise RuntimeArtifactError("runtime_artifact_path_invalid")
    return value


@dataclass(frozen=True)
class ManagedFile:
    path: str
    mode: str
    sha256: str
    size: int

    def as_dict(self) -> dict:
        return {
            "path": self.path, "mode": self.mode,
            "sha256": self.sha256, "size": self.size,
        }


@dataclass(frozen=True)
class VerifiedRuntimeArtifact:
    """Shared immutable data for future scanner AND provenance consumers.

    This is a verification result, not an execution/deployment authorization.
    Files can change after verification; consumers must verify at point of use.
    """

    producer_key_id: str
    producer_scope: str
    source_commit: str
    source_tree_reference: str
    manifest_digest: str
    managed_set_hash: str
    manifest_id: str
    managed_files: tuple[ManagedFile, ...]


def _pairs_without_duplicates(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeArtifactError("runtime_artifact_manifest_duplicate_field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise RuntimeArtifactError("runtime_artifact_contract_invalid")


def _parse_manifest(raw: bytes) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_MANIFEST_BYTES:
        raise RuntimeArtifactError("runtime_artifact_manifest_size_invalid")
    try:
        manifest = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (ValueError, UnicodeError, RecursionError):
        raise RuntimeArtifactError("runtime_artifact_manifest_malformed") from None
    if not isinstance(manifest, dict) or set(manifest) != _FIELDS:
        raise RuntimeArtifactError("runtime_artifact_contract_invalid")
    if (
        manifest["schema_version"] != MANIFEST_SCHEMA
        or manifest["producer_contract"] != PRODUCER_CONTRACT
    ):
        raise RuntimeArtifactError("runtime_artifact_schema_invalid")
    return manifest


def manifest_digest(manifest: dict) -> str:
    payload = {
        key: value for key, value in manifest.items()
        if key not in {"signature", "manifest_digest"}
    }
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def signature_payload(manifest: dict) -> bytes:
    return canonical_bytes({key: value for key, value in manifest.items() if key != "signature"})


def _managed_entries(manifest: dict) -> tuple[ManagedFile, ...]:
    raw = manifest["managed_files"]
    if not isinstance(raw, list) or not 0 < len(raw) <= MAX_MANAGED_FILES:
        raise RuntimeArtifactError("runtime_artifact_managed_set_invalid")
    result = []
    previous = ""
    for entry in raw:
        if not isinstance(entry, dict) or set(entry) != {"path", "mode", "sha256", "size"}:
            raise RuntimeArtifactError("runtime_artifact_managed_set_invalid")
        path = validate_managed_path(entry["path"])
        if path <= previous:
            raise RuntimeArtifactError("runtime_artifact_managed_set_invalid")
        previous = path
        if (
            not isinstance(entry["mode"], str)
            or entry["mode"] not in {"100644", "100755"}
            or not isinstance(entry["sha256"], str)
            or not _HEX64.fullmatch(entry["sha256"])
            or type(entry["size"]) is not int
            or not 0 <= entry["size"] <= MAX_FILE_BYTES
        ):
            raise RuntimeArtifactError("runtime_artifact_managed_set_invalid")
        result.append(ManagedFile(**entry))
    actual_hash = hashlib.sha256(canonical_bytes(raw)).hexdigest()
    if manifest["managed_set_hash"] != actual_hash:
        raise RuntimeArtifactError("runtime_artifact_managed_set_mismatch")
    return tuple(result)


def inspect_managed_file(root: Path, entry: ManagedFile) -> tuple[str, str]:
    """Linux openat/O_NOFOLLOW traversal; return SHA256 and Git blob OID.

    Never follow root/parent/file symlinks. Never log file bytes or paths.
    Each read must have stable inode, size, mode, mtime and ctime.
    """
    validate_managed_path(entry.path)
    handles: list[int] = []
    try:
        absolute = Path(root).absolute()
        if absolute.resolve(strict=True) != absolute:
            raise RuntimeArtifactError("runtime_artifact_root_invalid")
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(absolute, flags | os.O_DIRECTORY)
        handles.append(descriptor)
        for part in entry.path.split("/")[:-1]:
            descriptor = os.open(part, flags | os.O_DIRECTORY, dir_fd=descriptor)
            handles.append(descriptor)
        descriptor = os.open(entry.path.split("/")[-1], flags | os.O_NONBLOCK, dir_fd=descriptor)
        handles.append(descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeArtifactError("runtime_artifact_file_type_invalid")
        if before.st_size != entry.size:
            raise RuntimeArtifactError("runtime_artifact_file_size_mismatch")
        expected_executable = entry.mode == "100755"
        if bool(before.st_mode & 0o111) != expected_executable:
            raise RuntimeArtifactError("runtime_artifact_file_mode_mismatch")
        sha = hashlib.sha256()
        git_hash = hashlib.sha1(f"blob {entry.size}\0".encode("ascii"))
        count = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            count += len(chunk)
            if count > entry.size:
                raise RuntimeArtifactError("runtime_artifact_file_changed")
            sha.update(chunk)
            git_hash.update(chunk)
        after = os.fstat(descriptor)
        snapshot = lambda info: (
            info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns,
        )
        if count != entry.size or snapshot(before) != snapshot(after):
            raise RuntimeArtifactError("runtime_artifact_file_changed")
        return sha.hexdigest(), git_hash.hexdigest()
    except OSError:
        raise RuntimeArtifactError("runtime_artifact_file_unavailable") from None
    finally:
        for descriptor in reversed(handles):
            os.close(descriptor)


def verify_runtime_artifact(
    raw: bytes,
    root: Path,
    trust: ProducerTrust,
    *,
    expected_source_commit: str | None = None,
    expected_source_tree: str | None = None,
) -> VerifiedRuntimeArtifact:
    manifest = _parse_manifest(raw)
    key_id = manifest["producer_key_id"]
    if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
        raise RuntimeArtifactError("runtime_artifact_producer_key_id_invalid")
    if not isinstance(trust, ProducerTrust):
        raise RuntimeArtifactError("runtime_artifact_producer_trust_unavailable")
    trust.validate()
    if key_id != trust.key_id:
        raise RuntimeArtifactError("runtime_artifact_producer_untrusted")
    if manifest["producer_scope"] != trust.producer_scope:
        raise RuntimeArtifactError("runtime_artifact_producer_scope_mismatch")
    signature = _decode_base64(
        manifest["signature"], 64, "runtime_artifact_signature_invalid",
    )
    try:
        Ed25519PublicKey.from_public_bytes(trust.public_key).verify(
            signature, signature_payload(manifest),
        )
    except (InvalidSignature, ValueError):
        raise RuntimeArtifactError("runtime_artifact_signature_invalid") from None
    if manifest["manifest_digest"] != manifest_digest(manifest):
        raise RuntimeArtifactError("runtime_artifact_manifest_digest_mismatch")
    for field in ("source_commit", "source_tree_reference"):
        if not isinstance(manifest[field], str) or not _HEX40.fullmatch(manifest[field]):
            raise RuntimeArtifactError("runtime_artifact_source_invalid")
    if expected_source_commit is not None and manifest["source_commit"] != expected_source_commit:
        raise RuntimeArtifactError("runtime_artifact_source_conflict")
    if expected_source_tree is not None and manifest["source_tree_reference"] != expected_source_tree:
        raise RuntimeArtifactError("runtime_artifact_source_conflict")
    if not isinstance(manifest["manifest_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", manifest["manifest_id"]):
        raise RuntimeArtifactError("runtime_artifact_manifest_id_invalid")
    reference = manifest["build_reference"]
    if reference is not None and (
        not isinstance(reference, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,200}", reference)
    ):
        raise RuntimeArtifactError("runtime_artifact_build_reference_invalid")
    try:
        timestamp = manifest["created_at"]
        parsed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != timestamp or parsed > datetime.now(timezone.utc):
            raise ValueError
    except (TypeError, ValueError):
        raise RuntimeArtifactError("runtime_artifact_timestamp_invalid") from None
    entries = _managed_entries(manifest)
    for entry in entries:
        digest, _git_oid = inspect_managed_file(root, entry)
        if digest != entry.sha256:
            raise RuntimeArtifactError("runtime_artifact_file_digest_mismatch")
    return VerifiedRuntimeArtifact(
        key_id, trust.producer_scope, manifest["source_commit"],
        manifest["source_tree_reference"], manifest["manifest_digest"],
        manifest["managed_set_hash"], manifest["manifest_id"], entries,
    )
