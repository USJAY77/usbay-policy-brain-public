"""Build-only signing API. Never import this module in the runtime verifier.

The caller supplies producer signing material explicitly. No key is discovered,
generated, defaulted, read from environment, or written to disk here.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import subprocess
from uuid import uuid4
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security.runtime_artifact_provenance import (
    MANIFEST_SCHEMA, PRODUCER_CONTRACT, MAX_MANAGED_FILES, MAX_FILE_BYTES,
    ManagedFile, RuntimeArtifactError, canonical_bytes, inspect_managed_file,
    manifest_digest, public_key_id, signature_payload, validate_managed_path,
)


def _git(root: Path, *arguments: str) -> bytes:
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    environment.update(GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments], check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeArtifactError("runtime_artifact_build_git_unavailable") from None
    if result.returncode:
        raise RuntimeArtifactError("runtime_artifact_build_git_unavailable")
    return result.stdout


def build_runtime_artifact_manifest(
    root: Path,
    *,
    signing_key: Ed25519PrivateKey | None,
    producer_key_id: str,
    producer_scope: str,
    build_reference: str | None = None,
) -> bytes:
    """Bind every regular tracked HEAD path, without omission, to Ed25519.

    Symlinks/submodules/dirty tracked files are unsupported and rejected. Ignored
    and untracked files are NOT declared managed; existing runtime scans must
    continue examining them. This function neither packages nor uploads files.
    """
    if signing_key is None:
        raise RuntimeArtifactError("runtime_artifact_build_signing_key_unavailable")
    if not isinstance(signing_key, Ed25519PrivateKey):
        raise RuntimeArtifactError("runtime_artifact_build_signing_key_invalid")
    public = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    if producer_key_id != public_key_id(public):
        raise RuntimeArtifactError("runtime_artifact_producer_key_id_mismatch")
    if not isinstance(producer_scope, str) or producer_scope not in {"production", "test"}:
        raise RuntimeArtifactError("runtime_artifact_producer_scope_invalid")
    try:
        root = Path(root).resolve(strict=True)
    except OSError:
        raise RuntimeArtifactError("runtime_artifact_root_invalid") from None
    identity = _git(root, "rev-parse", "--show-toplevel", "--absolute-git-dir", "HEAD", "HEAD^{tree}")
    try:
        lines = identity.decode("utf-8", errors="strict").splitlines()
        if (
            len(lines) != 4 or Path(lines[0]).resolve() != root
            or Path(lines[1]).resolve() != root / ".git"
            or not (root / ".git").is_dir() or (root / ".git").is_symlink()
        ):
            raise ValueError
    except (ValueError, UnicodeError):
        raise RuntimeArtifactError("runtime_artifact_build_identity_invalid") from None
    if _git(root, "status", "--porcelain=v1", "--untracked-files=no"):
        raise RuntimeArtifactError("runtime_artifact_build_source_dirty")
    inventory = _git(root, "ls-tree", "-r", "-l", "-z", "HEAD")
    entries: list[dict] = []
    for item in inventory.split(b"\0"):
        if not item:
            continue
        try:
            metadata, raw_path = item.split(b"\t", 1)
            mode, kind, oid, size = metadata.decode("ascii").split()
            path = validate_managed_path(raw_path.decode("utf-8", errors="strict"))
            if mode not in {"100644", "100755"} or kind != "blob":
                raise RuntimeArtifactError("runtime_artifact_build_file_type_invalid")
            declared_size = int(size)
            if not 0 <= declared_size <= MAX_FILE_BYTES:
                raise ValueError
        except (ValueError, UnicodeError):
            raise RuntimeArtifactError("runtime_artifact_build_inventory_invalid") from None
        entry = ManagedFile(path, mode, "", declared_size)
        digest, actual_oid = inspect_managed_file(root, entry)
        if actual_oid != oid:
            raise RuntimeArtifactError("runtime_artifact_build_source_mismatch")
        entries.append(ManagedFile(path, mode, digest, declared_size).as_dict())
        if len(entries) > MAX_MANAGED_FILES:
            raise RuntimeArtifactError("runtime_artifact_managed_set_invalid")
    if not entries:
        raise RuntimeArtifactError("runtime_artifact_managed_set_invalid")
    entries.sort(key=lambda entry: entry["path"])
    if (
        _git(root, "rev-parse", "--show-toplevel", "--absolute-git-dir", "HEAD", "HEAD^{tree}") != identity
        or _git(root, "ls-tree", "-r", "-l", "-z", "HEAD") != inventory
        or _git(root, "status", "--porcelain=v1", "--untracked-files=no")
    ):
        raise RuntimeArtifactError("runtime_artifact_build_source_changed")
    # Re-read every file after the Git snapshot checks to catch ordinary mutation.
    for raw in entries:
        entry = ManagedFile(**raw)
        if inspect_managed_file(root, entry)[0] != entry.sha256:
            raise RuntimeArtifactError("runtime_artifact_build_source_changed")
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "producer_contract": PRODUCER_CONTRACT,
        "producer_key_id": producer_key_id,
        "producer_scope": producer_scope,
        "source_commit": lines[2],
        "source_tree_reference": lines[3],
        "managed_files": entries,
        "managed_set_hash": hashlib.sha256(canonical_bytes(entries)).hexdigest(),
        "build_reference": build_reference,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "manifest_id": uuid4().hex,
    }
    manifest["manifest_digest"] = manifest_digest(manifest)
    manifest["signature"] = base64.b64encode(signing_key.sign(signature_payload(manifest))).decode("ascii")
    return canonical_bytes(manifest)
