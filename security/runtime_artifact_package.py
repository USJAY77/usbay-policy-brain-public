"""Build/package boundary. This module is never imported by runtime consumers."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security.runtime_artifact_builder import _git, build_runtime_artifact_manifest
from security.runtime_artifact_authority import MANIFEST_NAME, load_runtime_artifact_authority
from security.runtime_artifact_provenance import (
    ProducerTrust, RuntimeArtifactError, _decode_base64,
)
from cryptography.hazmat.primitives import serialization


def _copy_entry(source: Path, output_root_fd: int, entry: dict) -> None:
    handles = []
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open(source, flags | os.O_DIRECTORY)
        handles.append(descriptor)
        for part in entry["path"].split("/")[:-1]:
            descriptor = os.open(part, flags | os.O_DIRECTORY, dir_fd=descriptor)
            handles.append(descriptor)
        descriptor = os.open(entry["path"].split("/")[-1], flags | os.O_NONBLOCK, dir_fd=descriptor)
        handles.append(descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeArtifactError("runtime_artifact_package_file_invalid")
        output_parent = output_root_fd
        for part in entry["path"].split("/")[:-1]:
            try:
                os.mkdir(part, mode=0o755, dir_fd=output_parent)
            except FileExistsError:
                pass
            output_parent = os.open(part, flags | os.O_DIRECTORY, dir_fd=output_parent)
            handles.append(output_parent)
        output_fd = os.open(
            entry["path"].split("/")[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=output_parent,
        )
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(output_fd, "wb") as output:
            while chunk := os.read(descriptor, 1024 * 1024):
                size += len(chunk)
                if size > entry["size"]:
                    raise RuntimeArtifactError("runtime_artifact_package_source_changed")
                digest.update(chunk)
                output.write(chunk)
            os.fchmod(output.fileno(), 0o755 if entry["mode"] == "100755" else 0o644)
        after = os.fstat(descriptor)
        if (
            size != entry["size"] or digest.hexdigest() != entry["sha256"]
            or (before.st_ino, before.st_size, before.st_mode, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_ino, after.st_size, after.st_mode, after.st_mtime_ns, after.st_ctime_ns)
            or bool(before.st_mode & 0o111) != (entry["mode"] == "100755")
        ):
            raise RuntimeArtifactError("runtime_artifact_package_source_changed")
    except OSError:
        raise RuntimeArtifactError("runtime_artifact_package_io_failed") from None
    finally:
        for descriptor in reversed(handles):
            os.close(descriptor)


def package_runtime_artifact(
    source: Path, destination: Path, *, signing_key: Ed25519PrivateKey | None,
    producer_key_id: str, producer_scope: str, build_reference: str | None = None,
) -> Path:
    """Only a new destination; only HEAD files; publish manifest last.

    No release manifest is fabricated. Runtime retains the independent required
    governance-release/signature/tenant/policy checks.
    """
    source = Path(source).absolute()
    destination = Path(destination).absolute()
    if source.resolve(strict=True) != source or destination.parent.resolve(strict=True) != destination.parent:
        raise RuntimeArtifactError("runtime_artifact_package_path_invalid")
    if destination.exists() or destination.is_symlink():
        raise RuntimeArtifactError("runtime_artifact_package_destination_exists")
    raw = build_runtime_artifact_manifest(
        source, signing_key=signing_key, producer_key_id=producer_key_id,
        producer_scope=producer_scope, build_reference=build_reference,
    )
    manifest = json.loads(raw)
    if any(item["path"] == MANIFEST_NAME for item in manifest["managed_files"]):
        raise RuntimeArtifactError("runtime_artifact_manifest_path_invalid")
    output_root_fd = None
    try:
        destination.mkdir(mode=0o700)
        output_root_fd = os.open(
            destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        for entry in manifest["managed_files"]:
            _copy_entry(source, output_root_fd, entry)
        if (
            _git(source, "rev-parse", "HEAD").decode().strip() != manifest["source_commit"]
            or _git(source, "rev-parse", "HEAD^{tree}").decode().strip() != manifest["source_tree_reference"]
            or _git(source, "status", "--porcelain=v1", "--untracked-files=no")
        ):
            raise RuntimeArtifactError("runtime_artifact_package_source_changed")
        manifest_fd = os.open(
            MANIFEST_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o644, dir_fd=output_root_fd,
        )
        with os.fdopen(manifest_fd, "wb") as stream:
            stream.write(raw)
        public = signing_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        # Build self-check is not runtime trust provisioning; runtime independently
        # loads its public key. Test keys are never promoted to production here.
        load_runtime_artifact_authority(
            destination, trust=ProducerTrust(public, producer_key_id, producer_scope, producer_scope),
        )
    except OSError:
        raise RuntimeArtifactError("runtime_artifact_package_io_failed") from None
    finally:
        if output_root_fd is not None:
            os.close(output_root_fd)
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package a signed USBAY source artifact")
    parser.add_argument("--source", default=".")
    parser.add_argument("--destination", required=True)
    parser.add_argument("--signing-key-file", required=True)
    parser.add_argument("--producer-key-id", required=True)
    parser.add_argument("--producer-scope", choices=("production", "test"), required=True)
    args = parser.parse_args(argv)
    try:
        source = Path(args.source).absolute()
        destination = Path(args.destination).absolute()
        key_path = Path(args.signing_key_file)
        # Explicit external read-only build input; never package a private key.
        if (
            not key_path.is_absolute() or key_path.resolve(strict=True) != key_path
            or key_path.is_relative_to(source) or key_path.is_relative_to(destination)
        ):
            raise RuntimeArtifactError("runtime_artifact_build_key_path_invalid")
        descriptor = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 64:
                raise RuntimeArtifactError("runtime_artifact_build_signing_key_invalid")
            key = _decode_base64(
                stream.read(64).decode("ascii").strip(), 32,
                "runtime_artifact_build_signing_key_invalid",
            )
        package_runtime_artifact(
            source, destination, signing_key=Ed25519PrivateKey.from_private_bytes(key),
            producer_key_id=args.producer_key_id, producer_scope=args.producer_scope,
        )
    except (RuntimeArtifactError, OSError, UnicodeError, ValueError):
        # No path, key, subprocess stderr, or secret material in build output.
        print("runtime_artifact_package_failed", file=sys.stderr)
        return 1
    print("runtime_artifact_package_verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
