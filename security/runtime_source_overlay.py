"""Offline source-overlay checking using a disposable Git object store/index.

No checkout, commit, hook, filter, package, signer or application is invoked.
The reference repository is read only; all new Git objects are temporary.
This verifies source reconstruction, not permission or runtime/image identity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import tempfile
import time

from security.runtime_artifact_provenance import (
    RuntimeArtifactError, canonical_bytes, inspect_managed_file, validate_managed_path,
)

_MAX_OUTPUT = 16 * 1024 * 1024
_MAX_PATCH = 4 * 1024 * 1024
_MAX_OBJECT = 64 * 1024 * 1024
_MAX_REFERENCE_BYTES = 512 * 1024 * 1024
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_SEAL = object()


def _require(value, code="runtime_overlay_invalid"):
    if not value:
        raise RuntimeArtifactError(code)


@dataclass(frozen=True)
class SourceOverlayProof:
    base_commit: str
    base_tree: str
    patch_sha256: str
    resulting_tree: str
    source_inventory_sha256: str
    source_file_count: int
    _seal: object = field(repr=False, compare=False)

    @property
    def verified(self):
        return self._seal is _SEAL


def _environment():
    # No inherited Git overrides, credential helpers, application secrets or
    # signing material. These commands never contact a remote.
    return {
        "PATH": os.defpath, "LC_ALL": "C", "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_COUNT": "0",
        "GIT_ATTR_NOSYSTEM": "1", "GIT_NO_LAZY_FETCH": "1",
        "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
        "GIT_ALLOW_PROTOCOL": "", "GIT_PROTOCOL_FROM_USER": "0",
    }


def _git(executable, cwd, args, environment, *, data=None):
    try:
        result = subprocess.run(
            [executable, "-c", "core.hooksPath=" + os.devnull,
             "-c", "core.fsmonitor=false", *args],
            cwd=cwd, env=environment, input=data, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeArtifactError("runtime_overlay_git_unavailable") from None
    _require(result.returncode == 0, "runtime_overlay_git_rejected")
    _require(len(result.stdout) <= _MAX_OUTPUT, "runtime_overlay_inventory_too_large")
    return result.stdout


def _tree_entries(raw):
    entries = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode, kind, oid, size = metadata.decode("ascii", errors="strict").split()
        name = validate_managed_path(path.decode("utf-8", errors="strict"))
        _require(mode in {"100644", "100755"} and kind == "blob"
                 and _HEX40.fullmatch(oid) and size.isdecimal(),
                 "runtime_overlay_unsupported_file")
        _require(name not in entries, "runtime_overlay_inventory_invalid")
        entries[name] = (mode, oid, int(size))
        _require(len(entries) <= 100000, "runtime_overlay_inventory_too_large")
    _require(bool(entries), "runtime_overlay_inventory_invalid")
    return entries


def _verify_reference_objects(executable, cwd, environment, objects):
    """Do not assume Git recomputes object hashes while applying a patch.

    Verify every referenced base commit/tree/blob in a single bounded batch.
    Corrupt loose objects can otherwise change the patch preimage while still
    being addressed by their old object filename. No object content is logged.
    """
    process = None
    try:
        process = subprocess.Popen(
            [executable, "cat-file", "--batch"], cwd=cwd, env=environment,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0)
        deadline = time.monotonic() + 30
        buffer = bytearray()
        total = 0
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)

            def fill():
                remaining = deadline - time.monotonic()
                _require(remaining > 0 and selector.select(remaining),
                         "runtime_overlay_git_timeout")
                chunk = os.read(process.stdout.fileno(), 65536)
                _require(bool(chunk), "runtime_overlay_object_invalid")
                buffer.extend(chunk)

            def take(size):
                while len(buffer) < size:
                    fill()
                value = bytes(buffer[:size])
                del buffer[:size]
                return value

            for oid, kind in sorted(objects.items()):
                process.stdin.write(oid.encode("ascii") + b"\n")
                while b"\n" not in buffer:
                    _require(len(buffer) < 160, "runtime_overlay_object_invalid")
                    fill()
                length = buffer.index(10)
                _require(length < 160, "runtime_overlay_object_invalid")
                header = take(length + 1)[:-1].decode("ascii").split()
                _require(len(header) == 3 and header[:2] == [oid, kind]
                         and header[2].isdecimal(), "runtime_overlay_object_invalid")
                size = int(header[2])
                total += size
                _require(size <= _MAX_OBJECT and total <= _MAX_REFERENCE_BYTES,
                         "runtime_overlay_reference_too_large")
                digest = hashlib.sha1(kind.encode() + b" " + str(size).encode() + b"\0")
                remaining = size
                while remaining:
                    count = min(remaining, 65536)
                    digest.update(take(count))
                    remaining -= count
                _require(take(1) == b"\n" and digest.hexdigest() == oid,
                         "runtime_overlay_object_digest_mismatch")
        process.stdin.close()
        _require(process.wait(timeout=max(0.01, deadline-time.monotonic())) == 0,
                 "runtime_overlay_object_invalid")
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeArtifactError("runtime_overlay_git_unavailable") from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stdout.close()
            if not process.stdin.closed:
                process.stdin.close()


def verify_source_overlay(reference_repository: Path, artifact_root: Path, *,
                          expected, patch: bytes, managed_files,
                          metadata_paths: tuple[str, ...]) -> SourceOverlayProof:
    """Reconstruct base+patch and compare every source path/mode/blob/size.

    The caller must FIRST authenticate the artifact and metadata with existing
    producer trust. Expected identifiers are constraints, never authorization.
    Source commit denotes the base commit for this explicit uncommitted overlay;
    source_tree denotes its reconstructed result. No dirty builder is enabled.
    """
    try:
        expected.validate()
        _require(expected.source_commit == expected.base_commit,
                 "runtime_overlay_base_commit_mismatch")
        _require(type(patch) is bytes and 0 < len(patch) <= _MAX_PATCH)
        _require(hashlib.sha256(patch).hexdigest() == expected.patch_sha256,
                 "runtime_overlay_patch_mismatch")
        reference = Path(reference_repository).absolute()
        _require(reference.resolve(strict=True) == reference and reference.is_dir(),
                 "runtime_overlay_reference_invalid")
        executable = shutil.which("git", path=os.defpath)
        _require(executable is not None, "runtime_overlay_git_unavailable")
        environment = _environment()
        common = _git(executable, reference,
                      ["rev-parse", "--path-format=absolute", "--git-common-dir"], environment)
        objects = Path(os.fsdecode(common.rstrip(b"\n"))) / "objects"
        _require(objects.is_dir() and objects.resolve(strict=True) == objects
                 and all(char not in str(objects) for char in (os.pathsep, "\n", "\r", '"', '\\')),
                 "runtime_overlay_reference_invalid")
        with tempfile.TemporaryDirectory(prefix="usbay-overlay-") as directory:
            temporary = Path(directory)
            bare = temporary / "source.git"
            _git(executable, temporary, ["init", "--bare", "--quiet", "--template=", str(bare)], environment)
            isolated = dict(environment, GIT_DIR=str(bare),
                            GIT_INDEX_FILE=str(temporary / "overlay.index"),
                            GIT_ALTERNATE_OBJECT_DIRECTORIES=str(objects))
            base_tree = _git(executable, temporary,
                ["rev-parse", "--verify", expected.base_commit + "^{tree}"], isolated).decode("ascii").strip()
            _require(base_tree == expected.base_tree, "runtime_overlay_base_tree_mismatch")
            objects = {expected.base_commit: "commit", base_tree: "tree"}
            records = _git(executable, temporary,
                           ["ls-tree", "-r", "-t", "-z", base_tree], isolated)
            for record in records.split(b"\0"):
                if not record:
                    continue
                mode, kind, oid = record.split(b"\t", 1)[0].decode("ascii").split()
                _require(mode in {"040000", "100644", "100755"}
                         and kind in {"tree", "blob"} and _HEX40.fullmatch(oid),
                         "runtime_overlay_unsupported_file")
                _require(oid not in objects or objects[oid] == kind,
                         "runtime_overlay_object_invalid")
                objects[oid] = kind
                _require(len(objects) <= 100002, "runtime_overlay_inventory_too_large")
            _verify_reference_objects(executable, temporary, isolated, objects)
            _git(executable, temporary, ["read-tree", expected.base_commit], isolated)
            _git(executable, temporary, ["apply", "--cached", "--binary", "--whitespace=nowarn", "-"],
                 isolated, data=patch)
            tree = _git(executable, temporary, ["write-tree"], isolated).decode("ascii").strip()
            _require(tree == expected.source_tree, "runtime_overlay_result_tree_mismatch")
            expected_entries = _tree_entries(_git(executable, temporary,
                ["ls-tree", "-r", "-l", "-z", tree], isolated))
            declared = {item.path: item for item in managed_files}
            _require(len(declared) == len(managed_files), "runtime_overlay_inventory_invalid")
            _require(type(metadata_paths) is tuple and len(metadata_paths) == 3
                     and len(set(metadata_paths)) == 3, "runtime_overlay_metadata_invalid")
            for name in metadata_paths:
                validate_managed_path(name)
            extras = set(declared) - set(expected_entries)
            # Only the three exact authenticated companion/patch/lock paths may
            # be supplemental metadata. A tracked lock remains a source file.
            _require(extras == set(metadata_paths) - set(expected_entries)
                     and set(expected_entries) <= set(declared),
                     "runtime_overlay_source_inventory_mismatch")
            inventory = []
            for name, (mode, oid, size) in sorted(expected_entries.items()):
                entry = declared[name]
                _require(entry.mode == mode and entry.size == size,
                         "runtime_overlay_source_inventory_mismatch")
                digest, actual_oid = inspect_managed_file(artifact_root, entry)
                _require(digest == entry.sha256 and actual_oid == oid,
                         "runtime_overlay_source_content_mismatch")
                inventory.append({"path": name, "mode": mode, "oid": oid, "size": size})
            return SourceOverlayProof(expected.base_commit, base_tree, expected.patch_sha256,
                                      tree, hashlib.sha256(canonical_bytes(inventory)).hexdigest(),
                                      len(inventory), _SEAL)
    except RuntimeArtifactError:
        raise
    except Exception:
        raise RuntimeArtifactError("runtime_overlay_invalid") from None
