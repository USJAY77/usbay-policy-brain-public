"""Offline non-production evidence verification; never execution authorization.

Reuses the existing pinned producer trust and signed artifact inventory. A signed
companion file binds patch bytes and observed interpreter/dependency metadata.
No key, trust, manifest, package, application process or deployment is created here.

An optional isolated Git check verifies patch application and full source content.
This does not verify import resolution, OCI image identity,
release/tenant authority or lifetime currentness. The result stays PARTIAL.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from importlib import metadata
import os
from pathlib import Path
import platform
import re
import stat
import sys
import sysconfig

from security.runtime_artifact_authority import load_runtime_artifact_authority
from security.runtime_artifact_provenance import (
    ProducerTrust, RuntimeArtifactError, canonical_bytes,
    _pairs_without_duplicates, _reject_constant,
)
import json

from security.runtime_source_overlay import SourceOverlayProof, verify_source_overlay

EVIDENCE_NAME = "runtime_validation_evidence.json"
SCHEMA = "usbay.non_production_runtime_validation_evidence.v1"
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)\Z")
_HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}\Z")


def _require(condition, code="runtime_validation_evidence_invalid"):
    if not condition:
        raise RuntimeArtifactError(code)


@dataclass(frozen=True)
class CandidateBinding:
    source_commit: str
    source_tree: str
    base_commit: str
    base_tree: str
    patch_sha256: str

    def validate(self):
        _require(set(vars(self)) == {"source_commit", "source_tree", "base_commit", "base_tree", "patch_sha256"})
        for name, value in vars(self).items():
            pattern = _SHA if name == "patch_sha256" else _COMMIT
            _require(type(value) is str and pattern.fullmatch(value) is not None)


@dataclass(frozen=True)
class RuntimeValidationEvidence:
    artifact_reference: str
    evidence_sha256: str
    patch_sha256: str
    python_observation_sha256: str
    dependency_inventory_sha256: str
    lock_sha256: str
    # These are explicit limits, not options a caller can enable.
    status: str = field(default="EVIDENCE_VERIFIED_PARTIAL", init=False)
    execution_authorized: bool = field(default=False, init=False)
    runtime_equivalence_proven: bool = field(default=False, init=False)
    _source_overlay_proof: SourceOverlayProof | None = field(default=None, repr=False)
    image_identity_verified: bool = field(default=False, init=False)

    @property
    def patch_application_verified(self):
        return (type(self._source_overlay_proof) is SourceOverlayProof
                and self._source_overlay_proof.verified)


def _snapshot(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _read_entry(root, entry):
    """Read one signed managed entry without following any path symlink."""
    _require(entry.size <= MAX_EVIDENCE_BYTES, "runtime_validation_evidence_size_invalid")
    handles = []
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(root, flags | os.O_DIRECTORY)
        handles.append(fd)
        parts = entry.path.split("/")
        for part in parts[:-1]:
            fd = os.open(part, flags | os.O_DIRECTORY, dir_fd=fd)
            handles.append(fd)
        fd = os.open(parts[-1], flags | os.O_NONBLOCK, dir_fd=fd)
        handles.append(fd)
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode), "runtime_validation_evidence_file_invalid")
        chunks, size = [], 0
        while chunk := os.read(fd, 65536):
            size += len(chunk)
            _require(size <= entry.size, "runtime_validation_evidence_changed")
            chunks.append(chunk)
        raw = b"".join(chunks)
        _require(size == entry.size and _snapshot(before) == _snapshot(os.fstat(fd))
                 and hashlib.sha256(raw).hexdigest() == entry.sha256,
                 "runtime_validation_evidence_changed")
        return raw
    except OSError:
        raise RuntimeArtifactError("runtime_validation_evidence_unavailable") from None
    finally:
        for fd in reversed(handles):
            os.close(fd)


def _python_observation():
    path = Path(sys.executable).resolve(strict=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_BINARY_BYTES)
        digest, size = hashlib.sha256(), 0
        while chunk := os.read(fd, 65536):
            size += len(chunk)
            _require(size <= MAX_BINARY_BYTES)
            digest.update(chunk)
        _require(size == before.st_size and _snapshot(before) == _snapshot(os.fstat(fd)),
                 "runtime_validation_python_changed")
    finally:
        os.close(fd)
    return {
        "implementation": sys.implementation.name, "version": platform.python_version(),
        "cache_tag": sys.implementation.cache_tag, "compiler": platform.python_compiler(),
        "build": list(platform.python_build()), "executable_sha256": digest.hexdigest(),
    }


def _name(value):
    _require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value))
    return re.sub(r"[-_.]+", "-", value).lower()


def _dependency_observation():
    """Inventory only this interpreter's configured site-packages.

    This is metadata parity, not verification of imported package bytes or of
    every sys.path/PYTHONPATH entry. It cannot establish runtime equivalence.
    """
    paths = sorted({sysconfig.get_paths()[key] for key in ("purelib", "platlib")})
    found = {}
    for dist in metadata.distributions(path=paths):
        name = _name(dist.metadata["Name"])
        _require(name not in found, "runtime_validation_dependency_duplicate")
        _require(type(dist.version) is str and bool(dist.version))
        found[name] = dist.version
        _require(len(found) <= 10000)
    return found


def _locked_versions(raw):
    """Accept the repository's exact, hash-locked requirements grammar only."""
    try:
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except UnicodeError:
        raise RuntimeArtifactError("runtime_validation_lock_invalid") from None
    pins, current, hashes = {}, None, 0
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            line = line[:-1].rstrip()
        if _HASH.fullmatch(line):
            _require(current is not None, "runtime_validation_lock_invalid")
            hashes += 1
            continue
        match = _PIN.fullmatch(line)
        _require(match is not None and (current is None or hashes > 0),
                 "runtime_validation_lock_invalid")
        name = _name(match[1])
        _require(name not in pins, "runtime_validation_lock_invalid")
        pins[name] = match[2]
        current, hashes = name, 0
    _require(bool(pins) and hashes > 0, "runtime_validation_lock_invalid")
    return pins


def verify_runtime_validation_evidence(root: Path, *, trust: ProducerTrust,
                                       expected: CandidateBinding,
                                       reference_repository: Path | None = None) -> RuntimeValidationEvidence:
    """Verify signed evidence against actual observations, with no ALLOW result.

    Expected candidate identifiers are comparison constraints, never authority.
    The companion, patch and lock must all be declared in the existing signed
    artifact. Production trust is intentionally outside this offline boundary.
    """
    try:
        _require(type(trust) is ProducerTrust
                 and trust.mode == "test" and trust.producer_scope == "test",
                 "runtime_validation_non_production_only")
        _require(type(expected) is CandidateBinding)
        expected.validate()
        authority = load_runtime_artifact_authority(root, trust=trust)
        _require(authority.verified.source_commit == expected.source_commit
                 and authority.verified.source_tree_reference == expected.source_tree,
                 "runtime_validation_candidate_mismatch")
        entries = {item.path: item for item in authority.verified.managed_files}
        _require(EVIDENCE_NAME in entries, "runtime_validation_evidence_not_managed")
        raw = _read_entry(authority.root, entries[EVIDENCE_NAME])
        data = json.loads(raw.decode("utf-8", errors="strict"),
                          object_pairs_hook=_pairs_without_duplicates,
                          parse_constant=_reject_constant)
        _require(type(data) is dict and set(data) == {
            "schema_version", "candidate", "patch_path", "lock_path", "lock_sha256",
            "python", "distributions", "image_digest"})
        _require(data["schema_version"] == SCHEMA)
        _require(type(data["candidate"]) is dict
                 and canonical_bytes(data["candidate"]) == canonical_bytes(vars(expected)),
                 "runtime_validation_candidate_mismatch")
        for key in ("patch_path", "lock_path"):
            _require(type(data[key]) is str and data[key] in entries,
                     "runtime_validation_evidence_not_managed")
        _require(len({EVIDENCE_NAME, data["patch_path"], data["lock_path"]}) == 3)
        patch = _read_entry(authority.root, entries[data["patch_path"]])
        _require(hashlib.sha256(patch).hexdigest() == expected.patch_sha256,
                 "runtime_validation_patch_mismatch")
        lock = _read_entry(authority.root, entries[data["lock_path"]])
        _require(hashlib.sha256(lock).hexdigest() == data["lock_sha256"],
                 "runtime_validation_lock_mismatch")
        python = _python_observation()
        _require(canonical_bytes(data["python"]) == canonical_bytes(python),
                 "runtime_validation_python_mismatch")
        observed = _dependency_observation()
        _require(type(data["distributions"]) is dict
                 and canonical_bytes(data["distributions"]) == canonical_bytes(observed)
                 and _locked_versions(lock) == observed,
                 "runtime_validation_dependencies_mismatch")
        image = data["image_digest"]
        _require(image is None or (type(image) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", image)))
        # No platform observer exists here: even a signed image string is only a
        # claim. Neither it nor this successful evidence check permits execution.
        overlay = None
        if reference_repository is not None:
            overlay = verify_source_overlay(
                reference_repository, authority.root, expected=expected, patch=patch,
                managed_files=authority.verified.managed_files,
                metadata_paths=(EVIDENCE_NAME, data["patch_path"], data["lock_path"]))
        authority.assert_fresh()
        return RuntimeValidationEvidence(
            authority.verification_reference, hashlib.sha256(raw).hexdigest(),
            expected.patch_sha256, hashlib.sha256(canonical_bytes(python)).hexdigest(),
            hashlib.sha256(canonical_bytes(observed)).hexdigest(), data["lock_sha256"], overlay)
    except RuntimeArtifactError:
        raise
    except Exception:
        raise RuntimeArtifactError("runtime_validation_evidence_invalid") from None
