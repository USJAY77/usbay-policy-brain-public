"""One signed artifact authority for scanner and deployment provenance.

No Git, signing-key discovery, release issuance, or execution authority lives here.
The cached object is immutable, but freshness is checked at every consumption.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import stat
from threading import RLock

from security.runtime_artifact_provenance import (
    MAX_MANIFEST_BYTES, ProducerTrust, RuntimeArtifactError, VerifiedRuntimeArtifact,
    producer_trust_from_environment, validate_managed_path, verify_runtime_artifact,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_NAME = "runtime_source_manifest.json"
MANAGED_RUNTIME_PATH_PREFIXES = (
    (".cache", "uv"), (".config", ".semgrep"),
    (".config", "replit", ".semgrep"), (".local", "share", "pnpm", "store"),
    (".local", "state", "replit"), (".pythonlibs",), ("node_modules", ".pnpm"),
)
RUNTIME_SCAN_EXCLUDED_DIRS = frozenset({
    ".githooks", ".github", ".pytest_cache", ".venv", "__pycache__", "docs",
    "demos", "tests", "tools", "usbay_policy_brain.egg-info", "venv",
})
_SEAL = object()
_runtime_authority = None
_authority_lock = RLock()


def artifact_runtime_required(root: Path | None = None) -> bool:
    """Production/explicit packaged mode never falls back to Git on failure."""
    root = REPO_ROOT if root is None else root
    modes = (os.getenv("USBAY_ENV", ""), os.getenv("USBAY_ENVIRONMENT", ""))
    return (
        any(mode.strip().lower() in {"prod", "production"} for mode in modes)
        or bool(os.getenv("USBAY_RUNTIME_SOURCE_MANIFEST"))
        or not (Path(root) / ".git").is_dir()
    )


def _fingerprint(path: Path) -> tuple:
    try:
        info = path.lstat()
    except OSError:
        raise RuntimeArtifactError("runtime_artifact_state_unavailable") from None
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns,
    )


def _read_manifest(path: Path) -> bytes:
    try:
        if path.parent.resolve(strict=True) != path.parent:
            raise RuntimeArtifactError("runtime_artifact_manifest_path_invalid")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise RuntimeArtifactError("runtime_artifact_manifest_file_invalid")
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
    except OSError:
        raise RuntimeArtifactError("runtime_artifact_manifest_unavailable") from None
    if len(raw) > MAX_MANIFEST_BYTES:
        raise RuntimeArtifactError("runtime_artifact_manifest_size_invalid")
    return raw


def _check_inventory(root: Path, verified: VerifiedRuntimeArtifact, manifest_name: str) -> tuple:
    """Reject extra governed files without excluding them from the old scanner.

    Existing scanner exclusions and platform-managed dependency prefixes stay
    unchanged. tmp is existing mutable runtime state: it is NOT exempted from
    forbidden-material, symlink, traversal or read-failure scanning.
    """
    expected = {entry.path for entry in verified.managed_files}
    failures = []
    symlinks = []
    for directory, names, files in os.walk(root, followlinks=False, onerror=failures.append):
        for name in [*names, *files]:
            path = Path(directory) / name
            relative = path.relative_to(root)
            parts = relative.parts
            if parts[0] == ".git":
                continue
            validate_managed_path(relative.as_posix())
            mode = _fingerprint(path)[2]
            if stat.S_ISLNK(mode):
                # Existing scanner handles platform-managed symlink exceptions.
                # A declared file is independently rejected by the verifier.
                symlinks.append((relative.as_posix(), _fingerprint(path)))
                continue
            if stat.S_ISDIR(mode):
                continue
            if relative.as_posix() in expected or relative.as_posix() == manifest_name:
                continue
            if (
                parts[0] == "tmp"
                or any(part in RUNTIME_SCAN_EXCLUDED_DIRS for part in parts)
                or any(parts[:len(prefix)] == prefix for prefix in MANAGED_RUNTIME_PATH_PREFIXES)
            ):
                continue
            raise RuntimeArtifactError("runtime_artifact_unexpected_governed_file")
        names[:] = [name for name in names if name != ".git"]
    if failures:
        raise RuntimeArtifactError("runtime_artifact_traversal_failed")
    return tuple(sorted(symlinks))


@dataclass(frozen=True)
class RuntimeArtifactAuthority:
    root: Path
    manifest_path: Path
    verified: VerifiedRuntimeArtifact
    verification_reference: str
    _trust: ProducerTrust = field(repr=False)
    _raw_hash: str = field(repr=False)
    _states: tuple = field(repr=False)
    _symlinks: tuple = field(repr=False)
    _seal: object = field(repr=False, compare=False)

    def assert_fresh(self) -> "RuntimeArtifactAuthority":
        if self._seal is not _SEAL:
            raise RuntimeArtifactError("runtime_artifact_authority_unverified")
        paths = (self.manifest_path, *(self.root / item.path for item in self.verified.managed_files))
        if tuple(_fingerprint(path) for path in paths) != self._states:
            raise RuntimeArtifactError("runtime_artifact_state_changed")
        raw = _read_manifest(self.manifest_path)
        if hashlib.sha256(raw).hexdigest() != self._raw_hash:
            raise RuntimeArtifactError("runtime_artifact_state_changed")
        result = verify_runtime_artifact(raw, self.root, self._trust)
        if result != self.verified:
            raise RuntimeArtifactError("runtime_artifact_authority_mismatch")
        symlinks = _check_inventory(self.root, result, self.manifest_path.relative_to(self.root).as_posix())
        if symlinks != self._symlinks:
            raise RuntimeArtifactError("runtime_artifact_state_changed")
        if tuple(_fingerprint(path) for path in paths) != self._states:
            raise RuntimeArtifactError("runtime_artifact_state_changed")
        return self


def load_runtime_artifact_authority(
    root: Path, *, trust: ProducerTrust | None = None,
    manifest_name: str = MANIFEST_NAME,
) -> RuntimeArtifactAuthority:
    root = Path(root).absolute()
    if root.resolve(strict=True) != root:
        raise RuntimeArtifactError("runtime_artifact_root_invalid")
    validate_managed_path(manifest_name)
    configured_trust = trust if trust is not None else producer_trust_from_environment()
    path = root / manifest_name
    before = _fingerprint(path)
    raw = _read_manifest(path)
    verified = verify_runtime_artifact(raw, root, configured_trust)
    if before != _fingerprint(path):
        raise RuntimeArtifactError("runtime_artifact_state_changed")
    if manifest_name in {entry.path for entry in verified.managed_files}:
        raise RuntimeArtifactError("runtime_artifact_manifest_path_invalid")
    paths = (path, *(root / item.path for item in verified.managed_files))
    states = tuple(_fingerprint(item) for item in paths)
    authority = RuntimeArtifactAuthority(
        root, path, verified, "sha256:" + verified.manifest_digest,
        configured_trust, hashlib.sha256(raw).hexdigest(), states,
        _check_inventory(root, verified, manifest_name), _SEAL,
    )
    return authority.assert_fresh()


def get_runtime_artifact_authority(root: Path | None = None) -> RuntimeArtifactAuthority:
    """A single process authority; config/source changes are not silently reloaded."""
    global _runtime_authority
    root = REPO_ROOT if root is None else root
    trust = producer_trust_from_environment()
    name = os.getenv("USBAY_RUNTIME_SOURCE_MANIFEST", MANIFEST_NAME)
    validate_managed_path(name)
    with _authority_lock:
        if _runtime_authority is None:
            _runtime_authority = load_runtime_artifact_authority(root, trust=trust, manifest_name=name)
        authority = _runtime_authority
    if (
        authority.root != Path(root).absolute() or authority._trust != trust
        or authority.manifest_path != Path(root).absolute() / name
    ):
        raise RuntimeArtifactError("runtime_artifact_authority_configuration_changed")
    return authority.assert_fresh()
