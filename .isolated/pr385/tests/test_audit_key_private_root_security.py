from __future__ import annotations

import stat
from pathlib import Path

import pytest

import audit.anchor as audit_anchor
import audit.keys as audit_keys


def _configure_audit_modules(monkeypatch, *, private_root: Path, public_root: Path, registry_root: Path):
    monkeypatch.setenv("USBAY_AUDIT_PRIVATE_KEY_ROOT", str(private_root))
    monkeypatch.setenv("USBAY_AUDIT_PRIVATE_KEY_PATH", str(private_root / "audit_private_key.pem"))
    monkeypatch.setenv("USBAY_AUDIT_PRIVATE_KEY_DIR", str(private_root / "versions"))
    monkeypatch.setenv("USBAY_AUDIT_PUBLIC_KEY_ROOT", str(public_root))
    monkeypatch.setenv("USBAY_AUDIT_PUBLIC_KEY_PATH", str(public_root / "public_key.pem"))
    monkeypatch.setenv("USBAY_AUDIT_PUBLIC_KEY_DIR", str(public_root / "versions"))
    monkeypatch.setenv("USBAY_AUDIT_KEY_REGISTRY_ROOT", str(registry_root))
    monkeypatch.setenv("USBAY_AUDIT_KEY_REGISTRY_PATH", str(registry_root / "key_registry.json"))
    monkeypatch.setattr(audit_anchor, "DEFAULT_PRIVATE_KEY_ROOT", private_root)
    monkeypatch.setattr(audit_anchor, "DEFAULT_PRIVATE_KEY_PATH", private_root / "audit_private_key.pem")
    monkeypatch.setattr(audit_anchor, "DEFAULT_PUBLIC_KEY_PATH", public_root / "public_key.pem")
    monkeypatch.setattr(audit_keys, "DEFAULT_REGISTRY_PATH", registry_root / "key_registry.json")
    monkeypatch.setattr(audit_keys, "DEFAULT_PRIVATE_KEY_PATH", private_root / "audit_private_key.pem")
    monkeypatch.setattr(audit_keys, "DEFAULT_PRIVATE_KEY_DIR", private_root / "versions")
    monkeypatch.setattr(audit_keys, "DEFAULT_PRIVATE_KEY_ROOT", private_root)
    monkeypatch.setattr(audit_keys, "DEFAULT_PUBLIC_KEY_PATH", public_root / "public_key.pem")
    monkeypatch.setattr(audit_keys, "DEFAULT_PUBLIC_KEY_DIR", public_root / "versions")
    monkeypatch.setattr(audit_keys, "DEFAULT_PUBLIC_KEY_ROOT", public_root)
    monkeypatch.setattr(audit_keys, "DEFAULT_REGISTRY_ROOT", registry_root)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def test_private_key_root_created_owner_only(tmp_path: Path, monkeypatch) -> None:
    private_root = tmp_path / "private"
    _configure_audit_modules(
        monkeypatch,
        private_root=private_root,
        public_root=tmp_path / "public",
        registry_root=tmp_path / "registry",
    )

    audit_keys.get_signing_key()

    assert private_root.is_dir()
    assert _mode(private_root) == 0o700
    assert _mode(private_root / "audit_private_key.pem") == 0o600


def test_preexisting_world_writable_private_key_root_blocks(tmp_path: Path, monkeypatch) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir()
    private_root.chmod(0o777)
    _configure_audit_modules(
        monkeypatch,
        private_root=private_root,
        public_root=tmp_path / "public",
        registry_root=tmp_path / "registry",
    )

    with pytest.raises(Exception, match="audit_private_key_root_invalid"):
        audit_keys.get_signing_key()


def test_private_key_root_symlink_blocks(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "target"
    target.mkdir()
    target.chmod(0o700)
    private_root = tmp_path / "private-link"
    try:
        private_root.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unsupported on this platform")
    _configure_audit_modules(
        monkeypatch,
        private_root=private_root,
        public_root=tmp_path / "public",
        registry_root=tmp_path / "registry",
    )

    with pytest.raises(Exception, match="audit_private_key_root_invalid"):
        audit_keys.get_signing_key()


def test_private_key_file_symlink_blocks(tmp_path: Path, monkeypatch) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_key = outside / "audit_private_key.pem"
    outside_key.write_text("not-a-real-key", encoding="utf-8")
    try:
        (private_root / "audit_private_key.pem").symlink_to(outside_key)
    except OSError:
        pytest.skip("symlink creation unsupported on this platform")
    _configure_audit_modules(
        monkeypatch,
        private_root=private_root,
        public_root=tmp_path / "public",
        registry_root=tmp_path / "registry",
    )

    with pytest.raises(Exception, match="audit_private_key_path_invalid"):
        audit_keys.get_signing_key()


def test_explicit_non_tmp_private_key_root_allows_valid_owner_only_root(tmp_path: Path, monkeypatch) -> None:
    private_root = tmp_path / "application-controlled-private"
    private_root.mkdir(mode=0o700)
    _configure_audit_modules(
        monkeypatch,
        private_root=private_root,
        public_root=tmp_path / "public",
        registry_root=tmp_path / "registry",
    )

    signing_key = audit_keys.get_signing_key()

    assert signing_key["private_key"]
    assert _mode(private_root / "audit_private_key.pem") == 0o600
