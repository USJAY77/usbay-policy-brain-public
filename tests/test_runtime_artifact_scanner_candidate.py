"""Synthetic regressions for the isolated, unactivated scanner candidate."""
from pathlib import Path
import os

import pytest

from gateway import app as gateway
from security.policy_registry import PolicyRegistryError

pytestmark = pytest.mark.governance


@pytest.mark.parametrize('relative,resolved', [
    ('.pythonlibs/bin/python', '/nix/store/synthetic/python'),
    ('.cache/replit/modules/current', '/nix/store/synthetic/module'),
    ('.config/pulse/repl-runtime', '/tmp/pulse-synthetic'),
    ('.local/skills/artifacts/artifacts', '/replit/cafs/skills/production/synthetic'),
])
def test_platform_paths_do_not_broaden_base_symlink_scope(tmp_path, relative, resolved):
    assert gateway._is_managed_runtime_symlink(
        tmp_path, Path(relative), Path(resolved), set(),
    ) is False


def test_candidate_does_not_infer_public_key_path_aliases():
    assert gateway._is_public_verification_key_path('governance/synthetic_public.key') is True
    assert gateway._is_public_verification_key_path('tmp/source/governance/synthetic_public.key') is False
    assert gateway._is_public_verification_pem_path('tmp/source/keys_runtime/synthetic.pub.pem') is False


def test_descriptor_scan_unavailable_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(gateway, '_RUNTIME_SCAN_DESCRIPTOR_IO_SUPPORTED', False)
    with pytest.raises(PolicyRegistryError, match='^runtime_scan_descriptor_io_unavailable$'):
        next(gateway._runtime_scan_entries(tmp_path, tmp_path.stat()))


@pytest.mark.skipif(not hasattr(os, 'O_DIRECTORY'), reason='POSIX directory descriptors required')
def test_descriptor_read_rejects_replaced_file(tmp_path):
    original = tmp_path / 'synthetic.txt'
    original.write_bytes(b'original synthetic content')
    expected = original.stat()
    replacement = tmp_path / 'replacement.txt'
    replacement.write_bytes(b'replacement synthetic content')
    os.replace(replacement, original)
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(PolicyRegistryError, match='^runtime_scan_source_changed$'):
            gateway._read_runtime_scan_file(descriptor, original.name, expected)
    finally:
        os.close(descriptor)


@pytest.mark.skipif(not hasattr(os, 'O_NOFOLLOW'), reason='POSIX no-follow required')
def test_descriptor_read_rejects_symlink_substitution(tmp_path):
    target = tmp_path / 'synthetic.txt'
    target.write_bytes(b'synthetic only')
    expected = target.stat()
    link = tmp_path / 'link.txt'
    link.symlink_to(target.name)
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(OSError):
            gateway._read_runtime_scan_file(descriptor, link.name, expected)
    finally:
        os.close(descriptor)


def test_public_material_uses_supplied_snapshot_without_reopening():
    class NoReopen:
        def read_text(self, **kwargs):
            raise AssertionError('Unexpected pathname reopen')

        def read_bytes(self):
            raise AssertionError('Unexpected pathname reopen')

    value = NoReopen()
    public = b'PUBLIC KEY synthetic marker'
    assert gateway._is_public_key_artifact(value, data=public) is True
    assert gateway._is_public_key_material_artifact(value, data=public) is True
    assert gateway._is_public_key_artifact(value, data=b'PRIVATE KEY synthetic marker') is False
