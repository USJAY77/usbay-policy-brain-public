"""Legacy source-tree claims cannot replace a verifiable signed binding."""
import json
from pathlib import Path
import tempfile
import unittest

from audit.export_input_contract import PACKAGE_FILES, ExportInputError, inspect_preissued_package


class LegacySourceBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.package = Path(self.temporary.name)
        for name in PACKAGE_FILES:
            raw = b'{}' if name.endswith('.json') else b''
            (self.package / name).write_bytes(raw)
        self.release = {'tenant_id': 'tenant-A', 'git_commit': '6' * 40}
        self.manifest = {**self.release, 'format': 'USBAY_TENANT_AUDIT_PACKAGE_V1',
                         'package_hash': 'a' * 64}
        (self.package / 'tenant_context.json').write_text(json.dumps({'tenant_id': 'tenant-A'}))

    def assert_legacy_denied(self):
        (self.package / 'governance_release.json').write_text(json.dumps(self.release))
        (self.package / 'verification_manifest.json').write_text(json.dumps(self.manifest))
        before = {p.name: p.read_bytes() for p in self.package.iterdir()}
        with self.assertRaises(ExportInputError) as raised:
            inspect_preissued_package(self.package, tenant_id='tenant-A',
                source_commit='6' * 40, source_tree='7' * 40, package_hash='a' * 64)
        self.assertEqual(str(raised.exception), 'EXPORT_SOURCE_TREE_BINDING_UNAVAILABLE')
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.package.iterdir()})

    def test_legacy_without_signed_tree_is_denied(self):
        self.assert_legacy_denied()

    def test_same_commit_different_tree_is_denied(self):
        self.release['source_tree'] = self.manifest['source_tree'] = '8' * 40
        self.assert_legacy_denied()

    def test_injected_matching_tree_and_verified_claim_are_not_authority(self):
        self.release['source_tree'] = self.manifest['source_tree'] = '7' * 40
        self.manifest['verified'] = True
        (self.package / 'package_signature.json').write_text(json.dumps({
            'source_tree': '7' * 40, 'verified': True, 'signature': 'caller-claim'}))
        self.assert_legacy_denied()


if __name__ == '__main__': unittest.main()
