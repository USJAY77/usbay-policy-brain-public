"""Native-only synthetic verifier cases. Import only after all containment gates.

Private test keys live in memory only. Public fixtures never grant product,
provider, issuer, deployment or execution authority. No live files are used.
"""
import base64
import dataclasses
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from security import runtime_artifact_provenance as p
from security import runtime_artifact_authority as a
from runtime_artifact_contract import CASE_NAMES, SCHEMA


class RuntimeArtifactCases(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='runtime-verifier-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / 'package'
        self.root.mkdir()
        self.file = self.root / 'application.py'
        self.file.write_bytes(b'# synthetic application\n')
        self.file.chmod(0o644)
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.trust = p.ProducerTrust(self.public, p.public_key_id(self.public), 'test', 'test')
        entries = [{'path': 'application.py', 'mode': '100644',
                    'sha256': hashlib.sha256(self.file.read_bytes()).hexdigest(),
                    'size': self.file.stat().st_size}]
        self.manifest = {'schema_version': p.MANIFEST_SCHEMA, 'producer_contract': p.PRODUCER_CONTRACT,
                         'producer_key_id': self.trust.key_id, 'producer_scope': 'test',
                         'source_commit': 'a'*40, 'source_tree_reference': 'b'*40,
                         'managed_files': entries, 'managed_set_hash': hashlib.sha256(p.canonical_bytes(entries)).hexdigest(),
                         'build_reference': None, 'created_at': '2026-01-01T00:00:00Z',
                         'manifest_id': 'c'*32}
        self.sign()

    def sign(self):
        self.manifest['manifest_digest'] = p.manifest_digest(self.manifest)
        self.manifest['signature'] = base64.b64encode(self.key.sign(p.signature_payload(self.manifest))).decode('ascii')

    def raw(self):
        return p.canonical_bytes(self.manifest)

    def verify(self, **kwargs):
        return p.verify_runtime_artifact(self.raw(), self.root, self.trust, **kwargs)

    def load(self):
        (self.root / a.MANIFEST_NAME).write_bytes(self.raw())
        return a.load_runtime_artifact_authority(self.root, trust=self.trust)

    def reject(self, operation, code):
        with self.assertRaises(p.RuntimeArtifactError) as raised:
            operation()
        self.assertEqual(str(raised.exception), code)

    def test_valid_signature(self):
        value = self.verify(expected_source_commit='a'*40, expected_source_tree='b'*40)
        self.assertEqual(value.source_commit, 'a'*40)
        self.assertIs(self.load().assert_fresh().verified.__class__, p.VerifiedRuntimeArtifact)
        self.assertFalse(hasattr(value, 'execution_authorized'))

    def test_untrusted_key(self):
        public = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        trust = p.ProducerTrust(public, p.public_key_id(public), 'test', 'test')
        self.reject(lambda: p.verify_runtime_artifact(self.raw(), self.root, trust), 'runtime_artifact_producer_untrusted')

    def test_bad_signature(self):
        self.manifest['signature'] = base64.b64encode(bytes(64)).decode()
        self.reject(self.verify, 'runtime_artifact_signature_invalid')

    def test_scope_mismatch(self):
        self.manifest['producer_scope'] = 'production'
        self.sign()
        self.reject(self.verify, 'runtime_artifact_producer_scope_mismatch')

    def test_test_producer_denied_in_production(self):
        trust = dataclasses.replace(self.trust, mode='production')
        self.reject(lambda: p.verify_runtime_artifact(self.raw(), self.root, trust), 'runtime_artifact_test_producer_denied')

    def test_key_id_mismatch(self):
        self.reject(dataclasses.replace(self.trust, key_id='sha256:'+'0'*64).validate, 'runtime_artifact_producer_key_id_mismatch')

    def test_missing_public_trust(self):
        self.reject(lambda: p.producer_trust_from_environment({}), 'runtime_artifact_producer_trust_unavailable')

    def test_conflicting_environment(self):
        self.reject(lambda: p.runtime_environment_mode({'USBAY_ENV':'prod', 'USBAY_ENVIRONMENT':'test'}), 'runtime_artifact_mode_conflict')

    def test_duplicate_field(self):
        raw = self.raw()[:-1] + b',"source_commit":"' + b'a'*40 + b'"}'
        self.reject(lambda: p.verify_runtime_artifact(raw, self.root, self.trust), 'runtime_artifact_manifest_duplicate_field')

    def test_nonfinite_field(self):
        raw = self.raw().replace(b'"build_reference":null', b'"build_reference":NaN')
        self.reject(lambda: p.verify_runtime_artifact(raw, self.root, self.trust), 'runtime_artifact_contract_invalid')

    def test_extra_field(self):
        self.manifest['extra'] = False
        self.reject(self.verify, 'runtime_artifact_contract_invalid')

    def test_commit_conflict(self):
        self.reject(lambda: self.verify(expected_source_commit='d'*40), 'runtime_artifact_source_conflict')

    def test_tree_conflict(self):
        self.reject(lambda: self.verify(expected_source_tree='d'*40), 'runtime_artifact_source_conflict')

    def test_digest_mismatch(self):
        self.manifest['manifest_digest'] = '0'*64
        self.manifest['signature'] = base64.b64encode(self.key.sign(p.signature_payload(self.manifest))).decode()
        self.reject(self.verify, 'runtime_artifact_manifest_digest_mismatch')

    def test_managed_set_mismatch(self):
        self.manifest['managed_set_hash'] = '0'*64
        self.sign()
        self.reject(self.verify, 'runtime_artifact_managed_set_mismatch')

    def test_same_size_mutation(self):
        self.file.write_bytes(b'x'*self.file.stat().st_size)
        self.reject(self.verify, 'runtime_artifact_file_digest_mismatch')

    def test_mode_mutation(self):
        self.file.chmod(0o755)
        self.reject(self.verify, 'runtime_artifact_file_mode_mismatch')

    def test_missing_file(self):
        self.file.unlink()
        self.reject(self.verify, 'runtime_artifact_file_unavailable')

    def test_file_symlink(self):
        target = self.base / 'other.py'
        self.file.rename(target)
        self.file.symlink_to(target)
        self.reject(self.verify, 'runtime_artifact_file_unavailable')

    def test_parent_symlink(self):
        directory = self.base / 'other'
        directory.mkdir()
        self.file.rename(directory / 'application.py')
        (self.root / 'linked').symlink_to(directory, target_is_directory=True)
        self.manifest['managed_files'][0]['path'] = 'linked/application.py'
        self.manifest['managed_set_hash'] = hashlib.sha256(p.canonical_bytes(self.manifest['managed_files'])).hexdigest()
        self.sign()
        self.reject(self.verify, 'runtime_artifact_file_unavailable')

    def test_root_symlink(self):
        root = self.base / 'linked'
        root.symlink_to(self.root, target_is_directory=True)
        self.reject(lambda: p.verify_runtime_artifact(self.raw(), root, self.trust), 'runtime_artifact_root_invalid')

    def test_unexpected_governed_file(self):
        (self.root / 'extra.py').write_bytes(b'# synthetic\n')
        self.reject(self.load, 'runtime_artifact_unexpected_governed_file')

    def test_freshness_file_mutation(self):
        authority = self.load()
        self.file.write_bytes(b'x'*self.file.stat().st_size)
        self.reject(authority.assert_fresh, 'runtime_artifact_state_changed')

    def test_freshness_manifest_mutation(self):
        authority = self.load()
        (self.root / a.MANIFEST_NAME).write_bytes(self.raw() + b' ')
        self.reject(authority.assert_fresh, 'runtime_artifact_state_changed')

    def test_forged_seal(self):
        forged = dataclasses.replace(self.load(), _seal=object())
        self.reject(forged.assert_fresh, 'runtime_artifact_authority_unverified')

    def test_future_timestamp(self):
        self.manifest['created_at'] = '2999-01-01T00:00:00Z'
        self.sign()
        self.reject(self.verify, 'runtime_artifact_timestamp_invalid')

    def test_malformed_manifest(self):
        self.reject(lambda: p.verify_runtime_artifact(b'{', self.root, self.trust), 'runtime_artifact_manifest_malformed')

    def test_production_ignores_git(self):
        (self.root / '.git').mkdir()
        with patch.dict('os.environ', {'USBAY_ENV':'production'}, clear=True):
            self.assertTrue(a.artifact_runtime_required(self.root))
        self.reject(lambda: a.load_runtime_artifact_authority(self.root, trust=self.trust), 'runtime_artifact_state_unavailable')

    def test_result_immutable(self):
        value = self.verify()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            value.source_commit = 'd'*40

    def test_freshness_extra_file(self):
        authority = self.load()
        (self.root / 'extra.py').write_bytes(b'# synthetic\n')
        self.reject(authority.assert_fresh, 'runtime_artifact_unexpected_governed_file')


class BoundedResult(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.reports = {}

    def record(self, test, outcome):
        name = test._testMethodName
        if name not in CASE_NAMES or name in self.reports:
            raise RuntimeError('RUNTIME_ARTIFACT_RESULT_INVALID')
        self.reports[name] = outcome

    def addSuccess(self, test): self.record(test, 'passed')
    def addError(self, test, error): self.record(test, 'error')
    def addFailure(self, test, error): self.record(test, 'failed')
    def addSkip(self, test, reason): self.record(test, 'skipped')
    def addExpectedFailure(self, test, error): self.record(test, 'failed')
    def addUnexpectedSuccess(self, test): self.record(test, 'failed')


def run(source_binding, dependency_binding):
    suite = unittest.TestSuite(RuntimeArtifactCases(name) for name in CASE_NAMES)
    result = BoundedResult()
    suite.run(result)
    return {'schema': SCHEMA, 'source_binding': source_binding,
            'dependency_binding': dependency_binding, 'reports': result.reports,
            'tests_run': result.testsRun, 'execution_authorized': False}
