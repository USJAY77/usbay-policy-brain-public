"""Native-only synthetic verifier cases. Import only after all containment gates.

Private test keys live in memory only. Public fixtures never grant product,
provider, issuer, deployment or execution authority. No live files are used.
"""
import base64
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from datetime import datetime, timezone
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
from security import deployment_attestation as d
from security import tenant_context as t
from governance import release_integrity as g
from security.runtime_artifact_package import package_preissued_runtime_artifact, main as package_main
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
        target.write_bytes(self.file.read_bytes())
        self.file.unlink()
        self.file.symlink_to(target)
        self.reject(self.verify, 'runtime_artifact_file_unavailable')

    def test_parent_symlink(self):
        directory = self.base / 'other'
        directory.mkdir()
        (directory / 'application.py').write_bytes(self.file.read_bytes())
        self.file.unlink()
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


    def preissued_package(self, output=None, **changes):
        options = dict(raw_manifest=self.raw(), trust=self.trust,
                       expected_source_commit='a'*40, expected_source_tree='b'*40)
        options.update(changes)
        return package_preissued_runtime_artifact(
            self.root, output or self.base/'output', **options,
        )

    def test_preissued_package_without_git(self):
        output = self.preissued_package()
        self.assertFalse((output/'.git').exists())
        self.assertEqual((output/'application.py').read_bytes(), self.file.read_bytes())
        self.assertEqual((output/a.MANIFEST_NAME).read_bytes(), self.raw())
        verified = a.load_runtime_artifact_authority(output, trust=self.trust)
        self.assertEqual(verified.verified.source_commit, 'a'*40)
        self.assertFalse(hasattr(verified, 'execution_authorized'))

    def test_preissued_package_commit_conflict(self):
        self.reject(lambda: self.preissued_package(expected_source_commit='d'*40), 'runtime_artifact_source_conflict')
        self.assertFalse((self.base/'output').exists())

    def test_preissued_package_tree_conflict(self):
        self.reject(lambda: self.preissued_package(expected_source_tree='d'*40), 'runtime_artifact_source_conflict')
        self.assertFalse((self.base/'output').exists())

    def test_preissued_package_requires_expected_binding(self):
        self.reject(lambda: self.preissued_package(expected_source_commit=None), 'runtime_artifact_package_source_binding_required')
        self.assertFalse((self.base/'output').exists())

    def test_preissued_package_preserves_existing_destination(self):
        output = self.base/'output'
        output.mkdir()
        marker = output/'marker.txt'
        marker.write_bytes(b'synthetic preserved marker')
        self.reject(lambda: self.preissued_package(output), 'runtime_artifact_package_destination_exists')
        self.assertEqual(marker.read_bytes(), b'synthetic preserved marker')
        self.assertFalse((output/a.MANIFEST_NAME).exists())

    def test_preissued_package_rejects_changed_source(self):
        self.file.write_bytes(b'x'*self.file.stat().st_size)
        self.reject(self.preissued_package, 'runtime_artifact_file_digest_mismatch')
        self.assertFalse((self.base/'output').exists())

    def test_preissued_package_rejects_invalid_signature(self):
        self.manifest['signature'] = base64.b64encode(bytes(64)).decode()
        self.reject(self.preissued_package, 'runtime_artifact_signature_invalid')
        self.assertFalse((self.base/'output').exists())

    def public_package_arguments(self):
        manifest = self.base/'issued-public-manifest.json'
        manifest.write_bytes(self.raw())
        return ['--source',str(self.root),'--destination',str(self.base/'output'),
                '--manifest-file',str(manifest),'--expected-source-commit','a'*40,
                '--expected-source-tree','b'*40]

    def public_trust_environment(self):
        return {'USBAY_ENV':'test',
                'USBAY_RUNTIME_ARTIFACT_PRODUCER_PUBLIC_KEY':base64.b64encode(self.public).decode(),
                'USBAY_RUNTIME_ARTIFACT_PRODUCER_KEY_ID':self.trust.key_id,
                'USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE':'test'}

    def test_preissued_package_cli_public_inputs(self):
        out, error = io.StringIO(), io.StringIO()
        with patch.dict('os.environ',self.public_trust_environment(),clear=True), redirect_stdout(out), redirect_stderr(error):
            result = package_main(self.public_package_arguments())
        self.assertEqual(result,0)
        self.assertEqual(out.getvalue(),'runtime_artifact_package_verified\n')
        self.assertEqual(error.getvalue(),'')
        self.assertEqual((self.base/'output/application.py').read_bytes(),self.file.read_bytes())

    def test_preissued_package_cli_missing_trust(self):
        out, error = io.StringIO(), io.StringIO()
        with patch.dict('os.environ',{'USBAY_ENV':'test'},clear=True), redirect_stdout(out), redirect_stderr(error):
            result = package_main(self.public_package_arguments())
        self.assertEqual(result,1)
        self.assertEqual(error.getvalue(),'runtime_artifact_package_failed\n')
        self.assertEqual(out.getvalue(),'')
        self.assertFalse((self.base/'output').exists())

    def test_preissued_package_cli_rejects_private_key_argument(self):
        out, error = io.StringIO(), io.StringIO()
        with patch.dict('os.environ',self.public_trust_environment(),clear=True), redirect_stdout(out), redirect_stderr(error):
            result = package_main(self.public_package_arguments()+['--signing-key-file','PRIVATE_CANARY'])
        self.assertEqual(result,1)
        self.assertEqual(error.getvalue(),'runtime_artifact_package_failed\n')
        self.assertNotIn('PRIVATE_CANARY',out.getvalue()+error.getvalue())
        self.assertFalse((self.base/'output').exists())


    def release_fixture(self):
        # Synthetic public policy fixtures; no enrolled operational identity or grant.
        node = {'required_attestation_mode':'mock_local','allowed_node_roles':['gateway'],
                'attestation_ttl_seconds':30,'require_hardware_backing':False,'production_rejects_mock':True,
                'enrolled_nodes':{'fixture':{'role':'gateway','public_identity':
                    {'vendor':'USBAY','node_label':'fixture','public_key_id':'synthetic-public'}}}}
        tenant = {'allowed_tenant_ids':['tenant-a'],'tenant_evidence_isolation':True,
                  'tenant_export_permissions':{'tenant-a':True},
                  'tenant_retention_policy':{'tenant-a':{'retention_days':1}}}
        fixtures = {'governance/policy_registry.json':{'synthetic':True},
                    'governance/policy_registry.sig':{'synthetic_signature_fixture':True},
                    'governance/policy_release_manifest.json':{'synthetic':True},
                    'governance/node_attestation_policy.json':node,
                    'governance/tenant_policy.json':tenant}
        for name, value in fixtures.items():
            path = self.root/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(p.canonical_bytes(value))
            path.chmod(0o644)
        entries = [{'path':path.relative_to(self.root).as_posix(),'mode':'100644',
                    'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'size':path.stat().st_size}
                   for path in sorted(self.root.rglob('*')) if path.is_file()]
        self.manifest['managed_files'] = entries
        self.manifest['managed_set_hash'] = hashlib.sha256(p.canonical_bytes(entries)).hexdigest()
        self.sign()
        (self.root/a.MANIFEST_NAME).write_bytes(self.raw())
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir,previous)
        for context in [patch.dict('os.environ',self.public_trust_environment(),clear=True),
                        patch.object(a,'REPO_ROOT',self.root),patch.object(a,'_runtime_authority',None),
                        patch.object(t,'DEFAULT_TENANT_POLICY_ROOT',self.root),
                        patch.object(d,'GENERATED_GOVERNANCE_RELEASE_DIR',self.base/'unissued')]:
            context.start()
            self.addCleanup(context.stop)
        self.release_path = self.base/'synthetic-release.json'
        os.environ['USBAY_GOVERNANCE_RELEASE_PATH'] = str(self.release_path)
        self.development_material = d._signing_material()
        self.release = {'release_id':'synthetic-read-boundary','git_commit':'a'*40,
                        'policy_bundle_hash':d.policy_bundle_hash(),
                        'deployment_timestamp':datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                        'activating_node_id':d._canonical_activating_node_id(),
                        'tenant_id':'tenant-a','previous_release_hash':'GENESIS'}
        self.save_release_fixture()

    def save_release_fixture(self):
        self.release['release_signature'] = d.sign_release_manifest(self.release)
        self.release_path.write_bytes(p.canonical_bytes(self.release))

    def release_reject(self, operation, code):
        with self.assertRaises(d.DeploymentAttestationError) as raised:
            operation()
        self.assertEqual(str(raised.exception),code)

    def artifact_in_fixture(self):
        return a.get_runtime_artifact_authority(self.root)

    def select_synthetic_production_source(self):
        self.manifest['producer_scope'] = 'production'
        self.sign()
        (self.root/a.MANIFEST_NAME).write_bytes(self.raw())
        os.environ.update(USBAY_ENV='production',USBAY_RUNTIME_ARTIFACT_PRODUCER_SCOPE='production')

    def test_release_source_commit_without_git(self):
        self.release_fixture()
        self.assertEqual(d.current_git_commit(),'a'*40)
        self.assertFalse((self.root/'.git').exists())

    def test_release_startup_reader_shares_verified_source(self):
        self.release_fixture()
        before = self.release_path.read_bytes()
        artifact = self.artifact_in_fixture()
        result = d.resolve_runtime_provenance_authority(artifact_authority=artifact)
        self.assertIs(result.artifact_authority,artifact)
        self.assertEqual(result.provenance_context.accepted_commit_set,('a'*40,))
        self.assertEqual(result.tenant_id,'tenant-a')
        self.assertIsNone(d.assert_startup_release_integrity())
        self.assertEqual(self.release_path.read_bytes(),before)
        self.assertFalse(hasattr(result,'execution_authorized'))

    def test_release_requires_explicit_path_in_artifact_mode(self):
        self.release_fixture()
        os.environ.pop('USBAY_GOVERNANCE_RELEASE_PATH')
        self.release_reject(d.resolve_release_manifest_path,'release_manifest_path_required')
        self.assertFalse((self.base/'unissued').exists())

    def test_release_missing_file_is_not_generated(self):
        self.release_fixture()
        missing = self.base/'missing-release.json'
        os.environ['USBAY_GOVERNANCE_RELEASE_PATH'] = str(missing)
        self.release_reject(d.load_release_manifest,'release_manifest_missing')
        self.assertFalse(missing.exists())
        self.assertFalse((self.base/'unissued').exists())

    def test_release_malformed_file_is_not_repaired(self):
        self.release_fixture()
        self.release_path.write_bytes(b'{')
        self.release_reject(d.load_release_manifest,'release_manifest_malformed')
        self.assertEqual(self.release_path.read_bytes(),b'{')

    def test_release_commit_substitution_rejected(self):
        self.release_fixture()
        self.release['git_commit'] = 'd'*40
        self.save_release_fixture()
        self.release_reject(d.resolve_runtime_provenance_authority,'git_commit_mismatch')

    def test_release_invalid_signature_rejected(self):
        self.release_fixture()
        self.release['release_signature'] = 'hmac-sha256:'+'0'*64
        self.release_path.write_bytes(p.canonical_bytes(self.release))
        self.release_reject(d.resolve_runtime_provenance_authority,'release_signature_invalid')

    def test_release_tenant_binding_mismatch_rejected(self):
        self.release_fixture()
        self.release_reject(lambda:d.validate_release_manifest(expected_tenant_id='tenant-b'),
                            'tenant_deployment_provenance_mismatch')

    def test_release_policy_bundle_substitution_rejected(self):
        self.release_fixture()
        self.release['policy_bundle_hash'] = 'f'*64
        self.save_release_fixture()
        self.release_reject(d.resolve_runtime_provenance_authority,'policy_bundle_hash_mismatch')

    def test_release_production_requires_independent_signing_material(self):
        self.release_fixture()
        self.select_synthetic_production_source()
        self.release_reject(d.resolve_runtime_provenance_authority,'deployment_signing_material_required')

    def test_release_production_rejects_development_signing_material(self):
        self.release_fixture()
        self.select_synthetic_production_source()
        os.environ['USBAY_DEPLOYMENT_SIGNING_MATERIAL'] = self.development_material
        self.release_reject(d.resolve_runtime_provenance_authority,'development_signing_material_denied')

    def test_release_generation_denied_even_when_forced(self):
        self.release_fixture()
        output = self.base/'must-not-generate.json'
        self.release_reject(lambda:d.ensure_runtime_release_manifest(output,force=True),'runtime_release_generation_denied')
        self.assertFalse(output.exists())

    def test_release_rejects_stale_source_before_consumption(self):
        self.release_fixture()
        artifact = self.artifact_in_fixture()
        self.file.write_bytes(b'x'*self.file.stat().st_size)
        self.release_reject(lambda:d.resolve_runtime_provenance_authority(artifact_authority=artifact),
                            'runtime_artifact_state_changed')

    def test_release_rejects_substituted_source_authority(self):
        self.release_fixture()
        artifact = self.artifact_in_fixture()
        changed = dataclasses.replace(artifact,verification_reference='sha256:'+'0'*64)
        self.release_reject(lambda:d.resolve_runtime_provenance_authority(artifact_authority=changed),
                            'runtime_artifact_authority_mismatch')

    def test_release_legacy_git_lineage_requires_build_metadata(self):
        self.release_fixture()
        for operation in [lambda:g.git_parent_commits(self.root,'a'*40),
                          lambda:g.baseline_tag_commit(self.root,'synthetic-tag')]:
            with self.assertRaises(g.GovernanceReleaseIntegrityError) as raised:
                operation()
            self.assertEqual(str(raised.exception),'release_integrity_build_metadata_required')

    def test_release_duplicate_json_fields_rejected(self):
        self.release_fixture()
        raw = self.release_path.read_bytes()[:-1]+b',"tenant_id":"tenant-a"}'
        for value in [raw,b'{"nested":{"x":1,"x":2}}']:
            self.release_path.write_bytes(value)
            self.release_reject(d.load_release_manifest,'release_manifest_duplicate_field')
            self.assertEqual(self.release_path.read_bytes(),value)

    def test_release_nonfinite_json_fields_rejected(self):
        self.release_fixture()
        for number in [b'NaN',b'Infinity',b'1e999']:
            raw = b'{"synthetic_number":'+number+b'}'
            self.release_path.write_bytes(raw)
            self.release_reject(d.load_release_manifest,'release_manifest_invalid')
            self.assertEqual(self.release_path.read_bytes(),raw)

    def test_release_external_expected_commit_mismatch_rejected(self):
        self.release_fixture()
        self.release_reject(lambda:d.validate_release_manifest(expected_git_commit='d'*40),'git_commit_mismatch')


    def test_release_symlink_file_rejected(self):
        self.release_fixture()
        before = self.release_path.read_bytes()
        link = self.base/'linked-release.json'
        link.symlink_to(self.release_path)
        self.release_reject(lambda:d.load_release_manifest(link),'release_manifest_substituted')
        self.assertEqual(self.release_path.read_bytes(),before)

    def test_release_oversized_file_rejected_without_repair(self):
        self.release_fixture()
        self.release_path.write_bytes(b' '*(p.MAX_MANIFEST_BYTES+1))
        self.release_reject(d.load_release_manifest,'release_manifest_malformed')
        self.assertEqual(self.release_path.stat().st_size,p.MAX_MANIFEST_BYTES+1)


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
