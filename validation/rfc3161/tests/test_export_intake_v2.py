"""Local intake integration with genuine signed, explicitly synthetic fixtures."""
from dataclasses import asdict, FrozenInstanceError
import base64
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from audit import export_intake_v2 as intake
from audit.export_input_contract import require_operational_timestamp_verifier, ExportInputError
from security import runtime_artifact_provenance as source_contract
import test_export_timestamp_v2 as vectors

ROOT = Path(__file__).resolve().parents[3]


class ExportIntakeTests(unittest.TestCase):
    # Reuse the native fixture producer, not the other TestCase's test methods.
    @classmethod
    def setUpClass(cls):
        vectors.NativeExportV2Tests.setUpClass.__func__(cls)
        cls.source_key = Ed25519PrivateKey.generate()  # Memory-only synthetic signer.

    resign = vectors.NativeExportV2Tests.resign

    def setUp(self):
        vectors.NativeExportV2Tests.setUp(self)
        self.inputs = self.package.parent
        self.source = self.inputs/'source'; self.source.mkdir()
        (self.source/'src').mkdir()
        self.source_file = self.source/'src/main.py'
        self.source_file.write_bytes(b'SYNTHETIC_SOURCE_CANARY = True\n')
        public = self.source_key.public_key().public_bytes_raw()
        entry = {'path': 'src/main.py', 'mode': '100644', 'size': self.source_file.stat().st_size,
                 'sha256': intake.digest(self.source_file.read_bytes())}
        self.source_manifest = {
            'schema_version': source_contract.MANIFEST_SCHEMA,
            'producer_contract': source_contract.PRODUCER_CONTRACT,
            'producer_key_id': source_contract.public_key_id(public), 'producer_scope': 'test',
            'source_commit': self.bindings['source_commit'], 'source_tree_reference': self.bindings['source_tree'],
            'managed_files': [entry], 'managed_set_hash': intake.digest(intake.canonical([entry])),
            'build_reference': 'github-actions:123', 'created_at': '2026-11-06T12:00:00Z', 'manifest_id': '1'*32,
        }
        self.profile = {
            'schema': intake.PROFILE_SCHEMA,
            'reference': {'schema': intake.REFERENCE_SCHEMA, 'repository': 'fixture-owner/usbay-test',
                'run_id': '123', 'artifact_id': '456', 'tenant_id': self.bindings['tenant_id'],
                'source_commit': self.bindings['source_commit'], 'source_tree': self.bindings['source_tree'],
                'manifest_sha256': self.expected_manifest, 'source_manifest_sha256': ''},
            'bindings': dict(self.bindings), 'package_signer_public_key_hex': self.public_key.hex(),
            'source_producer_public_key_hex': public.hex(), 'source_producer_scope': 'test',
            'source_verifier_mode': 'test', 'tsa_roots_pem': self.tsa_roots.decode('ascii'),
            'evaluation_time': '2026-11-06T12:00:05Z', 'max_source_age_seconds': 3600,
            'max_age_seconds': 300, 'clock_skew_seconds': 0, 'maximum_accuracy_seconds': 1,
            'max_crl_age_seconds': 3600,
        }
        self.sign_source()

    def sign_source(self, key=None):
        manifest = self.source_manifest
        manifest['manifest_digest'] = source_contract.manifest_digest(manifest)
        manifest['signature'] = base64.b64encode((key or self.source_key).sign(
            source_contract.signature_payload(manifest))).decode()
        raw = intake.canonical(manifest)
        (self.source/intake.SOURCE_MANIFEST).write_bytes(raw)
        self.profile['reference']['source_manifest_sha256'] = intake.digest(raw)
        self.write_reference()

    def write_reference(self):
        (self.inputs/'input_reference.json').write_bytes(intake.canonical(self.profile['reference']))

    def check(self):
        return intake.inspect_preissued_export_v2(self.inputs, verifier_inputs=self.profile)

    def reject(self, code=None):
        with self.assertRaises(intake.ExportIntakeError) as raised: self.check()
        if code: self.assertEqual(str(raised.exception), code)
        self.assertNotIn('SYNTHETIC_SOURCE_CANARY', str(raised.exception))

    def test_signed_inputs_compose_without_mutation(self):
        before = {p.relative_to(self.inputs): p.read_bytes() for p in self.inputs.rglob('*') if p.is_file()}
        result = self.check()
        self.assertEqual(result.source_file_count, 1)
        self.assertEqual(result.package.manifest_sha256, self.expected_manifest)
        self.assertEqual(before, {p.relative_to(self.inputs): p.read_bytes() for p in self.inputs.rglob('*') if p.is_file()})
        self.assertNotIn('allow', asdict(result))
        self.assertIn('ADOPTED_SOURCE_PRODUCER_TRUST', result.remaining_requirements)
        self.assertIn('AUDIT_LEDGER_RELEASE_WORM_SEMANTIC_VERIFICATION', result.package.remaining_requirements)
        with self.assertRaises(FrozenInstanceError): result.source_commit = '0'*40

    def test_positive_observation_does_not_enable_operational_export(self):
        self.check()
        with self.assertRaises(ExportInputError): require_operational_timestamp_verifier()

    def test_reference_repository_substitution(self):
        ref = dict(self.profile['reference'], repository='other/tenant')
        (self.inputs/'input_reference.json').write_bytes(intake.canonical(ref)); self.reject('INTAKE_REFERENCE_MISMATCH')

    def test_reference_run_substitution(self):
        ref = dict(self.profile['reference'], run_id='999')
        (self.inputs/'input_reference.json').write_bytes(intake.canonical(ref)); self.reject('INTAKE_REFERENCE_MISMATCH')

    def test_reference_artifact_substitution(self):
        ref = dict(self.profile['reference'], artifact_id='999')
        (self.inputs/'input_reference.json').write_bytes(intake.canonical(ref)); self.reject('INTAKE_REFERENCE_MISMATCH')

    def test_reference_extra_verified_flag(self):
        ref = dict(self.profile['reference'], verified=True)
        (self.inputs/'input_reference.json').write_bytes(intake.canonical(ref)); self.reject('INTAKE_REFERENCE_MISMATCH')

    def test_noncanonical_reference(self):
        (self.inputs/'input_reference.json').write_text(json.dumps(self.profile['reference'], indent=2))
        self.reject('INTAKE_REFERENCE_MISMATCH')

    def test_wildcard_artifact_reference(self):
        self.profile['reference']['artifact_id'] = '*'; self.reject('INTAKE_REFERENCE_INVALID')

    def test_tenant_mismatch_between_profile_and_reference(self):
        self.profile['bindings']['tenant_id'] = 'tenant-B'; self.reject('INTAKE_REFERENCE_BINDING_MISMATCH')

    def test_consistent_but_wrong_tenant_cannot_substitute_package(self):
        self.profile['bindings']['tenant_id'] = self.profile['reference']['tenant_id'] = 'tenant-B'
        self.write_reference(); self.reject('INTAKE_PACKAGE_VERIFICATION_FAILED')

    def test_actor_substitution_against_signed_package(self):
        self.profile['bindings']['actor_reference'] = 'sha256:'+'0'*64
        self.reject('INTAKE_PACKAGE_VERIFICATION_FAILED')

    def test_independent_source_pin(self):
        self.profile['reference']['source_manifest_sha256'] = '0'*64; self.write_reference()
        self.reject('INTAKE_SOURCE_PIN_MISMATCH')

    def test_noncanonical_source_manifest_is_denied_even_when_pinned(self):
        raw = json.dumps(self.source_manifest, indent=2).encode()
        (self.source/intake.SOURCE_MANIFEST).write_bytes(raw)
        self.profile['reference']['source_manifest_sha256'] = intake.digest(raw); self.write_reference()
        self.reject('INTAKE_SOURCE_ENCODING_INVALID')

    def test_independent_package_pin(self):
        self.profile['reference']['manifest_sha256'] = '0'*64; self.write_reference()
        self.reject('INTAKE_PACKAGE_VERIFICATION_FAILED')

    def test_signed_source_commit_conflict(self):
        self.source_manifest['source_commit'] = '5'*40; self.sign_source()
        self.reject('INTAKE_SOURCE_VERIFICATION_FAILED')

    def test_signed_source_tree_conflict(self):
        self.source_manifest['source_tree_reference'] = '5'*40; self.sign_source()
        self.reject('INTAKE_SOURCE_VERIFICATION_FAILED')

    def test_wrong_source_signature(self):
        self.sign_source(Ed25519PrivateKey.generate()); self.reject('INTAKE_SOURCE_VERIFICATION_FAILED')

    def test_wrong_source_public_key(self):
        self.profile['source_producer_public_key_hex'] = self.public_key.hex()
        self.reject('INTAKE_SOURCE_VERIFICATION_FAILED')

    def test_wrong_package_public_key(self):
        self.profile['package_signer_public_key_hex'] = self.source_key.public_key().public_bytes_raw().hex()
        self.reject('INTAKE_PACKAGE_VERIFICATION_FAILED')

    def test_corrupt_package_signature(self):
        path = self.package/'package_signature.json'; value = json.loads(path.read_bytes())
        value['signature'] = '0'*128; path.write_bytes(intake.canonical(value))
        self.reject('INTAKE_PACKAGE_VERIFICATION_FAILED')

    def test_stale_source_manifest(self):
        self.source_manifest['created_at'] = '2026-11-06T11:00:00Z'; self.sign_source()
        self.reject('INTAKE_SOURCE_FRESHNESS_INVALID')

    def test_future_source_manifest(self):
        self.source_manifest['created_at'] = '2026-11-06T12:00:06Z'; self.sign_source()
        self.reject('INTAKE_SOURCE_FRESHNESS_INVALID')

    def test_source_build_run_mismatch(self):
        self.source_manifest['build_reference'] = 'github-actions:999'; self.sign_source()
        self.reject('INTAKE_SOURCE_REFERENCE_MISMATCH')

    def test_test_source_not_accepted_under_production_mode(self):
        self.profile['source_verifier_mode'] = 'production'; self.reject()

    def test_unknown_profile_authority_flag(self):
        self.profile['execution_authority'] = True; self.reject('INTAKE_PROFILE_INVALID')

    def test_boolean_freshness_profile(self):
        self.profile['max_source_age_seconds'] = True; self.reject('INTAKE_PROFILE_INVALID')

    def test_unbounded_freshness_profile(self):
        self.profile['max_source_age_seconds'] = 86401; self.reject('INTAKE_PROFILE_INVALID')

    def test_native_time_profile_bounds(self):
        self.profile['clock_skew_seconds'] = self.profile['maximum_accuracy_seconds'] = 60
        self.check()
        for name in ('clock_skew_seconds', 'maximum_accuracy_seconds'):
            self.profile[name] = 61
            self.reject('INTAKE_PROFILE_INVALID')
            self.profile[name] = 60

    def test_unknown_top_level_input(self):
        (self.inputs/'extra.json').write_bytes(b'{}'); self.reject('INTAKE_INVENTORY_INVALID')

    def test_extra_source_in_mutable_prefix_is_not_exempt(self):
        (self.source/'tmp').mkdir(); (self.source/'tmp/extra').write_bytes(b'CANARY')
        self.reject('INTAKE_INVENTORY_INVALID')

    def test_extra_empty_directory_is_not_exempt(self):
        (self.source/'extra').mkdir(); self.reject('INTAKE_INVENTORY_INVALID')

    def test_missing_release(self):
        (self.package/'governance_release.json').unlink(); self.reject('INTAKE_INVENTORY_INVALID')

    def test_missing_original_timestamp_request(self):
        (self.package/'rfc3161_request.tsq').unlink(); self.reject('INTAKE_INVENTORY_INVALID')

    def test_source_byte_substitution(self):
        self.source_file.write_bytes(b'SUBSTITUTED'); self.reject('INTAKE_SOURCE_VERIFICATION_FAILED')

    def test_source_file_hardlink(self):
        os.link(self.source_file, self.base/'outside-link')
        self.addCleanup((self.base/'outside-link').unlink)
        self.reject('INTAKE_INVENTORY_INVALID')

    def test_input_root_symlink(self):
        alias = self.base/(self.inputs.name+'-alias'); alias.symlink_to(self.inputs, target_is_directory=True)
        self.addCleanup(alias.unlink); self.inputs = alias
        self.reject('INTAKE_PATH_INVALID')

    def test_reference_hardlink(self):
        alias = self.base/(self.inputs.name+'-reference-link')
        os.link(self.inputs/'input_reference.json', alias); self.addCleanup(alias.unlink)
        self.reject()

    def test_source_file_symlink(self):
        self.source_file.unlink(); self.source_file.symlink_to(self.vector/'test-root.pem')
        self.reject('INTAKE_INVENTORY_INVALID')

    def test_package_fifo(self):
        path = self.package/'verification_report.md'; path.unlink(); os.mkfifo(path)
        self.reject('INTAKE_INVENTORY_INVALID')

    def test_reference_symlink(self):
        path = self.inputs/'input_reference.json'; path.unlink(); path.symlink_to(self.vector/'test-root.pem')
        self.reject()

    def test_signed_oversized_source_is_denied_before_read(self):
        self.source_manifest['managed_files'][0]['size'] = intake.MAX_SOURCE_FILE+1
        self.sign_source(); self.reject('INTAKE_SOURCE_LIMIT')

    def test_source_file_count_is_bounded(self):
        self.source_manifest['managed_files'] *= intake.MAX_SOURCE_FILES+1
        self.sign_source(); self.reject('INTAKE_SOURCE_LIMIT')

    def test_source_total_size_is_bounded_before_file_reads(self):
        entries = [{'path': 'part-'+str(i)+'.bin', 'mode': '100644', 'sha256': 'a'*64,
                    'size': intake.MAX_SOURCE_FILE} for i in range(17)]
        self.source_manifest['managed_files'] = entries
        self.source_manifest['managed_set_hash'] = intake.digest(intake.canonical(entries))
        self.sign_source(); self.reject('INTAKE_SOURCE_LIMIT')

    def test_source_depth_is_bounded(self):
        self.source_manifest['managed_files'][0]['path'] = '/'.join(['deep']*33)
        self.sign_source(); self.reject('INTAKE_SOURCE_LIMIT')

    def test_supplied_source_is_never_imported(self):
        raw = b'raise RuntimeError("SYNTHETIC_SOURCE_CANARY")\n'
        self.source_file.write_bytes(raw)
        entry = self.source_manifest['managed_files'][0]
        entry.update(size=len(raw), sha256=intake.digest(raw))
        self.source_manifest['managed_set_hash'] = intake.digest(intake.canonical([entry]))
        self.sign_source(); self.check()

    def test_mutation_after_genuine_native_verification(self):
        actual = intake.inspect_native_export_v2
        def verify_then_mutate(*args, **kwargs):
            result = actual(*args, **kwargs)
            (self.package/'verification_report.md').write_bytes(b'SUBSTITUTED')
            return result
        with patch.object(intake, 'inspect_native_export_v2', side_effect=verify_then_mutate):
            self.reject('INTAKE_INPUT_CHANGED')

    def test_identical_source_rewrite_after_native_verification(self):
        actual = intake.inspect_native_export_v2
        def verify_then_rewrite(*args, **kwargs):
            result = actual(*args, **kwargs); self.source_file.write_bytes(self.source_file.read_bytes())
            return result
        with patch.object(intake, 'inspect_native_export_v2', side_effect=verify_then_rewrite):
            self.reject('INTAKE_INPUT_CHANGED')

    def test_identical_bundle_replacement_after_native_verification(self):
        actual = intake.inspect_native_export_v2
        def verify_then_replace(*args, **kwargs):
            result = actual(*args, **kwargs)
            previous = self.inputs.parent/(self.inputs.name+'-old')
            self.inputs.rename(previous); shutil.copytree(previous, self.inputs)
            self.addCleanup(shutil.rmtree, previous)
            return result
        with patch.object(intake, 'inspect_native_export_v2', side_effect=verify_then_replace):
            self.reject('INTAKE_INPUT_CHANGED')

    def test_caller_profile_mutation_cannot_rebind_snapshot(self):
        original_hash = intake.digest(intake.canonical(self.profile))
        actual = intake.verify_runtime_artifact
        def verify_then_change_caller(*args, **kwargs):
            result = actual(*args, **kwargs); self.profile['bindings']['tenant_id'] = 'tenant-B'
            return result
        with patch.object(intake, 'verify_runtime_artifact', side_effect=verify_then_change_caller):
            self.assertEqual(self.check().verifier_inputs_sha256, original_hash)

    def test_binding_mutation_during_validation_cannot_change_snapshot(self):
        original_hash = intake.digest(intake.canonical(self.profile))
        actual = intake._bindings
        def mutate_caller_then_validate(value):
            self.profile['bindings']['actor_reference'] = 'sha256:'+'0'*64
            return actual(value)
        with patch.object(intake, '_bindings', side_effect=mutate_caller_then_validate):
            self.assertEqual(self.check().verifier_inputs_sha256, original_hash)

    def test_concurrent_read_only_observations(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: self.check(), range(3)))
        self.assertEqual(results[0], results[1]); self.assertEqual(results[1], results[2])

    def run_cli(self, raw=None, extra=()):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)/'public-profile.json'
            profile.write_bytes(raw if raw is not None else intake.canonical(self.profile))
            return subprocess.run([sys.executable, '-m', 'audit.export_intake_v2', 'observe',
                '--inputs', str(self.inputs), '--profile', str(profile), *extra], cwd=ROOT,
                env={'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE': '1'},
                capture_output=True, timeout=30)

    def test_cli_observation_only_and_bounded_output(self):
        result = self.run_cli(); self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['status'], 'OBSERVED_ONLY_NOT_OPERATIONALLY_AUTHORIZED')
        self.assertEqual(result.stderr, b'')
        self.assertNotIn(b'SYNTHETIC_SOURCE_CANARY', result.stdout)
        self.assertNotIn(self.tsa_roots, result.stdout)

    def test_cli_duplicate_profile_fields_fail_without_raw_echo(self):
        raw = b'{"schema":"SYNTHETIC_SOURCE_CANARY","schema":true}'
        result = self.run_cli(raw); self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['status'], 'DENY')
        self.assertNotIn(b'SYNTHETIC_SOURCE_CANARY', result.stdout+result.stderr)

    def test_cli_unknown_arguments_do_not_echo_values(self):
        result = self.run_cli(extra=('--unknown', 'SYNTHETIC_SOURCE_CANARY'))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['reason_code'], 'INTAKE_ARGUMENTS_INVALID')
        self.assertNotIn(b'SYNTHETIC_SOURCE_CANARY', result.stdout+result.stderr)


if __name__ == '__main__': unittest.main()
