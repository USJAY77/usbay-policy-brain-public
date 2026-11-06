"""Signed input/native timestamp composition only, not full audit export.

Package signing keys remain only in Python memory; TSA test keys remain only
inside the native generator. Neither signer is an adopted operational issuer.
The synthetic audit/release/WORM bodies intentionally prove no such semantics.
"""
from dataclasses import asdict
from datetime import datetime, timezone
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from audit import export_timestamp_v2 as v2


ROOT=Path(__file__).resolve().parents[3]


class NativeExportV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='usbay-v2-native-tests-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base=Path(cls.temporary.name);cls.vector=cls.base/'vector';cls.vector.mkdir()
        cls.signing_key=Ed25519PrivateKey.generate()
        cls.public_key=cls.signing_key.public_key().public_bytes_raw()
        cls.bindings=dict(tenant_id='tenant-A',tenant_reference='sha256:'+'a'*64,
            actor_reference='sha256:'+'b'*64,resource_reference='sha256:'+'c'*64,
            source_commit='6'*40,source_tree='7'*40,purpose='audit_export_integrity',
            action='audit.timestamp.verify',tsa_policy_hash='sha256:'+'d'*64,
            tsa_policy_version='synthetic-test-1',tsa_policy_oid='1.2.3.4.1')
        cls.core={'audit.jsonl':b'{"event_type":"synthetic"}\n',
            'ledger.sha256':b'0'*64+b'\n','signatures.json':b'{}','consensus_evidence.json':b'{"synthetic":true}',
            'governance_release.json':v2.canonical({'tenant_id':'tenant-A','git_commit':'6'*40}),
            'tenant_context.json':v2.canonical({'tenant_id':'tenant-A'})}
        imprint=v2.timestamp_imprint({n:v2.digest(b) for n,b in cls.core.items()},cls.bindings)
        subprocess.run([str(ROOT/'validation/rfc3161/tests/make_memory_tsa_vectors'),imprint],cwd=cls.vector,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5,check=True)
        cls.tsa_roots=(cls.vector/'test-root.pem').read_bytes()

    def setUp(self):
        self.temporary_case=tempfile.TemporaryDirectory(dir=self.base)
        self.addCleanup(self.temporary_case.cleanup)
        self.package=Path(self.temporary_case.name)/'package';self.package.mkdir()
        data={**self.core,'timestamp_verification.json':b'{"valid":false,"synthetic":true}',
            'evidence_archive_manifest.json':b'{"object_id":"synthetic-only"}',
            'runtime_authority_identity.json':b'{"synthetic":true}',
            'tsa_policy_oid.txt':b'1.2.3.4.1\n',
            'tsa_certificate_chain.pem':(self.vector/'test-tsa.pem').read_bytes(),
            'rfc3161_timestamp.tsr':(self.vector/'test-response.der').read_bytes(),
            v2.REQUEST_FILE:(self.vector/'test-request.der').read_bytes(),
            v2.CRL_FILE:(self.vector/'test-good.crl.pem').read_bytes(),
            v2.UNSIGNED_REPORT_FILE:b'UNTRUSTED DERIVED TEST REPORT'}
        for name,raw in data.items():(self.package/name).write_bytes(raw)
        self.resign()

    def resign(self, *, bindings=None, manifest_format=None):
        bindings=dict(self.bindings if bindings is None else bindings)
        evidence={n:v2.digest((self.package/n).read_bytes()) for n in v2.PAYLOAD_FILES}
        manifest={'format':v2.FORMAT if manifest_format is None else manifest_format,
                  'bindings':bindings,'evidence_hashes':evidence,
                  'timestamp_imprint':v2.timestamp_imprint({n:evidence[n] for n in v2.CORE_FILES},bindings)}
        (self.package/'verification_manifest.json').write_bytes(v2.canonical(manifest))
        self.expected_manifest=v2.digest(v2.canonical(manifest))
        index={'format':v2.INDEX_FORMAT,'manifest_sha256':self.expected_manifest,'evidence_hashes':evidence}
        (self.package/'evidence_index.json').write_bytes(v2.canonical(index))
        basis={'format':v2.SIGNATURE_FORMAT,'public_key_sha256':v2.digest(self.public_key),
               'manifest_sha256':self.expected_manifest,'index_sha256':v2.digest(v2.canonical(index))}
        signature=self.signing_key.sign(v2.canonical(basis)).hex()
        (self.package/'package_signature.json').write_bytes(v2.canonical({**basis,'signature':signature}))

    def args(self):
        return dict(expected_bindings=dict(self.bindings),expected_manifest_sha256=self.expected_manifest,
            signer_public_key=self.public_key,tsa_roots_pem=self.tsa_roots,
            evaluation_time=datetime(2026,11,6,12,0,5,tzinfo=timezone.utc),
            max_age_seconds=300,clock_skew_seconds=0,maximum_accuracy_seconds=1,max_crl_age_seconds=3600)

    def check(self, **changes):
        args=self.args();args.update(changes);return v2.inspect_native_export_v2(self.package,**args)

    def reject(self, code=None, **changes):
        with self.assertRaises(v2.ExportTimestampV2Error) as raised:self.check(**changes)
        if code:self.assertEqual(str(raised.exception),code)
        return str(raised.exception)

    def test_signed_v2_and_native_timestamp_compose(self):
        observed=self.check()
        self.assertEqual(observed.manifest_sha256,self.expected_manifest)
        self.assertEqual(len(observed.observed_file_hashes),18)
        self.assertIn('AUDIT_LEDGER_RELEASE_WORM_SEMANTIC_VERIFICATION',observed.remaining_requirements)
        self.assertIn('ADOPTED_PACKAGE_SIGNER_AND_TSA_TRUST_CONTEXT',observed.remaining_requirements)
        self.assertFalse({'allow','valid','decision','authority'} & asdict(observed).keys())

    def test_v1_marker_never_auto_upgrades(self):
        self.resign(manifest_format='USBAY_TENANT_AUDIT_PACKAGE_V1')
        self.reject('V2_MANIFEST_VERSION_REQUIRED')

    def test_missing_request(self):
        (self.package/v2.REQUEST_FILE).unlink();self.reject('V2_PACKAGE_INVENTORY_INVALID')

    def test_missing_crl(self):
        (self.package/v2.CRL_FILE).unlink();self.reject('V2_PACKAGE_INVENTORY_INVALID')

    def test_extra_file(self):
        (self.package/'unexpected.json').write_bytes(b'{}');self.reject('V2_PACKAGE_INVENTORY_INVALID')

    def test_unsigned_request_substitution(self):
        (self.package/v2.REQUEST_FILE).write_bytes(b'changed');self.reject('V2_SIGNED_FILE_COVERAGE_MISMATCH')

    def test_unsigned_crl_substitution(self):
        (self.package/v2.CRL_FILE).write_bytes(b'changed');self.reject('V2_SIGNED_FILE_COVERAGE_MISMATCH')

    def test_resigned_revoked_actual_tsa_signer(self):
        (self.package/v2.CRL_FILE).write_bytes((self.vector/'test-revoked.crl.pem').read_bytes())
        self.resign();self.reject('V2_VERIFICATION_FAILED')

    def test_resigned_nonce_change_still_fails_native_check(self):
        request=bytearray((self.package/v2.REQUEST_FILE).read_bytes());i=request.index(bytes.fromhex('02023039'));request[i+3]^=1
        (self.package/v2.REQUEST_FILE).write_bytes(request);self.resign();self.reject('V2_VERIFICATION_FAILED')

    def test_resigned_core_change_still_fails_timestamp_preimage(self):
        (self.package/'audit.jsonl').write_bytes(b'{"event_type":"changed"}\n');self.resign()
        self.reject('V2_VERIFICATION_FAILED')

    def test_validity_boolean_cannot_replace_native_signature(self):
        (self.package/'timestamp_verification.json').write_bytes(b'{"valid":true}')
        data=bytearray((self.package/'rfc3161_timestamp.tsr').read_bytes());data[-10]^=1
        (self.package/'rfc3161_timestamp.tsr').write_bytes(data);self.resign();self.reject('V2_VERIFICATION_FAILED')

    def test_package_signature_forgery(self):
        p=self.package/'package_signature.json';data=json.loads(p.read_bytes());data['signature']='0'*128
        p.write_bytes(v2.canonical(data));self.reject('V2_SIGNATURE_INVALID')

    def test_unrelated_package_signer(self):
        other=Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        self.reject('V2_SIGNATURE_BINDING_MISMATCH',signer_public_key=other)

    def test_expected_manifest_is_independent(self):
        self.reject('V2_EXPECTED_MANIFEST_MISMATCH',expected_manifest_sha256='0'*64)

    def test_index_tampering(self):
        p=self.package/'evidence_index.json';data=json.loads(p.read_bytes());data['manifest_sha256']='0'*64
        p.write_bytes(v2.canonical(data));self.reject('V2_INDEX_MISMATCH')

    def test_duplicate_manifest_fields(self):
        p=self.package/'verification_manifest.json';data=p.read_bytes();p.write_bytes(b'{"format":"duplicate",'+data[1:])
        self.reject('V2_VERIFICATION_FAILED')

    def test_noncanonical_manifest(self):
        p=self.package/'verification_manifest.json';data=json.loads(p.read_bytes());p.write_bytes(json.dumps(data,indent=2).encode())
        self.reject('V2_MANIFEST_ENCODING_INVALID')

    def test_wrong_tenant_expected_binding(self):
        bindings=dict(self.bindings,tenant_id='tenant-B');self.reject('V2_BINDING_MISMATCH',expected_bindings=bindings)

    def test_wrong_actor_expected_binding(self):
        bindings=dict(self.bindings,actor_reference='sha256:'+'0'*64);self.reject('V2_BINDING_MISMATCH',expected_bindings=bindings)

    def test_wrong_source_expected_binding(self):
        bindings=dict(self.bindings,source_commit='0'*40);self.reject('V2_BINDING_MISMATCH',expected_bindings=bindings)

    def test_wrong_policy_expected_binding(self):
        bindings=dict(self.bindings,tsa_policy_hash='sha256:'+'0'*64);self.reject('V2_BINDING_MISMATCH',expected_bindings=bindings)

    def test_missing_scope_is_not_wildcard(self):
        bindings=dict(self.bindings);del bindings['resource_reference'];self.reject('V2_BINDINGS_INVALID',expected_bindings=bindings)

    def test_wildcard_tenant_is_rejected(self):
        self.reject('V2_TENANT_INVALID',expected_bindings=dict(self.bindings,tenant_id='*'))

    def test_action_cannot_widen_to_mail_sending(self):
        self.reject('V2_ACTION_PURPOSE_INVALID',expected_bindings=dict(self.bindings,action='mail.send'))

    def test_resigned_cross_tenant_body(self):
        (self.package/'tenant_context.json').write_bytes(v2.canonical({'tenant_id':'tenant-B'}));self.resign()
        self.reject('V2_TENANT_CONTENT_MISMATCH')

    def test_symlink_input(self):
        p=self.package/v2.REQUEST_FILE;data=p.read_bytes();p.unlink();external=self.package.parent/'elsewhere';external.write_bytes(data);p.symlink_to(external)
        self.reject('V2_VERIFICATION_FAILED')

    def test_hardlinked_input(self):
        p=self.package/v2.REQUEST_FILE;os.link(p,self.package.parent/'alias');self.reject('V2_VERIFICATION_FAILED')

    def test_stale_timestamp(self):
        self.reject('V2_VERIFICATION_FAILED',evaluation_time=datetime(2026,11,6,12,5,5,tzinfo=timezone.utc))

    def test_unsigned_report_is_not_trusted_output(self):
        (self.package/v2.UNSIGNED_REPORT_FILE).write_bytes(b'CLAIMED ALLOW / NOT AUTHORITY')
        result=self.check();self.assertIn('EXPORT_EXECUTION_AUTHORITY',result.remaining_requirements)

    def test_mutation_after_actual_native_verification_is_rejected(self):
        actual=v2.inspect_timestamp_temporal
        def verify_then_change(**kwargs):
            result=actual(**kwargs);(self.package/v2.REQUEST_FILE).write_bytes(b'changed-after-native');return result
        with patch.object(v2,'inspect_timestamp_temporal',side_effect=verify_then_change):self.reject('V2_INPUT_CHANGED')

    def test_root_replacement_with_identical_bytes_is_rejected(self):
        actual=v2.inspect_timestamp_temporal
        def verify_then_replace(**kwargs):
            result=actual(**kwargs);old=self.package.parent/'old';self.package.rename(old);shutil.copytree(old,self.package);return result
        with patch.object(v2,'inspect_timestamp_temporal',side_effect=verify_then_replace):self.reject('V2_INPUT_CHANGED')

    def test_inputs_are_unchanged(self):
        before={p.name:v2.digest(p.read_bytes()) for p in self.package.iterdir()};self.check()
        self.assertEqual(before,{p.name:v2.digest(p.read_bytes()) for p in self.package.iterdir()})

    def test_concurrent_native_v2_inspections(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            result=list(pool.map(lambda _:self.check(),range(4)))
        self.assertTrue(all(v==result[0] for v in result))


if __name__=='__main__':unittest.main()
