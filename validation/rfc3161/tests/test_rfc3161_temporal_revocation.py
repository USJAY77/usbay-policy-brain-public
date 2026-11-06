"""Native signed-time and signed-CRL tests; no keys, issuance or live transport.

PKITS historical evaluation is explicit test scope and not current production
revocation evidence. It is a different chain from the timestamp fixture.
"""
import base64
import concurrent.futures
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_rfc3161_crypto_native import crypto, TimestampHarness, ROOT, PROFILE


class TemporalNativeTests(TimestampHarness, unittest.TestCase):
    def args(self):
        args=super().args()
        args['evaluation_time']=datetime(2025,5,9,11,59,0,tzinfo=timezone.utc)
        return args

    def temporal(self, **changes):
        args=self.args();args.update(max_age_seconds=300,clock_skew_seconds=0,maximum_accuracy_seconds=1);args.update(changes)
        return crypto.inspect_timestamp_temporal(**args)

    def reject_temporal(self, code, **changes):
        with self.assertRaises(crypto.TimestampCryptoError) as raised:self.temporal(**changes)
        self.assertEqual(str(raised.exception),code)

    def test_actual_signed_time_and_accuracy(self):
        result=self.temporal()
        self.assertEqual(result.signed_generated_at,'2025-05-09T11:58:55+00:00')
        self.assertEqual(result.signed_accuracy_microseconds,1000000)
        self.assertIn('SIGNED_REVOCATION_EVIDENCE',result.remaining_requirements)
        self.assertIn('GOVERNED_CLOCK_AND_FRESHNESS_PROFILE_ADOPTION',result.remaining_requirements)

    def test_current_clock_rejects_old_fixture(self):
        self.reject_temporal('TSA_TIMESTAMP_STALE',evaluation_time=datetime(2026,11,6,tzinfo=timezone.utc))

    def test_whole_uncertainty_interval_must_fit_age(self):
        self.reject_temporal('TSA_TIMESTAMP_STALE',max_age_seconds=5)

    def test_exact_age_boundary(self):
        self.assertEqual(self.temporal(max_age_seconds=6).max_age_seconds,6)

    def test_future_interval_is_rejected(self):
        self.reject_temporal('TSA_TIMESTAMP_IN_FUTURE',evaluation_time=datetime(2025,5,9,11,58,55,tzinfo=timezone.utc))

    def test_explicit_skew_boundary(self):
        result=self.temporal(evaluation_time=datetime(2025,5,9,11,58,54,tzinfo=timezone.utc),clock_skew_seconds=2)
        self.assertEqual(result.clock_skew_seconds,2)

    def test_insufficient_skew(self):
        self.reject_temporal('TSA_TIMESTAMP_IN_FUTURE',evaluation_time=datetime(2025,5,9,11,58,54,tzinfo=timezone.utc),clock_skew_seconds=1)

    def test_accuracy_limit_is_checked(self):
        self.reject_temporal('TSA_ACCURACY_EXCEEDED',maximum_accuracy_seconds=0)

    def test_missing_profile_is_not_defaulted(self):
        self.reject_temporal('TSA_FRESHNESS_PROFILE_INVALID',max_age_seconds=None)

    def test_boolean_is_not_age_integer(self):
        self.reject_temporal('TSA_FRESHNESS_PROFILE_INVALID',max_age_seconds=True)

    def test_unbounded_skew_is_rejected(self):
        self.reject_temporal('TSA_FRESHNESS_PROFILE_INVALID',clock_skew_seconds=61)

    def test_signature_is_verified_before_time_is_used(self):
        damaged=bytearray(self.args()['response_der']);damaged[-10]^=1
        self.reject_temporal('TSA_SIGNATURE_CHAIN_IMPRINT_POLICY_FAILED',response_der=bytes(damaged))

    def test_concurrent_native_time_checks(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(lambda _:self.temporal(),range(4)))
        self.assertTrue(all(v==results[0] for v in results))

    def test_native_decoder_rejects_truncated_der(self):
        with tempfile.TemporaryDirectory() as temporary:
            p=Path(temporary);(p/'input.der').write_bytes(self.args()['response_der'][:30])
            result=subprocess.run([str(crypto.INFO_ENGINE),str(p/'input.der'),str(p/'out.json')],
                                  stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse((p/'out.json').exists())

    def test_missing_native_time_adapter_fails_closed(self):
        with patch.object(crypto,'INFO_ENGINE',Path('/does-not-exist/time-adapter')):
            self.reject_temporal('TSA_INFO_ENGINE_UNAVAILABLE')


class RevocationNativeTests(unittest.TestCase):
    def args(self):
        p=ROOT/'fixtures/pkits'
        return dict(certificate_pem=(p/'certs/ValidCertificatePathTest1EE.crt.pem').read_bytes(),
                    intermediates_pem=(p/'certs/GoodCACert.crt.pem').read_bytes(),
                    roots_pem=(p/'certs/TrustAnchorRootCertificate.crt.pem').read_bytes(),
                    crls_pem=(p/'crls/TrustAnchorRootCRL.crl.pem').read_bytes()+(p/'crls/GoodCACRL.crl.pem').read_bytes(),
                    evaluation_time=datetime(2010,1,1,8,31,tzinfo=timezone.utc),max_crl_age_seconds=3600)

    def check(self, **changes):
        args=self.args();args.update(changes);return crypto.inspect_certificate_revocation(**args)

    def reject(self, code, **changes):
        with self.assertRaises(crypto.TimestampCryptoError) as raised:self.check(**changes)
        self.assertEqual(str(raised.exception),code)

    def test_actual_signed_full_chain_crls(self):
        result=self.check()
        self.assertEqual(result.crls_sha256,hashlib.sha256(self.args()['crls_pem']).hexdigest())
        self.assertIn('GOVERNED_TRUST_AND_CLOCK_ADOPTION',result.remaining_requirements)

    def test_actually_revoked_certificate_is_denied(self):
        p=ROOT/'fixtures/pkits/certs/InvalidRevokedEETest3EE.crt.pem'
        self.reject('TSA_CERTIFICATE_REVOCATION_FAILED',certificate_pem=p.read_bytes())

    def test_bad_crl_signature_is_denied(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        p=ROOT/'fixtures/pkits/crls/GoodCACRL.crl.pem'
        bad=bytearray(x509.load_pem_x509_crl(p.read_bytes()).public_bytes(Encoding.DER));bad[-1]^=1
        corrupted=x509.load_der_x509_crl(bytes(bad)).public_bytes(Encoding.PEM)
        root=(ROOT/'fixtures/pkits/crls/TrustAnchorRootCRL.crl.pem').read_bytes()
        self.reject('TSA_CERTIFICATE_REVOCATION_FAILED',crls_pem=root+corrupted)

    def test_missing_leaf_issuer_crl(self):
        root=(ROOT/'fixtures/pkits/crls/TrustAnchorRootCRL.crl.pem').read_bytes()
        self.reject('TSA_CERTIFICATE_REVOCATION_FAILED',crls_pem=root)

    def test_missing_intermediate_issuer_crl(self):
        ca=(ROOT/'fixtures/pkits/crls/GoodCACRL.crl.pem').read_bytes()
        self.reject('TSA_CERTIFICATE_REVOCATION_FAILED',crls_pem=ca)

    def test_crl_age_not_only_next_update(self):
        self.reject('TSA_CRL_TIME_INVALID',max_crl_age_seconds=59)

    def test_exact_crl_age_boundary(self):
        self.assertEqual(self.check(max_crl_age_seconds=60).max_crl_age_seconds,60)

    def test_old_crls_are_not_current_production_evidence(self):
        self.reject('TSA_CRL_TIME_INVALID',evaluation_time=datetime(2026,11,6,tzinfo=timezone.utc))

    def test_future_crl(self):
        self.reject('TSA_CRL_TIME_INVALID',evaluation_time=datetime(2010,1,1,8,29,tzinfo=timezone.utc))

    def test_expired_crl(self):
        self.reject('TSA_CRL_TIME_INVALID',evaluation_time=datetime(2030,12,31,8,30,tzinfo=timezone.utc))

    def test_missing_crls_never_become_good_status(self):
        self.reject('TSA_INPUT_INVALID',crls_pem=b'')

    def test_duplicate_crl(self):
        self.reject('TSA_CRL_INPUT_INVALID',crls_pem=self.args()['crls_pem']*2)

    def test_crl_trailing_input(self):
        self.reject('TSA_CRL_INPUT_INVALID',crls_pem=self.args()['crls_pem']+b'RAW_INPUT_CANARY')

    def test_boolean_is_not_crl_age(self):
        self.reject('TSA_CRL_PROFILE_INVALID',max_crl_age_seconds=True)

    def test_unbounded_crl_age(self):
        self.reject('TSA_CRL_PROFILE_INVALID',max_crl_age_seconds=604801)

    def test_native_revocation_input_preservation(self):
        args=self.args();before={k:hashlib.sha256(v).hexdigest() for k,v in args.items() if type(v) is bytes}
        crypto.inspect_certificate_revocation(**args)
        self.assertEqual(before,{k:hashlib.sha256(v).hexdigest() for k,v in args.items() if type(v) is bytes})


class CompositionBoundaryTests(TimestampHarness, unittest.TestCase):
    def test_partial_crl_configuration_is_not_ignored(self):
        self.reject('TSA_CRL_PROFILE_INVALID',max_crl_age_seconds=300)

    def test_old_unrelated_crls_cannot_upgrade_timestamp_observation(self):
        p=ROOT/'fixtures/pkits/crls/GoodCACRL.crl.pem'
        self.reject('TSA_CRL_TIME_INVALID',crls_pem=p.read_bytes(),max_crl_age_seconds=3600)

    def test_empty_crls_cannot_upgrade_timestamp_observation(self):
        self.reject('TSA_INPUT_INVALID',crls_pem=b'',max_crl_age_seconds=300)


class MatchingSyntheticChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='usbay-memory-tsa-test-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.vector=Path(cls.temporary.name)
        subprocess.run([str(ROOT/'validation/rfc3161/tests/make_memory_tsa_vectors')],cwd=cls.vector,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5,check=True)

    def args(self):
        p=self.vector
        return dict(response_der=(p/'test-response.der').read_bytes(),request_der=(p/'test-request.der').read_bytes(),
                    expected_imprint=hashlib.sha256(b'hello').hexdigest(),expected_policy_oid='1.2.3.4.1',
                    roots_pem=(p/'test-root.pem').read_bytes(),intermediates_pem=(p/'test-tsa.pem').read_bytes(),
                    crls_pem=(p/'test-good.crl.pem').read_bytes(),max_crl_age_seconds=3600,
                    evaluation_time=datetime(2026,11,6,12,0,5,tzinfo=timezone.utc),
                    max_age_seconds=300,clock_skew_seconds=0,maximum_accuracy_seconds=1)

    def check(self, **changes):
        args=self.args();args.update(changes);return crypto.inspect_timestamp_temporal(**args)

    def reject(self, code, **changes):
        with self.assertRaises(crypto.TimestampCryptoError) as raised:self.check(**changes)
        self.assertEqual(str(raised.exception),code)

    def test_matching_signature_signed_time_and_crl_pass(self):
        result=self.check()
        self.assertIn('SIGNED_FULL_CHAIN_CRL_REVOCATION',result.crypto.checks)
        self.assertNotIn('SIGNED_REVOCATION_EVIDENCE',result.remaining_requirements)
        self.assertIn('GOVERNED_TRUST_ADOPTION',result.remaining_requirements)
        self.assertEqual(result.signed_generated_at,'2026-11-06T12:00:00+00:00')

    def test_revoked_actual_timestamp_signer_fails(self):
        self.reject('TSA_SIGNATURE_CHAIN_IMPRINT_POLICY_FAILED',crls_pem=(self.vector/'test-revoked.crl.pem').read_bytes())

    def test_forged_matching_issuer_crl_fails(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        crl=x509.load_pem_x509_crl(self.args()['crls_pem']);bad=bytearray(crl.public_bytes(Encoding.DER));bad[-1]^=1
        corrupted=x509.load_der_x509_crl(bytes(bad)).public_bytes(Encoding.PEM)
        self.reject('TSA_SIGNATURE_CHAIN_IMPRINT_POLICY_FAILED',crls_pem=corrupted)

    def test_matching_crl_age_boundary_pass(self):
        self.assertEqual(self.check(max_crl_age_seconds=65).crypto.max_crl_age_seconds,65)

    def test_matching_crl_age_boundary_fail(self):
        self.reject('TSA_CRL_TIME_INVALID',max_crl_age_seconds=64)

    def test_matching_chain_stale_timestamp_fails(self):
        self.reject('TSA_TIMESTAMP_STALE',evaluation_time=datetime(2026,11,6,12,5,5,tzinfo=timezone.utc))

    def test_matching_chain_future_timestamp_fails(self):
        self.reject('TSA_TIMESTAMP_IN_FUTURE',evaluation_time=datetime(2026,11,6,11,59,59,tzinfo=timezone.utc))

    def test_actual_request_nonce_substitution_fails(self):
        request=bytearray(self.args()['request_der']);position=request.index(bytes.fromhex('02023039'));request[position+3]^=1
        self.reject('TSA_SUPPLIED_REQUEST_MISMATCH',request_der=bytes(request))

    def test_partial_result_cannot_hide_missing_crls(self):
        result=self.check(crls_pem=None,max_crl_age_seconds=None)
        self.assertIn('SIGNED_REVOCATION_EVIDENCE',result.remaining_requirements)

    def test_concurrent_matching_chain_checks(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(lambda _:self.check(),range(4)))
        self.assertTrue(all(result==results[0] for result in results))

    def test_only_public_artifacts_written(self):
        self.assertEqual({p.name for p in self.vector.iterdir()},
                         {'test-root.pem','test-tsa.pem','test-good.crl.pem','test-revoked.crl.pem','test-request.der','test-response.der'})
        for p in self.vector.iterdir():self.assertNotIn(b'PRIVATE KEY',p.read_bytes())

    def test_matching_inputs_remain_unchanged(self):
        before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.vector.iterdir()}
        self.check()
        self.assertEqual(before,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.vector.iterdir()})


if __name__=='__main__':unittest.main()
