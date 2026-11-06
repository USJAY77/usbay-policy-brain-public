"""Real public signed vectors; no signer/private keys or live TSA calls.

The request used for the SHA256 fixture is RECONSTRUCTED test data, not evidence
of its historical request origin or freshness. Trust here is explicitly test-only.
"""
import concurrent.futures
from dataclasses import FrozenInstanceError, asdict
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('usbay_rfc3161_crypto_candidate', ROOT/'audit/rfc3161_crypto.py')
crypto = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = crypto
SPEC.loader.exec_module(crypto)
VECTORS = ROOT/'fixtures'
PROFILE = VECTORS/'sigstage'


class TimestampHarness:
    def args(self):
        return dict(response_der=(PROFILE/'response-sha256.tsr').read_bytes(),
                    request_der=(PROFILE/'reconstructed-test-request.der').read_bytes(),
                    expected_imprint=hashlib.sha256(b'hello').hexdigest(),
                    expected_policy_oid='1.3.6.1.4.1.57264.2',
                    roots_pem=(PROFILE/'test-only-root.pem').read_bytes(),
                    intermediates_pem=(PROFILE/'test-only-intermediates.pem').read_bytes(),
                    evaluation_time=datetime(2026,11,6,tzinfo=timezone.utc))

    def reject(self, expected_code=None, **changes):
        args = self.args(); args.update(changes)
        with self.assertRaises(crypto.TimestampCryptoError) as raised:
            crypto.inspect_timestamp_crypto(**args)
        if expected_code:
            self.assertEqual(str(raised.exception), expected_code)
        return str(raised.exception)


class NativeTimestampCryptoTests(TimestampHarness, unittest.TestCase):
    def test_real_sha256_signature_chain_and_policy(self):
        observed = crypto.inspect_timestamp_crypto(**self.args())
        self.assertEqual(observed.expected_imprint, hashlib.sha256(b'hello').hexdigest())
        self.assertIn('CMS_SIGNATURE', observed.checks)
        self.assertIn('SIGNED_REVOCATION_EVIDENCE', observed.remaining_requirements)

    def test_response_tampering_rejected_by_native_verifier(self):
        damaged = bytearray(self.args()['response_der']);damaged[-10] ^= 1
        self.reject('TSA_SIGNATURE_CHAIN_IMPRINT_POLICY_FAILED', response_der=bytes(damaged))

    def test_wrong_message_imprint(self):
        self.reject('TSA_SIGNATURE_CHAIN_IMPRINT_POLICY_FAILED', expected_imprint='0'*64)

    def test_digest_of_digest_is_not_original_message(self):
        self.reject('TSA_SIGNATURE_CHAIN_IMPRINT_POLICY_FAILED', expected_imprint=hashlib.sha256(bytes.fromhex(self.args()['expected_imprint'])).hexdigest())

    def test_hex_text_is_not_original_message(self):
        self.reject('TSA_SIGNATURE_CHAIN_IMPRINT_POLICY_FAILED', expected_imprint=hashlib.sha256(self.args()['expected_imprint'].encode()).hexdigest())

    def test_wrong_tstinfo_policy(self):
        self.reject('TSA_SIGNATURE_CHAIN_IMPRINT_POLICY_FAILED', expected_policy_oid='1.3.6.1.4.1.57264.3')

    def test_wrong_request_sha512(self):
        self.reject('TSA_SUPPLIED_REQUEST_MISMATCH', request_der=(PROFILE/'request.der').read_bytes())

    def test_reconstructed_nonce_substitution(self):
        request = bytearray(self.args()['request_der']);request[-1] ^= 1
        self.reject('TSA_SUPPLIED_REQUEST_MISMATCH', request_der=bytes(request))

    def test_response_trailing_bytes_rejected(self):
        self.reject('TSA_ENCODING_AMBIGUOUS', response_der=self.args()['response_der']+b'RAW_INPUT_CANARY')

    def test_request_trailing_bytes_rejected(self):
        self.reject('TSA_ENCODING_AMBIGUOUS', request_der=self.args()['request_der']+b'RAW_INPUT_CANARY')

    def test_mock_json_never_replaces_der(self):
        self.reject('TSA_RESPONSE_DER_INVALID', response_der=b'eyJ2YWxpZCI6dHJ1ZX0=')

    def test_truncated_response(self):
        self.reject('TSA_RESPONSE_DER_INVALID', response_der=self.args()['response_der'][:40])

    def test_invalid_request_der(self):
        self.reject('TSA_REQUEST_DER_INVALID', request_der=b'not DER')

    def test_expired_chain_at_explicit_evaluation_time(self):
        self.reject('TSA_SIGNATURE_CHAIN_IMPRINT_POLICY_FAILED', evaluation_time=datetime(2040,1,1,tzinfo=timezone.utc))

    def test_not_yet_valid_chain(self):
        self.reject('TSA_SIGNATURE_CHAIN_IMPRINT_POLICY_FAILED', evaluation_time=datetime(2020,1,1,tzinfo=timezone.utc))

    def test_wrong_explicit_root_does_not_fall_back(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        root = x509.load_pem_x509_certificates((VECTORS/'test_tsa/ts_chain.pem').read_bytes())[-1]
        self.reject('TSA_SIGNATURE_CHAIN_IMPRINT_POLICY_FAILED', roots_pem=root.public_bytes(Encoding.PEM))

    def test_parent_ca_environment_cannot_replace_wrong_explicit_root(self):
        with patch.dict(os.environ,{'SSL_CERT_FILE':str(PROFILE/'test-only-root.pem'),
                                   'OPENSSL_CONF':'/does-not-exist/untrusted-config'}):
            self.test_wrong_explicit_root_does_not_fall_back()

    def test_raw_token_cannot_be_substituted_for_response(self):
        result=subprocess.run(['/usr/bin/openssl','ts','-reply','-in',str(PROFILE/'response-sha256.tsr'),'-token_out'],
                              stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True)
        self.reject('TSA_RESPONSE_DER_INVALID',response_der=result.stdout)

    def test_nonroot_intermediate_cannot_be_promoted(self):
        self.reject('TSA_CERTIFICATE_INPUT_INVALID', roots_pem=self.args()['intermediates_pem'])

    def test_duplicate_root(self):
        self.reject('TSA_CERTIFICATE_INPUT_INVALID', roots_pem=self.args()['roots_pem']*2)

    def test_noncertificate_pem_prohibited(self):
        self.reject('TSA_CERTIFICATE_INPUT_INVALID', roots_pem=b'-----BEGIN NOT_A_CERTIFICATE-----\nRAW_INPUT_CANARY\n-----END NOT_A_CERTIFICATE-----')

    def test_certificate_trailing_input_prohibited(self):
        self.reject('TSA_CERTIFICATE_INPUT_INVALID', roots_pem=self.args()['roots_pem']+b'RAW_INPUT_CANARY')

    def test_missing_root(self):
        self.reject('TSA_INPUT_INVALID', roots_pem=b'')

    def test_missing_intermediates(self):
        self.reject('TSA_INPUT_INVALID', intermediates_pem=b'')

    def test_oversized_response(self):
        self.reject('TSA_INPUT_INVALID', response_der=b'x'*(crypto.MAX_DER_BYTES+1))

    def test_no_string_to_bytes_autocorrection(self):
        self.reject('TSA_INPUT_INVALID', response_der='not bytes')

    def test_naive_clock(self):
        self.reject('TSA_EVALUATION_TIME_INVALID', evaluation_time=datetime(2026,11,6))

    def test_fractional_clock_is_not_silently_truncated(self):
        self.reject('TSA_EVALUATION_TIME_INVALID', evaluation_time=datetime(2026,11,6,0,0,0,1,tzinfo=timezone.utc))

    def test_imprint_injection_is_not_an_argument(self):
        self.reject('TSA_IMPRINT_INVALID', expected_imprint='0'*64+' --no_check_time')

    def test_oid_injection_is_not_an_argument(self):
        code=self.reject('TSA_POLICY_INVALID', expected_policy_oid='1.2.3\nRAW_INPUT_CANARY')
        self.assertNotIn('CANARY',code)

    def test_oid_alias_is_not_numeric_policy(self):
        self.reject('TSA_POLICY_INVALID', expected_policy_oid='tsa_policy1')

    def test_invalid_oid_arcs(self):
        self.reject('TSA_POLICY_INVALID', expected_policy_oid='1.99.3')

    def test_input_bytes_remain_unchanged(self):
        args=self.args();before={k:hashlib.sha256(v).hexdigest() for k,v in args.items() if type(v) is bytes}
        crypto.inspect_timestamp_crypto(**args)
        self.assertEqual(before,{k:hashlib.sha256(v).hexdigest() for k,v in args.items() if type(v) is bytes})

    def test_concurrent_native_inspections_are_deterministic(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(lambda _: crypto.inspect_timestamp_crypto(**self.args()),range(4)))
        self.assertTrue(all(v==results[0] for v in results))

    def test_observation_cannot_claim_general_validity_or_allow(self):
        observed=crypto.inspect_timestamp_crypto(**self.args())
        data=asdict(observed)
        self.assertFalse({'valid','allow','decision','authority'} & data.keys())
        self.assertTrue(observed.remaining_requirements)
        with self.assertRaises(FrozenInstanceError):observed.expected_policy_oid='1.2.3'


class EngineFailureUnitTests(TimestampHarness, unittest.TestCase):
    # Only these three cases use failure injection; no positive crypto result
    # is ever simulated.
    def test_missing_engine_fails_closed(self):
        with patch.object(crypto,'ENGINE',Path('/does-not-exist/usbay-openssl')):
            self.reject('TSA_ENGINE_UNAVAILABLE')

    def test_engine_timeout_has_bounded_error(self):
        with patch.object(crypto.subprocess,'run',side_effect=subprocess.TimeoutExpired('redacted',5)):
            self.reject('TSA_ENGINE_TIMEOUT')

    def test_engine_process_error_has_bounded_error(self):
        with patch.object(crypto.subprocess,'run',side_effect=OSError('RAW_INPUT_CANARY')):
            self.reject('TSA_ENGINE_UNAVAILABLE')


if __name__=='__main__':unittest.main()
