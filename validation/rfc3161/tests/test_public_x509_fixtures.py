"""Public fixture decoding must reject private, malformed and substituted data."""
import base64
import json
import unittest

from cryptography import x509
from public_x509_fixtures import VECTOR_FILE, MAX_BYTES, decode_public_vectors, public_fixture_pem


class PublicVectorTests(unittest.TestCase):
    def setUp(self):
        self.raw = VECTOR_FILE.read_bytes()
        self.data = json.loads(self.raw)

    def encode(self):
        return json.dumps(self.data, sort_keys=True, separators=(',', ':')).encode() + b'\n'

    def first(self):
        return next(iter(self.data['vectors'].values()))

    def test_all_vectors_decode_only_public_certificates_or_crls(self):
        decoded = decode_public_vectors(self.raw)
        self.assertEqual(len(decoded), 10)
        self.assertEqual(sum(len(v['der_base64']) for v in self.data['vectors'].values()), 13)
        self.assertEqual(x509.load_pem_x509_certificates(decoded['sigstage/test-only-root.pem'])[0].subject,
                         x509.load_pem_x509_certificates(public_fixture_pem('sigstage/test-only-root.pem'))[0].subject)

    def test_no_static_pem_files_in_fixture_tree(self):
        self.assertEqual(list(VECTOR_FILE.parent.rglob('*.pem')), [])

    def test_original_public_vector_hashes_are_retained(self):
        self.assertEqual(self.data['vectors']['pkits/certs/GoodCACert.crt.pem']['source_pem_sha256'],
                         'c96a8fdc125718f68b90260bcc98844fc8692995afb1f076bee6cadce035a7e5')

    def test_missing_vector_fails(self):
        with self.assertRaises(ValueError): public_fixture_pem('unknown')

    def test_duplicate_json_field_fails(self):
        with self.assertRaises(ValueError): decode_public_vectors(b'{"schema":1,"schema":2}')

    def test_oversized_input_fails(self):
        with self.assertRaises(ValueError): decode_public_vectors(b'x'*(MAX_BYTES+1))

    def test_noncanonical_json_fails(self):
        with self.assertRaises(ValueError): decode_public_vectors(json.dumps(self.data, indent=2).encode())

    def test_unknown_kind_fails(self):
        self.first()['kind'] = 'PRIVATE_KEY'
        with self.assertRaises(ValueError): decode_public_vectors(self.encode())

    def test_unknown_field_fails(self):
        self.first()['extra'] = True
        with self.assertRaises(ValueError): decode_public_vectors(self.encode())

    def test_invalid_base64_fails(self):
        self.first()['der_base64'] = ['!?']
        with self.assertRaises(ValueError): decode_public_vectors(self.encode())

    def test_private_key_container_fails_without_material_generation(self):
        # Minimal DER PrivateKeyInfo-shaped bytes; no real key is generated or stored.
        self.first()['der_base64'] = [base64.b64encode(bytes.fromhex('300b020100300306012a040100')).decode()]
        with self.assertRaises(ValueError): decode_public_vectors(self.encode())

    def test_trailing_der_bytes_fail(self):
        item = self.first()
        item['der_base64'][0] = base64.b64encode(base64.b64decode(item['der_base64'][0])+b'X').decode()
        with self.assertRaises(ValueError): decode_public_vectors(self.encode())

    def test_digest_substitution_fails(self):
        self.first()['canonical_pem_sha256'] = '0'*64
        with self.assertRaises(ValueError): decode_public_vectors(self.encode())

    def test_wrong_public_type_fails(self):
        self.first()['kind'] = 'CRLS'
        with self.assertRaises(ValueError): decode_public_vectors(self.encode())


if __name__ == '__main__': unittest.main()
