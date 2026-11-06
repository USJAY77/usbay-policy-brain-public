"""Test-only public DER vectors; no private keys, trust grants or scanner exceptions."""
import base64
import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

VECTOR_FILE = Path(__file__).resolve().parents[3] / 'fixtures/public-x509-vectors.json'
MAX_BYTES = 131072


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('PUBLIC_VECTOR_DUPLICATE_FIELD')
        value[key] = item
    return value


def decode_public_vectors(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
        raise ValueError('PUBLIC_VECTOR_SIZE_INVALID')
    try:
        data = json.loads(raw, object_pairs_hook=_object)
        if (type(data) is not dict or set(data) != {'schema', 'vectors'}
                or data['schema'] != 'usbay.public_x509_test_vectors.v1'
                or type(data['vectors']) is not dict or not 1 <= len(data['vectors']) <= 16):
            raise ValueError('PUBLIC_VECTOR_SCHEMA_INVALID')
        canonical = json.dumps(data, sort_keys=True, separators=(',', ':')).encode() + b'\n'
        if raw != canonical:
            raise ValueError('PUBLIC_VECTOR_ENCODING_INVALID')
        decoded = {}
        for name, item in data['vectors'].items():
            if (type(item) is not dict or set(item) != {
                    'kind', 'der_base64', 'source_pem_sha256', 'canonical_pem_sha256'}
                    or item['kind'] not in {'CERTIFICATES', 'CRLS'}
                    or type(item['der_base64']) is not list
                    or not 1 <= len(item['der_base64']) <= 8):
                raise ValueError('PUBLIC_VECTOR_SCHEMA_INVALID')
            for field in ('source_pem_sha256', 'canonical_pem_sha256'):
                digest = item[field]
                if type(digest) is not str or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                    raise ValueError('PUBLIC_VECTOR_DIGEST_INVALID')
            parts = []
            for encoded in item['der_base64']:
                if type(encoded) is not str:
                    raise ValueError('PUBLIC_VECTOR_ENCODING_INVALID')
                der = base64.b64decode(encoded, validate=True)
                if not 1 <= len(der) <= 16384 or base64.b64encode(der).decode() != encoded:
                    raise ValueError('PUBLIC_VECTOR_ENCODING_INVALID')
                parser = x509.load_der_x509_certificate if item['kind'] == 'CERTIFICATES' else x509.load_der_x509_crl
                public = parser(der)
                if public.public_bytes(Encoding.DER) != der:
                    raise ValueError('PUBLIC_VECTOR_DER_INVALID')
                parts.append(public.public_bytes(Encoding.PEM))
            pem = b''.join(parts)
            if hashlib.sha256(pem).hexdigest() != item['canonical_pem_sha256']:
                raise ValueError('PUBLIC_VECTOR_DIGEST_MISMATCH')
            decoded[name] = pem
        return decoded
    except (ValueError, TypeError, KeyError, UnicodeError):
        # Do not reflect supplied bytes or native parser diagnostics.
        raise ValueError('PUBLIC_VECTOR_INVALID') from None


def public_fixture_pem(name):
    with VECTOR_FILE.open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    vectors = decode_public_vectors(raw)
    if name not in vectors:
        raise ValueError('PUBLIC_VECTOR_MISSING')
    return vectors[name]
