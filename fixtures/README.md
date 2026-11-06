# Public offline timestamp vectors

Source: https://github.com/trailofbits/rfc3161-client
Pinned commit: 56a2a9beb253ddbd1fcac8237f67b4c0b5ef90dd.
Upstream license is retained in LICENSE. No private keys are included in these
downloaded vectors. The separate matching-chain test generator keeps ephemeral
keys only in memory and writes public test artifacts only.

sigstage/response-sha256.tsr is an upstream signed response over SHA256(b'hello')
with timestamp policy 1.3.6.1.4.1.57264.2. Upstream certificate chains are public
test evidence; USBAY does not adopt these as production trust.

The sigstage test-only root and intermediate files are public certificates
split from the upstream chain. The test_tsa chain is used for wrong-root rejection.

IMPORTANT: sigstage/request.der is the upstream SHA512 request and does not match
response-sha256.tsr. It is a negative fixture. reconstructed-test-request.der is
new synthetic request material, using the response's nonce and expected digest and
policy; it demonstrates native request matching and nonce-substitution rejection.
It is NOT proof of the historical original request, nonce generation, request
authorization, freshness, replay resistance or production policy adoption.

Only public files required by the tests are included in the candidate patch.
Fixture hashes and upstream Git blob identities are recorded separately.

## Repository-safe public X.509 packaging

The ten original PEM certificate/CRL fixtures are represented in
public-x509-vectors.json as canonical base64-encoded public DER objects (13
objects). The test-only public_x509_fixtures decoder requires explicit
CERTIFICATES/CRLS types, canonical DER and JSON, bounded sizes and canonical
public PEM SHA256. Original PEM hashes remain provenance metadata. Private-key
containers, trailing bytes, invalid encodings and substitutions fail closed.
The decoder returns public PEM only in memory for the existing native verifier;
no runtime reader, scanner exemption or trust allowlist is introduced. Upstream
licenses and the signed public X.509 object bytes are preserved.
