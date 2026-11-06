# RFC3161 native crypto, signed-time and revocation candidate

PARTIAL: locally implemented and tested crypto-observation boundary; no export
integration, operational trust adoption or production-readiness claim.

Base USBAY source identity: 688ef2c1f4e2d7e4b3858187d8160fd4a6d01efb,
tree adf96c697211005042bc10c57b5f353bd14e15f6. This additive candidate is prepared
separately from the previous seven-file unpublished export patch. It neither
changes that patch nor changes GitHub or the active Replit application.

audit/rfc3161_crypto.py invokes native OpenSSL with fixed arguments, explicit
public roots/intermediates, an explicit evaluation time and bounded inputs.
Native round-trip parsing rejects trailing/changed response or request encoding.
Native verification checks the actual timestamp signature, explicit certificate
path and purpose, SHA256 imprint, expected TSTInfo policy and supplied request.
It uses neither stored validity booleans nor human-readable diagnostic text as
proof. A separate generated request binds expected digest/policy; the supplied
request is also verified. The inspection APIs send no requests and issue no
tokens. Synthetic issuance is confined to a separate test-only generator.

With explicit CRLs and an explicit age profile, timestamp verification enables
native `-crl_check_all` for the actual timestamp signer and chain. CRL signature,
issuer, chain coverage, revocation and validity are checked by OpenSSL. Additional
checks require signed thisUpdate/nextUpdate coverage and bounded CRL age.
Delta, indirect, partitioned and unknown critical CRL semantics are rejected;
OCSP is not implemented or silently substituted. A separate generic certificate
revocation primitive does not imply timestamp signer purpose or identify the
signer of a different timestamp response.

The temporal operation verifies the exact response first, then reads signed
genTime and accuracy using OpenSSL's native TS_RESP/TSTInfo APIs through a small
C helper. There is no handwritten ASN.1 parser or localized-text decision.
The entire signed accuracy interval must fit the supplied age/skew window.
Missing accuracy and precision above microseconds fail closed, without truncation.

The child process receives no parent credentials, CA defaults or OpenSSL config.
An empty private CA directory and the same explicit root PEM as CAfile/CAstore
prevent implicit root expansion. Child CPU, memory, file-size and descriptor
limits apply before OpenSSL exec, with a parent timeout. No shell, signing
operation, key generation or private-key material is used by inspection. Raw native stdout and
stderr are discarded; failures expose bounded reason codes only.

Frozen observations have no valid, ALLOW or execution-authority field. Technical
CRL/time gaps are removed only after their corresponding checks actually pass.
Independent governance requirements remain: adopted trust and profile, verified
clock, identity/tenant/resource/purpose binding, request origin/replay and
currentness/recovery. The partial observer may return an explicit missing-CRL
gap; it must never authorize export. Supplying a root or constructing an object
does not establish adoption or grant authority.

Validation environment: Python 3.12.14, cryptography 50.0.2, OpenSSL 3.0.13.
No dependencies were installed. These observed versions are not a qualified
production-runtime selection. Tests run only this standalone boundary, not the
USBAY application or deployment. The existing application-startup kernel
limitations are not claimed resolved by running this isolated verifier.

The native crypto/time/CRL subset has 84 unique passing cases: the 38 earlier
cases plus 46 additions, not 122. The V2 signed-input observer adds 33 cases,
bringing that subset to 117. Eighteen immutable-source projection cases bring
that candidate to 135 unique passing cases. The fixture-packaging repair adds
14 public-vector decoder cases, for 149 component cases; results remain
bound to the validated source and environment.
The new cases include actual signed-time/freshness checks, public PKITS signed
CRL paths, revoked certificates, forged CRLs and a matching synthetic timestamp,
request, certificate and CRL chain. Four engine/helper failure cases use negative
fault injection; no positive crypto result is mocked. Concurrency counts as
cases, not additional unique tests. The reconstructed public-vector request is
not historical request-origin evidence. Matching-chain tests use an actually
generated synthetic request and its native signed response.

The test-only C generator creates ephemeral keys inside EVP_PKEY memory and
frees them; no key serialization API is called. It writes only six public test
artifacts. Its root is labelled synthetic and is never registered as production
authority. Historical PKITS evaluation does not establish current CRL status.

`sh validation/rfc3161/run.sh` compiles the C helpers with warnings-as-errors and
hardening flags, then selects exactly the four component modules under
validation/rfc3161/tests. It does not
start the application or run unrelated RFC3161 tests. Compiler, headers and
libcrypto must already exist; missing tooling fails without installation.

Six additional AddressSanitizer/UBSan wrapper checks pass. LeakSanitizer aborted
with its explicit unsupported-ptrace diagnostic in this environment. That
failure is preserved; leak detection remains NOT_PROVEN and needs a supported
environment. Address/UBSan is not substituted for leak validation. The linked
OpenSSL library itself was not rebuilt with instrumentation.

The initial positive qualification failure is retained separately. OpenSSL
rejected an empty CAstore URI; the correction supplies exactly the same explicit
root PEM to both CAfile and CAstore. No verification flag was disabled.

Next integration boundary: independently verified/adopted trust-policy context,
applicable provider public CRLs/profile, trusted clock and source/context binding,
then complete export result/subject-hash integration. Native helpers must be
built into a source-bound, qualified runtime artifact; existing scanner/kernel
controls are not bypassed. This Linux test adapter does not prove macOS, Replit,
CI or deployment equivalence. No production trust policy was established by the
reviewed non-production placeholder policy.

Supported input-profile bounds are 2 MiB per DER object, 128 KiB per certificate
or CRL input, CRL age at most seven days, timestamp age at most one day and skew
at most 60 seconds. These are supported bounds, not adopted policy or grants.

Native API reference: https://github.com/openssl/openssl/blob/openssl-3.0.13/include/openssl/ts.h

The existing export hard-denial guard remains unchanged. This observation alone
must never remove it. Existing main export failure and operational authority gaps
remain open. No publication, CI run, merge, deployment or activation is performed.
