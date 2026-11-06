# V2 signed inputs and native timestamp composition

LOCAL_CANDIDATE / NOT_ADOPTED / NO_EXPORT_AUTHORITY.

`audit/export_timestamp_v2.py` implements a read-only V2 input observer. It does
not dispatch the existing exporter, create an adoption, verify full audit/release/
WORM semantics or authorize an export. The existing main exporter and earlier
operational hard-denial proposal are unchanged.

## Exact file and signature coverage

V2 requires the earlier 16-file inventory plus `rfc3161_request.tsq` and
`tsa_revocation.crl.pem`, for exactly 18 files. The timestamp response is native
DER. A V1 marker, extra/missing files and alternate format guesses are rejected.
Readers are reused byte-for-byte from the previous bounded-input proposal.
Reads reject symlinks, hardlinks, nonregular files, rebinding and oversized data.
This observer limits each file to 2 MiB and the whole snapshot to 32 MiB.

The 14 payload files are covered by `verification_manifest.json` evidence hashes.
The canonical manifest binds exact tenant/actor/resource/source/policy/action/
purpose values and the timestamp preimage. An externally supplied expected manifest
hash is required. The canonical index references the exact manifest and payload
hashes. A separate Ed25519 signature binds manifest hash, index hash and signer
public-key fingerprint; the expected signer key is supplied independently, never
loaded from package metadata. The manifest, index and signature cannot hash
themselves; coverage is explicit rather than circular.

`verification_report.md` remains an UNTRUSTED derived report excluded from signing
basis. It is never read as authority or copied as trusted output. Its observed
bytes are hashed and checked for mutation, but a signed-input observation is not
a validation of report claims. A future export must regenerate a bounded report.

## Timestamp preimage

The pre-timestamp canonical preimage contains a fixed V2 domain, all exact context
bindings, and hashes of six pre-timestamp files: audit.jsonl, ledger.sha256,
signatures.json, consensus_evidence.json, governance_release.json and
tenant_context.json. It excludes the request containing that imprint, response,
CRLs and final manifest/index/signature, avoiding circular dependencies.

The final package signature covers request, response and CRLs. Native verification
independently recomputes the preimage and checks the real signed response, expected
TSTInfo policy, request/nonce, chain, signed time/accuracy and signed full-chain
CRLs under explicit root/clock/profile inputs. A signed `valid=true` metadata
boolean cannot replace those checks. Every input is read again after native
verification; the root directory identity must also remain unchanged.

## Authority and validation scope

The result is `ExportTimestampV2Observation`, never ALLOW, a general `valid` flag
or execution authority. Passing expected references, signer keys, roots and clock
parameters does not adopt them. Full audit/ledger/release/WORM validation, verified
source/native build, adopted signer/TSA context, request origin/replay, currentness/
recovery and export execution authority remain explicit downstream requirements.
No caller callback or manufactured positive governance result is accepted.

33 original tests validate actual signed V2/native composition, tampering, resigned
core/nonce/revoked-signer cases, false validity claims, signer/index substitution,
wrong context, V1 downgrade, filesystem aliases, mutation after genuine native
verification, identical-byte root replacement and concurrency. The package signer
is an ephemeral in-memory Ed25519 test key, distinct from the test TSA's in-memory
EC keys. No private key is serialized, written to files or published.

Synthetic audit/release/WORM bodies deliberately establish no full semantic
validity. Positive observations must not be described as passing the existing
exporter. Source/registry/kernel/runtime integration is still unvalidated.

Run `sh validation/rfc3161/run.sh` to compile native test helpers and execute the
explicit component test modules. Existing application modules are not started.
No dependencies, policy changes, publication or operational actions are performed.

Patch composition: this full additive candidate targets clean main 688ef2c1.
It originally included audit/export_input_contract.py from the separate seven-file
input proposal. The PR428 review repair now retires its legacy package observer:
inspect_preissued_package raises EXPORT_SOURCE_TREE_BINDING_UNAVAILABLE because
that reader has no verifiable signed-tree contract. Supplying matching metadata
or a claimed signature cannot establish one. Shared bounded readers remain intact
for V2; there is no V1 fallback or implicit migration. Reconcile that changed shared
path before combining proposals. The active GitHub/Replit exporter is unchanged.

V2 additionally requires the exact bytes of package_signature.json to equal
canonical(signature). Reordering, indentation, surrounding whitespace, a trailing
newline or alternate JSON escaping are rejected as V2_SIGNATURE_ENCODING_INVALID,
even when they decode to the same correctly signed object. Signature verification
is still mandatory. Five encoding regressions, one wrong expected-tree case and
three legacy denial cases were added; canonical signed V2 positive cases remain.
