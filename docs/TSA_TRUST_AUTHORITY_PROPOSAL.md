# TSA trust-authority integration proposal

DESIGN_REVIEW_ONLY / NOT_ADOPTED / NOT_READY_FOR_OPERATIONAL_APPROVAL.
The authoritative reference to any already adopted TSA policy remains UNKNOWN.
The user's continuation does not select roots, establish policy or adopt trust.

## Proposed boundary

Proposed domain: `usbay.timestamp_verification.v1`.
Purpose: independently verify timestamp evidence for an exactly scoped audit
package. It grants no mail sending, external provider operation, export execution,
policy authoring, deployment, activation, recovery, remote transport or delegation.

Current `policy/policy.json` has `scope=ci_security`; its existing adoption reader
must not accept a caller-selected TSA policy under that CI authority. Reuse the
pattern of signed policy validation plus exact scoped-adoption revalidation,
after the correct TSA policy-authority mechanism has been independently established.
CI evidence signers and package-supplied certificates are not TSA trust roots.

## Required adopted inputs and bindings

| Required field | Evidence required | Present proposal status |
| --- | --- | --- |
| Governing policy authority/domain | Valid machine-verifiable authority to govern TSA trust in the exact scope | UNRESOLVED |
| TSA policy version/hash | Exact signed bytes, schema/version, validity and adoption record | UNRESOLVED |
| Public TSA roots/signers | Exact public identities/fingerprints, independent provenance and allowed chain/profile | UNRESOLVED |
| Tenant/actor/resource/environment | Verified identity and exact matching scope; no GLOBAL or wildcard inference | UNRESOLVED |
| Action/purpose | Proposed audit.timestamp.verify / audit_export_integrity, separately authorized by governing policy | PROPOSED_ONLY |
| Digest/policy/nonce profile | Explicit permitted digest, TSTInfo OID and original-request/nonce/replay requirements | UNRESOLVED |
| Trusted clock/freshness/accuracy | Authenticated clock/currentness and bounded receipt/uncertainty profile | UNRESOLVED |
| Revocation/currentness | Applicable signed CRLs, freshness, root/policy revocation and rotation evidence | UNRESOLVED |
| Human-reserved adoption | Independently verified distinct authorized reviewers and exact policy/scope bindings through the correct mechanism | UNFILLED |
| Native implementation identity | Qualified source-bound verifier/helper/library artifacts and supported validation | PARTIAL_LOCAL_TESTS |

No unresolved field is an implicit default. Do not request approval of this
unfilled table as if it were an operational trust policy. No reviewer signature,
decision, root fingerprint, validity or adoption record is manufactured.

## Bounded software integration

The proposed V2 input observer cryptographically binds exact tenant/actor/resource,
source, policy reference and purpose/action values. Those are caller expectations,
not authority. A governed consumer must obtain them from independently verified
identity, source and adopted-policy state, then revalidate state before and after
verification and before any consequential export/attestation.

V2 covers the native response, original request and CRLs through a signed package
manifest/index, with a separate pre-timestamp preimage free from circular hashes.
No protected consumer, existing policy file, adoption store, package writer or
production guard is changed by this proposal or by the standalone observer.

## Acceptance / stops

Do not enable the route until valid adoption, exact context, currentness/revocation,
source/native-build identity, full audit/release/WORM checks and distinct export
execution authority are demonstrated. Chat confirmation and test success cannot
substitute for these inputs. Timestamp authority does not create execution authority.

Clock/receipt freshness and long-term historical evidence validation are different
profiles. The current native candidate supports bounded fresh receipt verification;
do not silently apply it as archival validation or relax it to accept old evidence.
Unsupported OCSP, delta/indirect CRLs or provider requirements fail closed pending
an explicitly governed supported profile.

Publication, CI, merge, deployment, activation and new root/policy adoption remain
outside this local proposal. Missing information can be filled from a verified
existing authoritative public reference; no secret material is requested.
