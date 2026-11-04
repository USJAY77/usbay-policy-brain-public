# Release issuance authority — unadopted proposal

Status: PROPOSAL ONLY. No policy, issuer, reviewer, key, trust anchor or release
authority is registered or activated. No writer or startup consumer imports the
prototype. USBAY-AUDIT and USBAY-GLOBAL23 have not reviewed this proposal here.

## Existing behavior and reuse boundary

`security.deployment_attestation` has a technical writer and HMAC verifier.
The inspected writer does not establish a mandatory independently authenticated
issuer/approval grant for its specific invocation. A key or signature alone is
not such a grant. No writer was invoked during this preparation.

The mutation-authority implementation supplies useful design patterns: strict
signed contracts, two separately bound reviews, exact child/parent scope and
fresh authenticated status. Its existing four-action domain does not authorize
release issuance. This proposal does not add an action to that domain.

`DurableAuthorityRegistry` storage and its VALID status must not be interpreted
as independent human identity, issuer provenance or a new release grant.
The older human-approval metadata helper is not a signature-verification route.

## Proposed exact binding

The proposed request binds actor, tenant, purpose, non-production environment,
tool and exact release-core resource; source commit AND tree; policy bundle;
predecessor; existing parent authority, issuer grant and review policy;
currentness reference; nonce; and issuance/validity times. Wildcards, missing
fields, unexpected fields and re-delegation are rejected. The legacy HMAC
manifest itself is unchanged. No GENESIS/history reset is inferred: the proposal
requires an explicit predecessor binding, whose actual validity remains a gate.

The issuer signs the complete request. Each proposed reviewer signs its exact
request-envelope hash and decision. Reviewer IDs, key IDs and public keys must
be independent; reviewer labels in tests establish no human authority. Review
key intervals must cover the requested interval. The prototype binds supplied
context exactly but cannot establish its external truth.

## Prototype result and remaining mandatory interfaces

`inspect_release_issuance_evidence` reuses existing strict JSON, canonical hash
and UTC-time primitives plus Ed25519 verification. It inspects bytes against
separately supplied public bindings. Even fully valid synthetic evidence yields
DENY / LIVE_ISSUANCE_AUTHORITY_NOT_ESTABLISHED. It never produces an ALLOW token.

Before a future authority verifier can allow issuance, all of these must be
implemented and independently provisioned under an adopted human contract:

- authenticated parent/issuer scope and approved key provenance;
- current reviewer identity and adopted review-policy resolution;
- authenticated fresh revocation/currentness, protected against rollback;
- durable replay reservation, exact request binding and single consumption;
- held source/predecessor CAS and commit fence through writer COMMIT;
- verified mapping of the signed proposed core to the exact legacy manifest;
- immutable bounded audit evidence and uncertain-commit/recovery handling.

These are interface requirements, not caller booleans that may bypass gates.
No references in a well-signed dossier prove these facts by themselves.

## Human decisions still unresolved

All of the following remain UNRESOLVED: applicable issuer and parent domain;
review roles/threshold adoption; allowed source/tool/resource/environment scope;
validity/freshness limits; predecessor/GENESIS rules; authority/replay storage and
recovery rules; and applicable signing/verifying custody. Suggested bindings and
test labels in this proposal do not settle those decisions.

No implementation, synthetic signature, owner chat confirmation, review-ready
status or green test substitutes for independently verifiable issued authority.
Production, publication, deployment and activation remain outside this proposal.
