# Bounded Hydra transport authority correction

Status: local, uncommitted candidate. Base: d5777f747ca195c1b8fcb76de11c1f2d7c2894a6.
No new PB identifier, issuer registration, operational grant, deployment,
activation, commit, push, or external edit is part of this batch.

## Human authority model

Only an explicitly enrolled human `governance_owner` may issue a Hydra transport
mandate. The existing `DurableAuthorityRegistry` human_approval domain is the
trusted local authority source. A normal human approval, media issuer, EURIA
request, GitHub approval, or runtime provenance object does not become a Hydra
transport grant implicitly. Enrollment and custody of the human's private key
remain separate, externally governed operations. Runtime reads public keys only.

The authoritative human-approval record must independently bind the tenant,
environment, policy reference/hash, validity and non-revoked status. It must also
contain `issuer_role: governance_owner`,
`transport_contract: usbay.hydra.transport_mandate.v1`, an Ed25519
`issuer_public_key_pem`, and exact `allowed_node_ids` and
`allowed_endpoint_hashes` lists. Existing registry source restrictions still apply.
No production records or keys have been created by this correction.

## Signed transport contract

The exact signed fields are declared by `security.hydra_transport_authority.FIELDS`.
They include the contract version, authorization ID, issuer reference, tenant,
environment, policy reference/hash/version, node ID, endpoint URL hash, original
Gateway request hash, ALLOW decision, nonce, issued_at and expires_at. Times are
finite numeric Unix timestamps. The signature is Ed25519 over the sorted compact
JSON of those fields; unknown fields are rejected. Maximum grant age is 300
seconds, regardless of caller freshness preferences.

This is permission for the specific transport, not permission to execute the
eventual action. It cannot depend on the Hydra consensus it is about to request.
Gateway's existing validated request and canonical tenant context remain intact.
The policy hash is normalized from Gateway's bare hexadecimal representation to
the existing registry's `sha256:` reference format.

## Detached delivery and configuration

To avoid a circular request hash, the signed mandates are not embedded in the
original Gateway request. An externally prepared server-side JSON file maps the
original request hash to a node-ID-to-mandate mapping. Each node requires its own
mandate with a distinct authorization ID and nonce.

All runtime settings are explicit and server controlled:

- `USBAY_GATEWAY_AUTHORITY_REGISTRY`: existing trusted human authority registry.
- `USBAY_HYDRA_ENVIRONMENT_REFERENCE`: canonical environment reference.
- `USBAY_HYDRA_TRANSPORT_REPLAY_DB`: protected local SQLite reservation store.
- `USBAY_HYDRA_TRANSPORT_MANDATES_PATH`: detached mandate file used by Gateway.

Nothing sets these values automatically. Missing configuration fails closed.
Applications must not expose these paths/settings to request-controlled values.
Direct client integrations may present the same signed mandate and validated
tenant/policy context; they cannot replace verification with trust booleans.

## Admission and evidence

Both remote clients independently verify the mandate at the transport boundary.
Issuer state is rechecked before the reservation commits. SQLite BEGIN IMMEDIATE
and unique nonce/authorization constraints serialize admission, with a durable
START_RESERVED receipt in the same transaction. Receipts contain bindings and
hashes, not raw requests, private keys, mandate signatures or endpoint URLs.
Failure to commit blocks transport. A timeout never releases the reservation.
HTTP redirects are blocked so an endpoint grant cannot authorize another URL.
Existing urllib proxy routing is preserved by this bounded transport opener.
Authorization objects are removed from the forwarded node context.

## Validation evidence

On the unchanged base, a bounded direct-client reproduction used an unsigned
caller dictionary with evidence_verified/trust_material_available true and
replayed/revoked false. With urlopen mocked, the same context reached the mock
transport twice and returned two valid signed test votes. No issuer registry or
mandate signature was supplied. This proves a direct-client trust gap under the
synthetic calling conditions, not external HTTP exploitability. Existing Gateway
requests without a transport grant still fail closed.

The correction has a regression that attempts that unsigned context twice and
requires zero transport entries. Positive cases use synthetic human-issued
Ed25519 mandates and temporary native registry/SQLite stores.

Latest final regression batch after HTTP Gateway integration: CPython 3.11.17, 256 passed in 3.82s, exit 0:

```
python -m pytest -q tests/test_hydra_transport_authority.py tests/test_hydra_live_client.py tests/test_durable_authority_registries.py tests/test_hydra_consensus.py tests/test_hydra_stack.py tests/test_gateway_hydra.py tests/test_hydra_node_service.py tests/test_gateway_authorization_request_consumer.py
```

The subsequently added baseline-reproduction regression passed separately: 1 passed
in 0.09s, exit 0. This brings the previously verified unique test coverage to 241. Earlier development runs: 59 passed on Python
3.12 (supplemental only), then 143 and 152 passed on Python 3.11.17. One attempted
batch used a nonexistent test filename and collected no tests (exit 4); the path
was corrected, without suppressing or deselecting any failing assertions. An
initial import attempt failed because the fresh environment lacked requests;
dependencies were installed only in isolated local virtual environments.

Coverage includes 16 simultaneous attempts with one admission, reopen/replay,
timeout/replay, tenant/environment/policy/endpoint/node substitution, signature
tampering, missing configuration, issuer revocation/scope/role, corrupt storage,
missing storage parent, directory instead of database, commit failure, detached
Gateway delivery and redirect refusal. Network transport is mocked. Existing
Gateway consumer and Hydra consensus/node regressions are included.

Repository dependency files and workflows are unchanged. Local test dependencies
were resolved from requirements.txt and differ from historical CI, including
FastAPI 0.156.4 and cryptography 50.0.2. This is not CI-version parity evidence.

## Remaining boundaries

Local trusted registry/storage and protected server configuration are assumed.
The authority registry and reservation DB are separate stores: revocation after
the last check and before network I/O is not an atomic distributed transaction.
Registry/DB rollback, lost reservation history, independent hosts, DNS changes,
production PKI/key custody, authentic external node enrollment, real network
transport and operational activation require separate evidence. START_RESERVED
does not claim completed transport. Network effects and later consensus/evidence
are not one atomic transaction; uncertainty must not trigger automatic retry.

The historical closure record is preserved as evidence, not silently rewritten.
This candidate does not close the broader production transport assurance gap or
start the AI Act implementation. Human review and current CI are still required
before publication/merge decisions.

## Review correction evidence

The previous immutable patch is retained with SHA-256
71d5be777ecd9a6650a684131e31d1368b7aab0ae5241bca3ac813555b69db88.
Ten added regression cases failed before implementation changes (10 failed, 35
deselected, exit 1) and passed afterward (10 passed, 35 deselected, exit 0).
The original failure output is retained outside Git as
`hydra-review-reproduction.txt`.

Corrections:

- Sample fresh wall time and monotonic elapsed time after storage waits and
  after commit. Revalidate mandate and issuer validity after registry reads.
  Expiry after commit blocks transport and retains the committed reservation.
- Require nonempty lists of distinct, nonempty strings for issuer allowlists;
  endpoint allowlist entries must be canonical SHA-256 hex digests. Strings and
  mappings cannot become substring/key-based allowlists.
- Preserve existing urllib proxy routing while continuing to reject redirects.
- Freeze node, endpoint, timeout and nested request context; serialize the
  outbound request before authorization and use the same captured node and
  endpoint for validation, request dispatch and response checks.

An additional registry-read expiry test covers the independent registry lock
window. The final complete bounded suite passed 252 tests in 3.71s. Dependency
compatibility and git diff --check pass. No GitHub CI or real network transport
was run for this candidate. Final output is retained as
`hydra-review-corrected-validation-final.txt`; intermediate 251-pass output is
retained as `hydra-review-corrected-validation.txt`. These are separate from the
original failure output. This is a correction candidate, not an independently
approved security assessment or publication authorization.

## HTTP Gateway quorum integration

Four additional parameterized cases exercise the actual signed HTTP /decide
route, using existing signed runtime, request and attestation fixtures. Gateway
request validation, policy loading, tenant authority, real Hydra client classes,
human mandate signature verification, durable reservations, vote signature
verification, quorum evaluation and signed audit verification remain active.
Only network I/O is mocked; the human issuer and node keys are synthetic.
No execution route, application adapter or provider is invoked.

The valid case supplies distinct signed authorization IDs and nonces for node1
and node2. Node3 has no mandate and must not reach transport. The HTTP response
is ALLOW, the stored Gateway decision signature verifies, both node reservations
are present and the tenant-bound audit chain verifies. Repeating the HTTP request
is blocked by request replay protection. Independently repeating the internal
consensus path cannot reuse either transport grant and initiates no further I/O.

Negative cases cover swapping the node1 grant into node2's slot, tampering with
the original Gateway request signature, and grants issued for a different tenant.
None may produce ALLOW or additional unauthorized transport.

The first integration run produced 3 failed / 1 passed, exit 1. A sanitized
exception trace located LedgerIntegrityError in the live-consensus audit append:
the existing live aggregation returned no full evidence bundle, and the audit
entry consequently omitted tenant identity. The immutable ledger rejected it.
This evidence is retained in hydra-gateway-quorum-validation.txt and
hydra-gateway-quorum-diagnostic.txt outside Git.

The bounded correction passes the already validated canonical Gateway tenant
context into audit_hydra_consensus as a fallback when the result has no tenant
metadata. Ledger validation remains enabled. No consensus/attestation evidence
or signature is manufactured. Existing full evidence-bundle tenant metadata
continues to take precedence. The corrected four HTTP cases pass.

Final bounded validation: 256 passed in 3.82s on CPython 3.11.17, exit 0, with
unchanged assertions in the earlier regressions. Output is retained outside Git
as hydra-gateway-quorum-final-regressions.txt. Dependency compatibility and
git diff --check pass. The V1 and V2 immutable patches are retained unchanged.
No GitHub CI, real transport, commit, publication or activation is claimed.
Local validation is complete for this batch; the next gate is authorized Draft
publication followed by exact-candidate automatic CI and human review.
