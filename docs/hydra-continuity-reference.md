# Hydra recovery continuity: local synthetic reference

This is a local, non-operational implementation of the human-selected Independent
Continuity Authority plus separate append-only witness. It does not enroll an
operational identity, authorize deployment, implement independent witness recovery,
or close EGAP-HYDRA-REMOTE-TRANSPORT-AUTH. The reference requires both
`USBAY_ENV=test` and a closed trust configuration with mode
`synthetic_reference_only`; only literal IPv4 loopback reference endpoints are
accepted. There is no production provider adapter or offline fallback.

## Contracts and authority

`security/hydra_continuity_contracts.py` owns strict canonical JSON, duplicate-field
rejection, exact field sets, Ed25519 verification and versioned trust/mandate
bindings. The continuity wire version is `usbay.hydra.continuity.v1`, with closed
operation/kind tags; the human transport mandate is explicitly v2. Unknown fields,
wrong types (including boolean generations), invalid keys, non-finite timestamps
and scope substitutions fail closed. No caller trust boolean is accepted.

Trust binds continuity identity, witness identity, logical local store identity,
generation, authority epoch, tenant, environment, policy reference/hash, three
distinct verification-key purposes, and fixed reference URLs. Key separation is
checked using decoded public-key bytes, including alternate PEM representations;
service/witness signing keys cannot be registered as human transport issuer keys. The configuration
is trusted server configuration, never request context. The synthetic fixture
generates ephemeral control, service, witness and transport-issuer keys. These
test keys do not establish human enrollment or operational custody.

The external control contract signs schema, action, fresh boot challenge, unique
authorization ID, issue/expiry, exact scope and action data. Supported provisioning
actions are PROVISION_LOCAL, PROVISION_SERVICE and PROVISION_WITNESS; they create
stores exclusively and are never invoked by admission. SET_ISSUER binds a canonical
human-approval record to the expected service head/sequence. Revoked issuers cannot
be revived in the same generation. Runtime service keys cannot sign these control
actions. Existing role checks on transport issuers are retained; no role name or
reviewer account supplies control authority.

`validate_recovery_contract` verifies a separately scoped RECOVER review contract
with expected head/sequence, target generation/epoch, revocation digest and
preservation policy. Its only mode is STOPPED_RECONCILIATION_ONLY. It returns
immutable reviewed data; no handler accepts it to reopen, recover, reset or advance
a generation. Signature validity alone does not prove current history. Operational
authorizers and independent witness recovery remain separate human decisions.

## Independent history and commit ordering

The authority owns the complete append-only issuer and consumption history in
SQLite. Its current head and sequence must match a fresh, signed live witness
observation before every transaction. Consumption uniquely binds both issuer/nonce
and issuer/authorization-ID, plus a one-use client challenge. Human signatures,
current issuer status, scope and validity are independently verified at the service.

The witness persists service-signed compare-and-append transitions and pins its own
SQLite log head in live memory. Every observation checks disk against that pin.
Its signed response binds the caller's fresh challenge, complete scope, current
service head/sequence, witness head, target inclusion and a five-second validity
window. A restored old witness database cannot silently become current while the
live memory pin remains intact.

Service consumption commits before witness publication and before a successful
receipt. These are separate transactions. A failed/uncertain commit, publication
or freshness check stops the service instance. A service crash after DB commit
but before witness append leaves a head mismatch and cannot auto-reconcile. If
both commits completed, service reopen can verify the live witness and reconstruct
consumption; the old grant remains spent. This is normal proof-based reopen of
intact history, not lost-history recovery.

A witness constructor never opens or self-baselines history. A fresh witness
process starts STOPPED_UNVERIFIED_HEAD. Initial synthetic genesis requires an
explicit control signature bound to that process's unpredictable boot challenge
and the initial service head. Existing stores cannot be re-provisioned; an old
genesis signature cannot initialize a new process after deletion. There is no
witness reopen/recovery API. Loss of its memory pin therefore stops admission even
when disk files remain readable. Full restoration of both a process and its memory,
or compromise of the configured test trust roots, is outside this local fault model.

## Shared Gateway admission boundary

Both remote-client families retain the existing shared `reserve_transport` funnel.
Before remote node I/O it verifies the existing human mandate/local registry,
opens an already-provisioned local SQLite store using mode=rw, and checks exact
schema, signed identity/scope and append-only local evidence/materialized-index
consistency. Missing, empty, corrupt, locked, unexpected or substituted storage
does not trigger creation, DDL, alternate paths or reinitialization.

The Gateway first commits CONTINUITY_PENDING locally. This burns local retry rights
before any uncertain external call. It then obtains a signed service admission
receipt and a freshly challenged witness inclusion/current-head observation.
Receipt bindings cover the canonical mandate digest, tenant/environment/policy,
issuer, node, endpoint/request, logical store, continuity identity, generation,
epoch, both unique consumption hashes and fresh client challenge. The service
signature, receipt fields and freshness are checked before committing local
START_RESERVED. Prior evidence is retained in a separate append-only events table;
the replay row is only its materialized current view. Freshness and local authority
are rechecked after storage waits before returning to the node opener. The second
local transaction requires the exact original pending row and exactly one updated
row; a local snapshot restored during the independent call cannot fabricate final
local evidence or produce admission.

Timeout, lost reply, local commit failure or killed client never releases a
reservation. A historical duplicate can be audited but cannot grant new dispatch.
Node effects and terminal evidence do not share a transaction with reservation.
Revocation blocks admissions ordered after it at the authoritative service; it
cannot cancel network effects already admitted.

## Explicit migration and stopped-state rollback

There is no v1 downgrade and no automatic import of an old replay database. The
v2 mandate adds continuity/store identity, generation and epoch under the original
human issuer signature; its issuer's canonical scope must explicitly name v2.
Synthetic fixtures explicitly provision all three stores and root-sign issuer
updates. Restoring Gateway registry files does not publish issuer state to the
independent service. Operational migration/provisioning is not authorized by the
presence of these helper functions or a GitHub approval.

For code rollback, stop remote admission and preserve all committed consumption,
issuer/revocation events, witness history, receipts and uncertainty. Reverting to
the unwitnessed v1 path or restoring older databases is not a safe runtime rollback.
If service history cannot match the independently current witness, remain stopped.
If witness freshness cannot be proven, remain stopped. No generation bump,
replacement grant, enrollment or recovery permission is minted by this code.

## Validation scope

`tests/test_hydra_continuity.py` exercises real cryptography and SQLite with an
explicit in-process synthetic exchange. `tests/test_hydra_continuity_native.py`
uses separate loopback HTTP authority/witness processes, actual HTTPS node/client
processes, ephemeral keys and disposable restore domains. The original three
DENY/no-extra-entry assertions and fault semantics are retained; the migration
change is explicit v2 fixture provisioning instead of baseline schema priming.
Additional native coverage includes cloned Gateway databases, both remote clients,
service/witness rollback, unavailable processes, timeout, killed clients, service
crashes between commits and signed Gateway requests with native node quorum and
verified tenant-bound audit.

The external validation harness removes both global lifecycle settings before
every pytest session. It reuses the pinned Linux/amd64 CPython 3.11 image and
unchanged offline hash-locked dependencies, with network none and loopback-only
guards. Commands, exact node IDs, counts, failures, source/harness hashes and final
results belong to the retained validation report, not historical claims here.
Separate directories/processes and a live memory pin model independence; they do
not prove independent hosts, storage administration, key custody, external witness
durability or production readiness.
