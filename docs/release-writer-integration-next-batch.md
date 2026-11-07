# Proposed next batch: dormant transactional release writer

Status: PREPARED / NOT IMPLEMENTED / NOT AUTHORIZED BY THIS DOCUMENT.
Historical proposal status above is preserved. Following the owner's batch
authorization, a dormant local implementation and synthetic validation now
exist; see release-transaction-writer-local-validation.md. No operational
adoption, active integration or publication is implied.
Baseline: dc549b2167dc6bdbe8e5b1c988bb27e9176e388e plus the local owner-contract candidate.

## Observed integration gap

security/deployment_attestation.py:748 write_release_manifest loads an existing
file, calls build_release_manifest, writes the target directly, then validates
it. build_release_manifest:699 reads source/node/tenant inputs and invokes the
legacy HMAC signer. In the inspected functions, no mandatory authenticated
release-issuer grant, transactional nonce/budget consumption or held
source/predecessor CAS is established. Direct file writing and a separate replay
store would not be one atomic transaction. This source observation is not proof
of every caller's behavior or a demonstrated live exploit.

security/intent_replay_store.py reserve commits its own SQLite transaction. It
cannot be called and then treated as an atomic release output commit. Its
open-only state, explicit provisioning, BEGIN IMMEDIATE and fail-closed error
patterns can be reused; the intent schema and its consume semantics must not
be repurposed as release authority.

## Bounded implementation proposal

Implement an import-only release transaction coordinator and versioned,
explicitly provisioned task-owned SQLite store. Provide no CLI, default store,
environment trust discovery, Gateway hook, production/staging fallback or
deployment route. Existing writer and consumer behavior remains unchanged until
a separately authorized integration replaces their invocation boundary.

The protected writer, not bindings_valid, must make its own governed decision.
Default/missing authority source, root adoption or writer configuration returns
DENY before signer invocation. Context/key lists supplied in an incoming request
must never bootstrap trust. Synthetic tests may provide explicitly isolated
fixture authorities; their outputs are not operational grants or adopted releases.

For an exact authenticated source/core/predecessor binding:

1. Open only an explicitly provisioned store. Obtain the protected write lock;
   check contract/schema/integrity and the expected state/CAS version.
2. Re-observe time and obtain independently authenticated request-bound current
   root/grant/policy/reviewer/revocation state after acquiring the lock. Verify
   the complete contract and its remaining deadline at the effect boundary.
3. Check the pinned source/core and predecessor against protected current state.
   Reject ambiguous or missing state; never infer GENESIS. The exact release
   core supplied for signing must be bound to the authorized release_core_hash.
   Do not rebuild a different core inside the legacy convenience writer.
4. Enforce one use of the tenant/issuer/nonce identity across grant/key rotation,
   and one issuance per exact issuer-grant budget. Distinct nonce and budget
   constraints must both hold. No success path may reserve outside the output
   transaction.
5. Sign only the verified exact core through an explicitly configured signer
   boundary. First tests use ephemeral synthetic HMAC material in memory.
   Store the complete signed output bytes, bounded receipt, consumed nonce and
   budget, and next predecessor/head version in one durable transaction.
6. Do not publish a release file during this first transaction batch. Committed
   bytes in the protected store and downstream file/provider publication are
   different outcomes. Export/publication requires a separate governed adapter.
7. A definite rollback produces no committed output/consumption. Ambiguous COMMIT
   returns UNKNOWN, never success or automatic retry. Reconciliation may only
   read the exact transaction identity; it must not mint, re-sign or widen scope.

An external signer is outside SQLite's atomicity. Do not claim atomic signing
plus commit, exactly-once external effects, anti-rollback against restored storage
or independently authenticated root adoption from an injected test fixture.
Those boundaries need explicit ports and remain closed when unavailable.

## Acceptance criteria

- Default/missing/wrong authority, altered core, stale status, revocation after
  waiting, source/predecessor CAS changes and expired deadline never call signer.
- Two threads and two processes contending for the same request yield at most
  one durable output plus matching nonce/budget consumption; no partial commit.
- Same nonce under rotated keys/grants, and a new nonce under a spent grant,
  cannot produce a second output.
- Faults before signing, before COMMIT and at an ambiguous COMMIT preserve the
  attempted/committed/UNKNOWN distinction. Reconciliation causes no signer call.
- Store absence/corruption/lock contention never silently provisions or repairs
  state. Metadata/head mismatch fails closed.
- Existing contract regressions and unchanged artifact-producer checks pass.

Execution scope proposed: local implementation and synthetic temporary-store
tests only; no operational keys, owner private-key access, real trust adoption,
live release, application startup, external service, publication or deployment.
Human root/issuer/tenant/custody decisions remain unresolved. This proposal does
not authorize those decisions or claim the implementation is complete.
