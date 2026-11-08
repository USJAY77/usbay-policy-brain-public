# Dormant producer-trust R1/R2 correction

NOT ADOPTED — NO PRODUCTION AUTHORITY — NO APPLICATION INTEGRATION.

Preserved base HEAD: 3fdd34305311f2e4a97d34544c95d87e0dbf781c
Preserved base tree: ae0f1774ed72add2da4a62d4f6203dca4cfc39d0
Predecessor manifest:
9c3fcc25a74f48cb4b0042c2c2d5af3be06448624a6956011ac9779f66310aa8

This is a NEW isolated task candidate. Predecessor files/logs are not modified.
Only synthetic, ephemeral signing material may be used; no application imports,
operational inputs, production storage, real roots or runtime integration.

## R1: applicable known time

The fence keeps monotone time for each exact (target, authority-context digest).
The target is app/environment/tenant/purpose; the authority digest binds exact
supplied principals, keys, roles, thresholds and freshness parameter. Existing
binding validation still binds producer/source/artifact/scope before acceptance.
No new production authority, time service or policy parameters are selected.

Snapshot authentication and scope validation precede observe. After each supplied
clock callback, observe/record capture the LATEST aggregate under the same RLock.
They recheck availability, exact authority context, ambiguity, applicable known
time, expiry and relevant snapshot/release/nonce predicates. Later inner valid
operations cannot be followed by an older outer acceptance or observation.
Valid equal-version snapshot observations update known time without rewriting
release evidence. Idempotence does not bypass time, expiry, revocation or freshness.

Rejected unauthenticated/wrong-scope/expired/rollback/foreign-context observations
do not advance known time. A fully authenticated current snapshot may advance
known time even when the subsequent release is invalid or revoked: knowledge and
release acceptance remain deliberately different state machines.
Time from another exact tenant/authority context does not advance this target.

## R2: one aggregate publication

All release/nonce/currentness/conflict/time state is held in one frozen aggregate
of mapping proxies, immutable receipts/snapshots and frozensets. Builders mutate
only private copies. All preparation and conflict-outcome allocation occurs
before _publish, which checks expected aggregate identity and replaces one
existing reference while locked. No user callback follows the final checks.
There are no two separately published release/nonce writes.

Preparation or pre-publication failure leaves the previous aggregate intact.
An authenticated equal-version equivocation is an intentional complete knowledge
transition to ambiguity, reported as Rejected AFTER publication; accepted-release
state does not change. It is not a partially committed failed release.
Clock callbacks can legitimately complete inner operations: an outer rejection
must preserve, not undo, those valid inner transitions.

This guarantee is scoped to synchronous preparation/publication faults and the
supported CPython 3.11 process-local implementation, not process crashes,
arbitrary monkeypatches of internals, asynchronous interruption, persistent
transactions, recovery or multi-process/distributed storage.

## Unchanged and synthetic limits

contracts.py, verifier.py, test_synthetic.py and test_review.py are byte-identical
to the predecessor. Existing signed schemas/domains and application manifest
contracts are unchanged. The new boundary tests inherit all 64 predecessor cases.
Synthetic keys exist in test-child memory only, never as stored private material.

The runner retains exact source copies, pre/post hashes, command/interpreter
metadata, actual import delta, stdout/stderr/exit and failed runs. Module-delta
observation and the inherited Python audit guard do NOT prove kernel isolation,
initial interpreter/site bootstrap, image/dependency closure or independent
attestation. Internal CurrentSnapshot/Receipt types are not cryptographic
capabilities against arbitrary same-process code; the verifier must authenticate
inputs before calling the fence. No active application is loaded.

This ignored local directory is not a commit, checkpoint/export or durable
external preservation guarantee. Nothing has been uploaded or published.
