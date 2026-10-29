# Experimental Hydra Option 2 / M1 foundation

This increment is unwired from runtime admission. It implements pure review
contracts and an unavailable provider, not operational recovery or authority.
EGAP-HYDRA-REMOTE-TRANSPORT-AUTH remains OPEN.

## Implemented contract

`security/hydra_operational_contracts.py` defines separate experimental v1
identifiers for the envelope, anchor observation, preservation prefix/record
and recovery-review plan. They do not replace existing reference/v2 mandates.
The exact field sets are enforced in `_exact` calls. `EvidenceScope` binds the
tenant, environment, policy reference/hash, continuity, witness, store,
generation and authority epoch. References use `sha256:` plus 64 lowercase hex
characters. There is no identity alias normalization.

`verify_evidence(packet, expected_context)` accepts UTF-8 JSON bytes or text,
not pre-decoded dictionaries. The envelope has `signed` and lowercase hex
`signature`; `signed` contains schema, purpose, signer/key identities, scope,
issued/expires times, challenge and purpose-specific payload. Ed25519 uses
existing reference canonicalization and public-key loading primitives. The
verifier supplies trusted keys (scoped by signer, key and purpose), exact scope,
challenge and time. No clock, key registry, file, network or provider is read.
Signature success proves authenticity under that supplied trust only. It does
not establish human authority, enrollment, independent custody or protected
currentness. URL hashes are not operational server-identity proof.

Decoding rejects duplicate, extra and missing fields, invalid UTF-8, trailing
JSON, unsupported identifiers, non-finite numbers, numeric magnitude above
2^53-1 and booleans where numbers are required. Limits: 131072 UTF-8 bytes,
12 nesting levels, 8192 visited values, arrays at most 256 items, strings at
most 4096 characters and keys at most 256 characters. Time validity is
`0 <= issued_at <= now < expires_at`; equality at expiry fails closed.
The caller, not this pure verifier, must establish trusted time/currentness.

Anchor payloads bind observation ID, sequence, head and witness head. Prefix
records bind schema, sequence, previous head, event hash and computed head.
The commitment binds record count, first sequence, previous head, last head and
canonical records hash. This is a bounded supplied segment commitment, not a
proof of full event contents, genesis coverage, independent preservation or
absence of any later unexported local pending tail.

`validate_recovery_plan(plan, verified_records, expected_context)` requires
one anchor and one prefix, re-authenticates their original packet bytes under
the supplied scope/time/challenge, binds their canonical packet hashes, and
checks matching terminal head/sequence. The proposed epoch must strictly
exceed the supplied current epoch. This comparison cannot prove the supplied
epoch is operationally current. The plan is unsigned review data, not an
approval or executable transition. It cannot advance epochs, fence receivers,
clear uncertainty, recover stores or reinterpret existing `RECOVER` behavior.
Results are detached frozen dataclasses with recursively immutable mappings
and tuples. Every accepted result retains explicit unresolved protected
currentness, complete history including local pending tail, and receiver
fencing. Plan state is always `STOPPED_RECONCILIATION_ONLY`; no API returns
`ALLOW`, `READY_TO_RESUME` or execution/recovery authorization.

## Provider and unchanged boundaries

`OperationalProvider` defines typed `observe_current`, `reserve` and
`read_preservation_evidence` operations. `UnavailableOperationalProvider` is
the only supplied implementation and raises its bounded typed unavailable
error before input inspection or I/O. There is no runtime selector, activation
flag, discovery, external provider, storage provisioning or reference fallback.
Test providers, if needed later, belong in tests only.

Existing `HydraLiveNodeClient` and `RemoteHydraNode` still share
`authorize_hydra_remote_transport` -> `reserve_transport`. Existing local
pending, authority/witness commits and local finalization remain separate
transactions. Existing fail-closed admission, signatures, audit, replay,
test-only loopback trust and identity spellings are unchanged.

## Future design order (NOT implemented)

Protected local pending -> authority consumption/history and protected anchor
confirmation -> authority receipt -> verified local finalization and
preservation -> dispatch.

Protected local pending, operational adapter, independent preservation,
recovery authority, complete-history assurance, fencing and activation remain
unavailable. Do not recreate missing stores, reset consumption/revocation
history, clear pending states, downgrade to v1 or infer authority from roles
or GitHub reviews. Coherent rollback of every trusted anchor is not necessarily
detectable. Expiry or epoch changes do not undo an already started effect.

## Validation scope and operational decisions

New tests use ephemeral synthetic Ed25519 keys, meaningful accepted proofs and
internally coherent review plans, substitutions, strict decoding, immutability
and guarded I/O boundaries. Native regressions use disposable loopback
processes, not operational enrollment or deployed providers. A timeout can
leave `admitted=false` with `NODE_ENTRY=1`; a retry must not add an entry.
The evidence directory records actual collection/results; this document does
not assert a test run or GitHub CI success. Mac staging-lock validation does
not establish Linux CI parity or governed macOS platform-lock approval.

Humans must separately decide actual provider/key ownership, independent
custody/recovery protocols, protected currentness/completeness evidence,
receiver fencing, migration compatibility and bounded recovery authority.
M1 chooses none of these and does not close the Hydra gap. Source review,
operational enrollment and activation are separate gates.
