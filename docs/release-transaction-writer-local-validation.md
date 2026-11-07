# Release transaction writer — local synthetic validation

Status: IMPLEMENTED_LOCALLY / SYNTHETIC_VALIDATION_PASS / NOT_ADOPTED.
This document records the initial 197-case writer batch. The later lineage
correction and actual consumer compatibility tests are recorded in
release-writer-native-compatibility.md; that report describes the latest bytes.

Baseline: USJAY77/usbay-policy-brain-public dc549b2167dc6bdbe8e5b1c988bb27e9176e388e;
tree b83475115eafe1ca75df661272958f21aac08665.
Local branch: local/release-owner-contract-v1. This is not GitHub main or Replit.

## Result and integration boundary

governance/release_transaction_writer.py introduces an import-only coordinator,
an explicitly provisioned SQLite transaction store, bounded receipt and query-only
reconciliation. No operational authority source, root adoption, HMAC signer,
authority fence or source/rollback anchor is installed. Defaults deny before
opening the store or invoking the signer. Request keys, environment labels,
hashes and bindings_valid alone do not configure authority.

The privileged ReleaseAuthoritySource port must independently authenticate live
root adoption, revocations/currentness and source observations, and hold an
authenticated request/state/adoption-bound authority fence through COMMIT. The
code requires the fence and verifies its binding and deadline. A source without
this port cannot be installed. A Python interface cannot prove that a future
provider actually holds its external lock: only a synthetic fixture fence is
tested here. Operational provider conformance remains open.

The writer obtains SQLite BEGIN IMMEDIATE before inspecting authority. The exact
signed contract is verified under the lock, immediately before signing, and
again before COMMIT. Root/tenant/target/source/core/predecessor, status epoch and
head, tool binding, time and adoption references must agree. The authority source
is a separately configured trusted dependency, never selected by request JSON.

Output bytes, one-time nonce reference, exact grant budget, receipt and successor
head commit in the same SQLite transaction. Nonces bind tenant and stable issuer
principal, so key/grant rotation does not reset the nonce. The store is open-only
during writing: missing, corrupt, locked, unsafe or unexpected schema does not
silently provision, repair, retry or broaden authority. Explicit test provisioning
requires a private owner-controlled directory and creates a new 0600 database.

The signer receives an immutable copy of the exact approved core. Signatures
must have the existing HMAC-SHA256 form and pass the configured signer's verifier.
The initial seven-field core mapped source commit, tenant, bundle and predecessor,
but was not yet sufficient for the existing consumer's non-GENESIS lineage rule.
The later correction adds signed release_history inside the exact authorized
core hash. The source-tree binding remains in the authorization contract.
GENESIS is not inferred. Existing release functions remain unmodified; actual
synthetic consumer compatibility is now covered by the later report.

No release file or provider publication occurs. COMMITTED means output and
consumption in this protected store only. Signer attempts may precede rollback;
external signing is not made atomic by SQLite. A possible COMMIT returns UNKNOWN.
Reconciliation reads the exact transaction and checks output/core digest,
receipt, nonce and budget correspondence without calling the signer. Absence or
inconsistency stays UNKNOWN and is not authorization to retry. These checks do
not independently re-authenticate HMAC custody or make the database an immutable
signed audit ledger. SQLite can perform ordinary hot-journal rollback after
process death while opening the store; no authority repair or reinitialization
is performed.

## Validation evidence

Final local command:

```sh
python3 -m unittest tests.test_release_owner_contract.ReleaseOwnerContractTests tests.test_release_transaction_writer.ReleaseTransactionWriterTests -q
```

197 unique cases passed: 135 contract regressions plus 62 writer cases;
0 failures, 0 errors, 0 skips. Python 3.12 on Linux. No packages installed.
Both test files are in the existing governance-tier mapping. Native pytest/CI
selection itself has not been executed here.

The retained writer-batch-tests.txt records exact test IDs and results;
writer-batch-result.json records counts and scope. Historical 131/135-case
results and the two pre-correction temporal failures remain separately retained.
writer-final-tests.txt and writer-final-result.json bind the final source hashes
to the final targeted run; earlier passing writer-batch evidence is preserved.

| Boundary | Observed synthetic evidence |
| --- | --- |
| Complete chain and transaction | One output, one nonce, one budget and successor head; exact core/HMAC round trip |
| Default/missing adoption, source, signer, clock or fence | Denied; no signer invocation |
| Signed root/issuer/policy/owner revocation | Denied before signing |
| Changed source/core/head/epoch/tool or expired evidence | Denied; after-sign changes roll back output and consumption |
| Nonce replay and issuer key/grant rotation | No second stored output or signer invocation |
| Spent grant budget | Separate constraint denies a never-used request nonce; test explicitly seeds a consumed budget fixture |
| Thread contention | Two simultaneous writers, exactly one committed output in the observed run |
| Process contention | Two forked writers, exactly one committed output and signer attempt in the observed run |
| Definite pre-COMMIT faults | Signed attempts possible, but output/nonce/budget all roll back |
| Ambiguous COMMIT before/after storage | UNKNOWN; reconciliation distinguishes observed commit from unobserved outcome |
| Actual process death | Two additional children exit at pre-/post-COMMIT boundaries; pre-COMMIT rows absent, post-COMMIT rows reconciled |
| Rollback observation | A newer independently supplied head rejects a restored old store; restoring both source and DB is outside this proof |
| Store boundary | Missing/corrupt/locked/symlink/hard-link/unsafe mode/extra schema denied without implicit provisioning |
| Reconciliation corruption | Altered output or wrong budget correspondence remains UNKNOWN; no signing |

The suite creates ephemeral synthetic Ed25519/HMAC material in memory, and
temporary task-owned databases. It reads no owner private key or password.
Process tests are Linux fork tests, not Mac/spawn or a broad browser/platform
matrix. The synthetic authority fence can remain unavailable after process
death; no operational lease recovery policy/provider is implemented or inferred.

## Open operational gaps

- Human-adopted root policy and independently enrolled issuer/owner/status/signer
  identities, custody, tenant/target, validity and lineage remain unresolved.
- Production-grade currentness, external source binding, authority fencing,
  durable rollback anchors and crash-safe fence recovery require separately
  verified adapters. The fixture's public keys/reference hashes are not adoption.
- An external signer needs its own governed idempotency/reconciliation contract;
  this module promises no exactly-once external signing and performs no automatic
  retry. No permission to retry an uncertain consequential action is issued.
- External file/provider publication, full legacy consumer/history integration,
  Gateway startup, native CI, macOS and deployment remain untested/unmodified.
- Protected-directory ownership and SQLite durability are assumptions. No
  kernel-level hostile-filesystem isolation, immutable audit store, resistance
  to simultaneous authority/store rollback or independent human acceptance is
  claimed.

Existing Gateway, .replit, release HMAC handling, dependency locks and workflows
remain unchanged. No operational trust registration, user-key access, public
publication, commit/push, restart, build or deployment was performed.
