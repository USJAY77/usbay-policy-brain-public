# Human engineering review request

**DRAFT HANDOFF — NOT ADOPTED — NO PRODUCTION AUTHORITY**

## Exact subject

Review only the dormant producer-trust engineering candidate preserved under
`candidate/`. Its original MANIFEST.json SHA256 must be:

`064c5a91a88c06af3208aea574a561522d4f5a1ea74eed502576761583d458f3`

Source repository: USJAY77/usbay-policy-brain-public
Source branch: integrate/gitless-runtime-seven-files-771007f1
Source HEAD: 3fdd34305311f2e4a97d34544c95d87e0dbf781c
Source tree: ae0f1774ed72add2da4a62d4f6203dca4cfc39d0

The archive contains the exact complete isolated candidate, NOT an export of
the application repository. No active loader, service or production configuration
is included or changed.

## Purpose and supported boundary

Assess engineering suitability of isolated signed adoption/selection/revocation
contracts, verifiers and a synthetic in-memory release fence. Explicit caller
authority, exact bindings, signatures, freshness and revocations are prerequisites;
the candidate itself does not establish real human identity or authority.

Supported evidence concerns cooperative process-local CPython 3.11 execution,
explicit synthetic clocks and ephemeral memory-only test keys. Python module
observations/audit hooks are not kernel isolation. No durability, recovery,
multi-process/distributed guarantee or production trusted clock is claimed.
Arbitrary privileged same-process modification and asynchronous interruption are
excluded. Artifact/source/dependency/image bytes are not verified by these
binding-only contracts.

## Repaired findings and existing conclusions

- F1: authenticate complete target-scoped snapshots before separate currentness
  observation; newer authenticated revocation prevents older clean replay.
- F2: one validated immutable expected binding is used throughout verification.
- F4: malformed authority/roles, including unhashable roles, reject explicitly.
- R1: after the last reentrant clock callback, read latest aggregate and check
  target/context-bound time high-watermark, expiry, ambiguity and currentness.
  Higher outer sequence/version and exact retry cannot restore an earlier time.
- R2: privately prepare release, nonce, currentness, conflict and time state;
  publish one consistent aggregate, including exception-safe conflict outcome
  allocation. No separate release-then-nonce publication remains.
- F3: fresh runs preserve exact executed source snapshots and pre/post hashes.
  No retrospective source-proof claim is made for older historical runs.

The implementation self-review and subsequent separate Replit static review
reported READY_FOR_SCOPED_REVIEW within these explicit limits, with no new
substantiated defect in the final scoped review. That separate review conclusion
is summarized from the retained engineering report; it is not an independent
human approval or signed decision. `candidate/REVIEW.md` is the preserved original
self-review, not a substituted human record. Handoff preparation does not repeat
the review or execute tests.

## Preserved execution evidence

`candidate/evidence/run-03-final-boundary/` contains the final source-bound run:

- 85 unique cases (64 inherited + 21 boundary cases), 163 subtests;
- 0 failures/errors/skips, exit 0, no timeout;
- Python 3.11.14 / cryptography 50.0.0;
- eight preserved source files, including fixed launcher; seven candidate root
  files match the executed copies;
- actual import delta, interpreter/command/cwd metadata, stdout/stderr and result.

Final pre-run and post-run inventory SHA256:

`c19987564ab4f1b154a759b447a086eb6732c15e8356e2fe684d8ec02780517b`

Also preserved: run-01 with four pre-correction failures and run-02 with the
84-case intermediate pass. Never relabel those runs as final or erase failures.
These are retained prior results, not new execution by this handoff batch.

## Requested review and decision handling

Intended reviewers are **USBAY-AUDIT** and **USBAY-GLOBAL23**. These labels only
designate intended recipients. They establish neither authority nor distinct
human identities. No messages have been sent and no response is presumed.

Both provided decision templates are UNFILLED; every decision is UNRESOLVED.
First verify integrity using the inventory and the externally supplied archive/
inventory hashes. `verify_integrity.py` performs only static file/hash checks;
it does not import candidate code or run tests.

Review actual code, fault/clock regressions and assertions, source-bound evidence
and exclusions. A response should state candidate hash, reviewer identity and
capacity evidence, findings, scope, limitations, outcome and actual decision time.
Use a separately identified response/working copy; do not edit the sealed original.
A filled response has new bytes and needs its own evidence binding. Matching a
reviewer label is not identity or authority verification.

## Strict exclusions

A positive engineering review grants NONE of:

trust adoption; real root/key, role, threshold or production policy selection;
active loader/startup integration; production storage/state/recovery; signing;
configuration or secrets changes; provisioning; commit/push/PR/merge; workflow/
runner activation; build, restart, publication, deployment, Promote or activation.

Every such stage requires separate explicit authorization and its own evidence
gates. See PRODUCTION_GATES.md. The visible failed publication/crashloop and its
cause/initiator remain UNKNOWN and outside this review request.

## Storage and authenticity

The candidate and this handoff have only verified local workspace storage.
A download attachment, if returned, is a delivery convenience, not proof of
immutable external persistence, public publication, independent attestation or
recipient access. No external durable location is established.
Hashes detect byte differences only relative to a trusted expected digest; they
do not authenticate the author or authorize adoption.
