# Final main-agent static boundary recheck

This is a self-review, not independent human approval.

- R1 record/observe capture aggregate after the only external clock callback.
  The current target context, ambiguity, time high-watermark, expiry and applicable
  snapshot/release/nonce predicates are checked before private preparation.
  No normal preparation helper invokes arbitrary caller objects: keys/values
  derive from strict immutable verifier output. Publication checks aggregate
  identity again. No clock or other caller callback follows the checks.
- Known time is published only with eligible authenticated snapshot knowledge or
  valid receipt acceptance/retry. Authenticated snapshot observation remains
  distinct from release authorization. Bad signature/scope/context, expiry and
  rollback reject before publishing any outer transition.
- Same-version observations remember later time independently of snapshot
  verified_at. Higher outer sequence/version cannot bypass known time. Latest
  revocation and expiry are checked even for exact retries.
- R2 stages independent dictionaries, proxies, frozen aggregate and conflict
  outcome before a single existing-reference assignment under RLock. No
  release-then-nonce publication exists. Injected synchronous failures leave
  published state consistent; a valid completed inner operation is not undone.
- Authenticated equivocation intentionally commits ambiguity and time atomically,
  then raises its preallocated Rejected outcome. Accepted-release state stays
  unchanged; this is not described as no knowledge advance on every rejection.
- CPython 3.11 process-local reference publication/locking is the tested boundary;
  this is not crash/persistence/hostile-same-process/asynchronous-failure proof.
- contracts.py/verifier.py and inherited test sources are unchanged; F1/F2/F4
  validation, signatures, parsing, immutable expected binding and scopes remain.
- Final 85-case/163-subtest run passed with bound sources. Prior failures and
  passing intermediate bytes are preserved separately, never relabeled.

Verdict: READY_FOR_SCOPED_REVIEW within these explicit synthetic limits only.
