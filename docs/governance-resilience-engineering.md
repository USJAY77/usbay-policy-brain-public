# USBAY Governance Resilience Engineering

This layer validates that USBAY governance remains fail-closed under bounded pressure. It is test-only and does not relax governance, evidence, replay, verifier, timestamp, or human-review requirements.

## Replay Storm Model

The replay storm tests simulate 10,000 repeated requests against a bounded nonce gate. The first unique nonce may pass; repeated nonces and queue saturation must return explicit `FAIL_CLOSED` evidence with no raw nonce exposure.

Expected evidence includes:

- `decision=FAIL_CLOSED`
- `reason=REPLAY_DETECTED` or `REPLAY_QUEUE_OVERLOADED`
- `pressure_model=replay_storm`
- `silent_pass=false`

## Verifier Pressure Model

The verifier pressure tests run parallel offline evidence-pack verification. A valid persisted evidence pack must produce stable `VERIFY_PASS` and `TIMESTAMP_VERIFY_PASS` outputs across concurrent workers. Missing or unreadable packs fail closed.

Expected evidence includes:

- stable `latest_event_hash`
- stable `timestamp_hash`
- `OFFLINE_VERIFIER_UNAVAILABLE` when verification cannot complete

## Export Saturation Model

The export saturation tests simulate concurrent evidence-pack exports, manifest contention, deterministic ZIP generation contention, and timestamp queue pressure. Saturation uses bounded gates so overload cannot become a silent success.

Expected evidence includes:

- `QUEUE_OVERLOADED`
- `pressure_model=evidence_export`, `manifest_contention`, `zip_export`, or `timestamp_queue`
- no private keys, tokens, or raw sensitive payloads

## Human-Review Flood Model

The human-review flood tests simulate governance review backlog and high-volume review-required labels. Missing approval remains blocked. Explicit approval must be present; pressure cannot auto-relax the reviewer requirement.

Expected evidence includes:

- `GOVERNANCE_REVIEW_MISSING`
- `HUMAN_REVIEW_QUEUE_OVERLOADED`
- `review_required=true`
- `review_approved=false` unless an explicit approval label exists

## Fail-Closed Expectations

Every overload condition must produce explicit fail-closed evidence. The tests must never transform missing queue capacity, missing verifier output, replayed nonce state, or missing human approval into a pass.

## Running

Manual resilience run:

```bash
python -m pytest -m resilience -vv
```

These tests are intentionally separated from fast PR checks. The optional workflow `.github/workflows/governance-resilience.yml` runs only on manual dispatch or schedule.
