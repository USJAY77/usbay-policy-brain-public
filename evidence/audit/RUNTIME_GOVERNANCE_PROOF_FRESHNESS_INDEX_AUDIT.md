# PB-RUNTIME-013 — Runtime Governance Proof Freshness Index — Audit Evidence

## Purpose

USBAY must be able to prove whether each exported runtime governance proof
package is **current, stale, missing, superseded, or invalid** through a
deterministic, non-sensitive freshness index — without exposing raw payloads,
signatures, secrets, or raw client identifiers, and without weakening the
`/execute` path.

This capability is an **evidence-only, read-only, deterministic, fail-closed**
overlay on top of the PB-RUNTIME-012 export index. It is **NOT** wired into
`/execute` and makes **no** runtime decision change.

## Scope (strictly)

- `gateway/app.py`
- `tests/test_gateway_app.py`
- `evidence/audit/RUNTIME_GOVERNANCE_PROOF_FRESHNESS_INDEX_AUDIT.md`

No simulator / travel / voucher / tenant / RFC3161 / Codex changes. No
`/execute` behavior change. No missing `policy_context_id` / `gateway_context_id`
invented.

## Freshness index model

The freshness index is derived **from** the PB-RUNTIME-012 export index (itself
derived from the PB-RUNTIME-011 export report). It classifies every export-index
record into a freshness status and binds those classifications into a
tamper-evident digest.

### Per-record freshness metadata (non-sensitive only)

- `decision_id`
- `audit_hash`
- `export_record_hash`
- `proof_generated_at`
- `proof_status` (carried — a status string, not raw evidence; required so the
  `INVALID` classification stays independently re-verifiable)
- `freshness_status`
- `freshness_reason_code`
- `policy_context_id` / `gateway_context_id` — emitted **only when present** in
  the source record; never invented.

### Index-level metadata

- `freshness_checked_at` — the **deterministic reference time**: the latest
  `proof_generated_at` present in the export index. This is a deterministic
  anchor derived from the evidence itself, **not** wall-clock time.
- `freshness_max_age` — the freshness window applied (stored so validation
  recomputes the classification identically). Default
  `RUNTIME_GOVERNANCE_PROOF_FRESHNESS_MAX_AGE = 86400.0`.
- `export_index_hash` — carried forward from PB-RUNTIME-012 and re-verified.
- `freshness_index_hash` — rolling SHA-256 seeded from the audit `GENESIS_HASH`,
  folding `freshness_checked_at` + `freshness_max_age` into a header step, then
  chaining each record's canonical non-sensitive content. Domain-separated by the
  freshness namespace.
- `freshness_counts` (per status), `all_current`, `count`, `records`.
- Carried verdicts: `export_valid`, `hash_chain_valid`,
  `export_index_integrity_valid`, `index_integrity_valid`, `valid`,
  `reason_codes`.

## Freshness statuses

Classification precedence (fail-closed) in
`classify_runtime_governance_proof_freshness`:

1. **MISSING** — core evidence absent (`audit_hash` / `export_record_hash` /
   `proof_generated_at` is `None`), so freshness cannot be established.
2. **INVALID** — the underlying proof verdict (`proof_status`) is not `VALID`.
3. **SUPERSEDED** — a newer proof exists for the same `decision_id`.
4. **STALE** — the proof is older than `max_age` relative to the deterministic
   reference time.
5. **CURRENT** — otherwise.

Timestamp handling is unit-agnostic: `_freshness_epoch` converts the production
ISO-8601 audit timestamp (`datetime.utcnow().isoformat() + "Z"`), a numeric
value, or a numeric string into a comparable epoch; uninterpretable values
degrade safely (age math is skipped rather than guessed).

## Reason codes

### Per-status classification (`freshness_reason_code`)

- `RUNTIME_GOVERNANCE_PROOF_FRESHNESS_CURRENT`
- `RUNTIME_GOVERNANCE_PROOF_FRESHNESS_STALE`
- `RUNTIME_GOVERNANCE_PROOF_FRESHNESS_MISSING`
- `RUNTIME_GOVERNANCE_PROOF_FRESHNESS_SUPERSEDED`
- `RUNTIME_GOVERNANCE_PROOF_FRESHNESS_INVALID`

### Validation namespace (`validate_runtime_governance_proof_freshness_index`)

- `..._FRESHNESS_INDEX_VALID`
- `..._FRESHNESS_INDEX_INCOMPLETE`
- `..._FRESHNESS_INDEX_UNKNOWN_STATUS`
- `..._FRESHNESS_INDEX_STATUS_MISMATCH` (declared status ≠ re-derived status)
- `..._FRESHNESS_INDEX_REASON_MISMATCH` (reason code ≠ status's canonical reason)
- `..._FRESHNESS_INDEX_HASH_MISMATCH`
- `..._FRESHNESS_INDEX_EXPORT_INDEX_HASH_MISMATCH`
- `..._FRESHNESS_INDEX_POLICY_CONTEXT_MALFORMED`
- `..._FRESHNESS_INDEX_GATEWAY_CONTEXT_MALFORMED`
- `..._FRESHNESS_INDEX_SENSITIVE_DATA`

## Hash / index status

- **Per-record content tamper** → `freshness_index_hash` fails to recompute →
  `..._INDEX_HASH_MISMATCH`.
- **Forged `freshness_status`** (even with a recomputed hash) → caught by
  re-derivation → `..._INDEX_STATUS_MISMATCH` (defense in depth).
- **Carried `export_index_hash` tamper** → `..._EXPORT_INDEX_HASH_MISMATCH`
  (recomputed over the records' `export_record_hash` values).
- **Upstream audit-chain tamper** → propagates via the carried `hash_chain_valid`
  into the overall fail-closed `valid`.

Staleness / supersession / invalidity / missing-ness are surfaced via per-record
`freshness_status` + `freshness_counts` + `all_current`, **not** by failing
structural validation — so auditors can still trust a correctly-built index that
*reports* stale or invalid evidence.

## Documented GAPs

- The export index dedupes `decision_id`, so in the chain-derived path every
  proof is the latest for its decision; `SUPERSEDED` and `MISSING` therefore
  arise only in synthetic / multi-proof scenarios. Both remain
  deterministically reachable and are covered by the classifier and
  index-level tests.
- Optional `policy_context_id` / `gateway_context_id` are **omitted** when
  absent (never faked), counted via the carried availability fields, and do not
  fail the index on their own; a **present-but-malformed** id fails.
- Staleness is computed only when both reference and record timestamps are
  epoch-convertible; otherwise the record is treated as not-stale rather than
  guessed.
- The freshness index is discovery / verification metadata only; the
  PB-RUNTIME-011 export remains the full evidence package.

## Fail-closed evidence

- All freshness functions are **pure / read-only** and **never raise**.
- **NOT** wired into `/execute`; no runtime decision weakening.
- Building the freshness index does **not** mutate the audit chain (asserted by
  `test_freshness_index_is_read_only`).
- Leakage is prevented primarily by **whitelist construction** of record fields;
  the sensitive-data scan is retained as defense in depth.
- Overall `valid` is fail-closed: it requires freshness-index integrity **AND**
  the carried export-index integrity **AND** `export_valid` **AND**
  `hash_chain_valid`.

## Validation results

- `python3.11 -m py_compile gateway/app.py tests/test_gateway_app.py` — passes.
- `pytest tests/test_gateway_app.py` — **216 passed** (191 prior + 25 new
  freshness tests).
- `pytest tests/test_voucher_authority.py
  tests/test_governance_actions_policy_approvals.py` — **74 passed**.
- `git diff --check` / `git diff --cached --check` — clean.
- CURRENT index passes; STALE / MISSING / SUPERSEDED / INVALID detected;
  freshness/index/export-index hash mismatches fail; sensitive data rejected;
  optional ids omitted when unavailable and never faked; execution path
  unchanged.

## Files changed

- `gateway/app.py`
- `tests/test_gateway_app.py`
- `evidence/audit/RUNTIME_GOVERNANCE_PROOF_FRESHNESS_INDEX_AUDIT.md`

## Rollback

```
git revert --no-edit HEAD
```

The change is purely additive (new constants, helpers, validators, tests, and
this audit doc) and is unreferenced by the execution path, so reverting removes
the freshness index with no effect on `/execute`.
