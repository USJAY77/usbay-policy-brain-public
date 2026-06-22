# PB-RUNTIME-014 — Runtime Audit Freshness Index PROOF — Audit Evidence

## Purpose

USBAY must be able to **prove** that its exported runtime governance proofs are
not only valid and indexed (PB-RUNTIME-011/012) and freshness-classified
(PB-RUNTIME-013), but are also **current, indexed, non-stale, counted, and
freshness-bound** — through a single compact, deterministic, non-sensitive
**proof** object.

This capability is an **evidence-only, read-only, deterministic, fail-closed**
summary on top of the PB-RUNTIME-013 freshness index. It is **NOT** wired into
`/execute`, makes **no** runtime decision change, and **does not weaken**
PB-RUNTIME-013.

## Scope (strictly)

- `gateway/app.py`
- `tests/test_gateway_app.py`
- `evidence/audit/RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_AUDIT.md`

No simulator / travel / voucher / tenant / RFC3161 / Codex changes. No
`/execute` behavior change. No missing `policy_context_id` /
`gateway_context_id` invented. The PB-TRAVEL-005 voucher approval-chain work is
already merged and is **out of scope** for this task.

## Proof model

The audit freshness index proof is derived **from** a PB-RUNTIME-013 freshness
index. It carries **only** summary metadata plus the carried-forward
tamper-evident hashes — it **never** carries per-record evidence, raw payloads,
signatures, secrets, or client identifiers.

### Proof fields (the exact non-sensitive whitelist)

- `freshness_index_id` — content-derived identifier of the proof (see below)
- `freshness_index_status` — `CURRENT` / `STALE` / `MISSING` / `INVALID`
- `freshness_index_reason_code` — canonical reason for the status
- `freshness_checked_at` — carried reference time (fail-closed if absent)
- `freshness_max_age` — carried freshness window (fail-closed if absent)
- `export_index_hash` — carried PB-RUNTIME-012 export-index digest
- `export_record_count` — total exported proof records
- `stale_record_count` — records older than the freshness window
- `fresh_record_count` — current records
- `missing_freshness_count` — records lacking establishable freshness
- `freshness_index_hash` — carried PB-RUNTIME-013 freshness-index digest

The proof field set is exactly
`RUNTIME_AUDIT_FRESHNESS_INDEX_PROOF_FIELDS`; the builder emits nothing else.

### Proof identity

`freshness_index_id` =
`usbafip-` + first 32 hex of
`sha256(namespace | GENESIS_HASH | canonical_json(hashes + reference params +
counts))`, where namespace = `usbay.runtime.audit.freshness.index.proof.v1`.

This binds every summary field, so tampering any of them changes the id
(tamper-evidence even without the source index). It is the **proof's own**
identity — **not** a policy/gateway context id, and no context id is fabricated.

## Status classification (fail-closed precedence)

`classify_runtime_audit_freshness_index_proof(...)`:

1. `INVALID` — the underlying freshness index is not integrity-valid, or the
   reference time / max-age window is absent.
2. `MISSING` — one or more exported proofs lack establishable freshness.
3. `STALE` — one or more exported proofs are older than the freshness window.
4. `CURRENT` — every exported proof is current and counted.

## Functions added (gateway/app.py)

- `compute_runtime_audit_freshness_index_proof_id(...)` — deterministic,
  namespaced, GENESIS-bound proof id.
- `classify_runtime_audit_freshness_index_proof(...)` — pure status classifier.
- `build_runtime_audit_freshness_index_proof(freshness_index)` — pure,
  read-only, fail-closed proof builder.
- `build_runtime_audit_freshness_index_proof_from_chain(chain=None, ...)` —
  convenience builder over the live export chain.
- `validate_runtime_audit_freshness_index_proof(proof, freshness_index=None, *,
  seen_ids=None)` — pure, fail-closed validator returning `(is_valid, codes)`.

All functions are pure / read-only and **not** referenced by `/execute`.

## Validation guarantees

`validate_runtime_audit_freshness_index_proof` proves a proof is:

- structurally complete (required fields present and non-null);
- free of any raw sensitive material (reuses the PB-RUNTIME-007 forbidden-key /
  value scan → `..._SENSITIVE_DATA`);
- fail-closed on a missing reference time / max-age (`..._CHECKED_AT_MISSING`,
  `..._MAX_AGE_MISSING`);
- internally count-consistent (non-negative ints; sub-counts ≤ total →
  `..._COUNT_MISMATCH`, `..._RECORD_COUNT_MISMATCH`);
- declaring a **known** status whose reason code matches and whose value
  re-derives from the carried counts (`..._UNKNOWN_STATUS`,
  `..._REASON_MISMATCH`, `..._STATUS_MISMATCH` — a status forged "healthier"
  than the counts is caught);
- **current** — any `STALE` / `MISSING` / `INVALID` population fails the proof
  (`..._STALE_RECORDS`, `..._MISSING_RECORDS`, `..._INVALID`);
- id-bound (`..._ID_MISMATCH` when the content-derived id does not recompute);
- cross-checked against the source index when supplied (precise
  `..._EXPORT_INDEX_HASH_MISMATCH`, `..._INDEX_HASH_MISMATCH`,
  `..._RECORD_COUNT_MISMATCH`, `..._COUNT_MISMATCH`, plus
  `..._STATUS_MISMATCH` / `..._REASON_MISMATCH` / `..._ID_MISMATCH` against the
  index-derived expectation — the master tamper-evidence check);
- carrying **exactly** the 11 whitelisted fields — any extra key (even a
  non-sensitive one) is an ungoverned schema extension and fails
  (`..._INCOMPLETE`);
- non-duplicated across a registry via `seen_ids` (`..._DUPLICATE`).

### Verification modes (what each proves)

- **With the source index** (`freshness_index=...`): full evidentiary
  verification. The carried hashes, counts, reference window, status, reason,
  and id are all re-derived from the trusted index and compared. A proof forged
  "healthier" than the underlying evidence (e.g. `CURRENT` over an `INVALID`
  index) is caught even if its id was recomputed to be internally consistent.
  This is the mode USBAY must use to *prove currency*.
- **Without the source index** (proof alone): structural + internal-consistency
  verification only. It proves the proof is well-formed, schema-exact,
  non-sensitive, count-consistent, currency-asserting (any STALE/MISSING/INVALID
  fails), and tamper-evident relative to its own content-derived id. It does
  **not** by itself anchor the summary to the trusted index; full currency proof
  requires supplying the source index (or building the proof from the chain).

## Fail-closed evidence

- Non-dict proof → `..._INCOMPLETE`, `is_valid=False`.
- Absent reference anchor (empty export chain) → proof status `INVALID`, never
  vacuously `CURRENT`.
- Stale / missing populations → proof fails (currency assertion).
- Any field tamper → id no longer recomputes and (with the index) a precise
  mismatch code fires.
- No raw sensitive material can ever be present without rejection.

## Non-sensitive guarantee

The proof carries only the whitelisted summary fields and carried-forward
hashes. The builder is verified by
`test_afip_build_never_carries_raw_sensitive_fields` and
`test_afip_build_has_exactly_the_whitelisted_fields`.

## Tests (tests/test_gateway_app.py)

33 PB-RUNTIME-014 tests, all passing, covering: the four classifier statuses and
precedence; id determinism and field-sensitivity; the builder field whitelist,
count summarisation, hash carry-forward, and non-sensitivity; the happy path
(with and without the source index); the 10 required validation failure modes
(missing `freshness_checked_at`, missing `freshness_max_age`, stale record,
export-index-hash mismatch, record-count mismatch, stale/fresh count mismatch,
freshness-index-hash mismatch, duplicate, sensitive data, plus missing-record);
forged-status, unknown-status, reason-mismatch, incomplete, and non-dict
guards; system-wide proof over a real `/execute` decision; read-only proof; and
empty-chain `INVALID`.

## Validation performed

- `python3.11 -m py_compile gateway/app.py tests/test_gateway_app.py` → OK.
- `pytest -k afip` → 33 passed.
- Full `tests/test_gateway_app.py` → the new tests pass; the only full-suite
  failures are pre-existing **order/shared-state-dependent** system-wide tests
  (audit chain accumulates across system-wide tests) that pass in isolation —
  confirmed by running all of them in isolation (7 passed). These are unrelated
  to this change.
- Regression `tests/test_voucher_authority.py tests/test_travel_voucher.py` →
  77 passed.
- `git diff --check` → clean.

## Rollback

This change is purely additive (new constants, functions, tests, and this audit
doc). To revert: `git revert --no-edit HEAD`.
