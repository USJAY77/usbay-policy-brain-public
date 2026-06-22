# PB-RUNTIME-015 — Regulator-Grade Evidence Package Manifest — Audit Evidence

## Purpose

USBAY must be able to hand a regulator a **single, auditor-readable manifest**
that proves four independently-produced governance evidence digests belong to
the **same** evidence set:

- the **runtime proof hash** (the runtime governance proof),
- the **export index hash** (PB-RUNTIME-012),
- the **freshness index hash** (PB-RUNTIME-013),
- the **canonical E2E evidence hash** (PB-E2E-005).

This capability is an **evidence-only, read-only, deterministic, fail-closed**
manifest that *binds* those four hashes under one tamper-evident package digest.
It is **NOT** wired into `/execute`, makes **no** runtime decision change, and
**does not weaken** PB-RUNTIME-013.

## Scope (strictly)

- `gateway/app.py`
- `tests/test_gateway_app.py`
- `evidence/audit/RUNTIME_REGULATOR_EVIDENCE_PACKAGE_AUDIT.md`

No simulator / voucher / travel / tenant / RFC3161 / Codex changes. No
`/execute` behavior change. No `policy_context_id` / `gateway_context_id`
invented. The PB-TRAVEL-005 voucher approval-chain work is already merged and is
**out of scope** for this task.

## Package model

The package is a compact manifest that carries **only** the four component
digests plus the non-sensitive metadata required to (a) classify the package's
currency and (b) cross-check it against the source PB-RUNTIME-013 evidence set.
It **never** carries per-record evidence, raw payloads, signatures, secrets, or
client identifiers.

### Package fields (the exact non-sensitive whitelist)

- `regulator_package_id` — content-derived identifier of the package (see below)
- `regulator_package_status` — `VALID` / `STALE` / `INCOMPLETE` / `INVALID`
- `regulator_package_reason_code` — canonical reason for the status
- `regulator_package_generated_at` — package generation reference time
- `runtime_proof_hash` — carried runtime governance proof digest
- `export_index_hash` — carried PB-RUNTIME-012 export-index digest
- `freshness_index_hash` — carried PB-RUNTIME-013 freshness-index digest
- `e2e_evidence_hash` — carried PB-E2E-005 canonical E2E evidence digest
- `evidence_record_count` — exported proof record count
- `freshness_checked_at` — carried freshness reference anchor (fail-closed if absent)
- `freshness_max_age` — carried freshness window (fail-closed if absent)
- `package_hash` — the binding content digest over all of the above

The package field set is exactly
`RUNTIME_REGULATOR_EVIDENCE_PACKAGE_FIELDS`; the builder emits nothing else.

### Package binding digest

`package_hash` =
`sha256(namespace | GENESIS_HASH | canonical_json(four hashes + record count +
freshness window + generated_at))`, where namespace =
`usbay.runtime.regulator.evidence.package.v1`.

This is the **"same evidence set" proof**: any change to any one of the four
component hashes (or the bound metadata) changes `package_hash`, so the four
digests are cryptographically bound together as one package.

### Package identity

`regulator_package_id` =
`usbrep-` + first 32 hex of
`sha256(namespace | GENESIS_HASH | canonical_json(package_hash + status +
reason_code))`.

The id is bound to the binding digest plus the classified status/reason, so
tampering any bound field (or forging the status/reason) changes the id
(tamper-evidence). It is the **package's own** identity — **not** a
policy/gateway context id, and no context id is fabricated.

## Status classification (fail-closed precedence)

`classify_runtime_regulator_evidence_package(...)`:

1. `INCOMPLETE` — one or more of the four component evidence hashes is absent,
   or the evidence record count is not a usable count.
2. `INVALID` — the freshness window or the package generation reference time is
   absent / uninterpretable (currency unprovable).
3. `STALE` — the freshness check was already older than the freshness window at
   package generation time.
4. `VALID` — all four hashes present and the package is within the window.

The freshness anchor / generation time may be a numeric epoch **or** the
production ISO-8601 audit timestamp; both are normalised through the shared
PB-RUNTIME-013 `_freshness_epoch` helper for the staleness math, while the
**raw** values are carried for cross-checking against the index.

## Functions added (gateway/app.py)

- `compute_runtime_regulator_evidence_package_hash(...)` — deterministic,
  namespaced, GENESIS-bound binding digest over the four hashes + metadata.
- `compute_runtime_regulator_evidence_package_id(...)` — deterministic,
  content-derived package id.
- `classify_runtime_regulator_evidence_package(...)` — pure status classifier.
- `build_runtime_regulator_evidence_package(...)` — pure, read-only,
  fail-closed package builder.
- `build_runtime_regulator_evidence_package_from_chain(chain=None, *,
  runtime_proof_hash, e2e_evidence_hash, ...)` — convenience builder that
  derives the export hash, freshness hash, record count, and freshness window
  from the live PB-RUNTIME-013 freshness index over the chain (so those three
  provably come from ONE evidence set) and binds them with the caller-supplied
  runtime proof hash and E2E evidence hash.
- `validate_runtime_regulator_evidence_package(package, freshness_index=None, *,
  seen_hashes=None)` — pure, fail-closed validator returning `(is_valid, codes)`.

All functions are pure / read-only and **not** referenced by `/execute`.

## Validation guarantees

`validate_runtime_regulator_evidence_package` proves a package is:

- structurally complete — each of the four component hashes present and
  non-empty, each with a **precise** missing code
  (`..._RUNTIME_PROOF_HASH_MISSING`, `..._EXPORT_INDEX_HASH_MISSING`,
  `..._FRESHNESS_INDEX_HASH_MISSING`, `..._E2E_EVIDENCE_HASH_MISSING`);
- fail-closed on a missing freshness window / generation time
  (`..._CHECKED_AT_MISSING`, `..._MAX_AGE_MISSING`, `..._GENERATED_AT_MISSING`);
- count-consistent — `evidence_record_count` is a usable non-negative int
  (`..._RECORD_COUNT_MISMATCH`);
- free of any raw sensitive material (reuses the PB-RUNTIME-007 forbidden-key /
  value scan → `..._SENSITIVE_DATA`);
- declaring a **known** status whose reason code matches and whose value
  re-derives from the carried content (`..._UNKNOWN_STATUS`,
  `..._REASON_MISMATCH`, `..._STATUS_MISMATCH` — a status forged "healthier"
  than the content is caught);
- **current** — any `STALE` / `INCOMPLETE` / `INVALID` status fails the package
  (`..._STALE`, `..._INCOMPLETE`, `..._INVALID`), so a passing package certifies
  a VALID, in-window evidence set;
- binding-digest-bound (`..._PACKAGE_HASH_MISMATCH` when `package_hash` does not
  recompute from the carried content);
- id-bound (`..._ID_MISMATCH` — the id is recomputed from the **recomputed**
  binding digest + the **re-derived** status/reason, so it is the master
  tamper-evidence check);
- cross-checked against the source freshness index when supplied (precise
  `..._EXPORT_INDEX_HASH_MISMATCH`, `..._FRESHNESS_INDEX_HASH_MISMATCH`,
  `..._RECORD_COUNT_MISMATCH`, `..._FRESHNESS_WINDOW_MISMATCH`), binding the
  package to the real PB-RUNTIME-013 evidence set;
- carrying **exactly** the 12 whitelisted fields — any extra key (even a
  non-sensitive one) is an ungoverned schema extension and fails
  (`..._INCOMPLETE`);
- non-duplicated across a registry via `seen_hashes` (`..._DUPLICATE`).

### Verification modes (what each proves)

- **With the source index** (`freshness_index=...`): full evidentiary
  verification. The carried export hash, freshness hash, record count, and
  freshness window are re-derived from the trusted index and compared, and the
  binding digest + id are recomputed. This is the mode USBAY must use to *prove*
  the export/freshness components belong to the trusted set.
- **Without the source index** (package alone): structural + internal-consistency
  verification only. It proves the package is well-formed, schema-exact,
  non-sensitive, currency-asserting (any STALE/INCOMPLETE/INVALID fails), and
  tamper-evident relative to its own binding digest and content-derived id. It
  does **not** by itself anchor the export/freshness components to the trusted
  index; full proof requires supplying the source index (or building the package
  from the chain).

## Documented GAPs (auditor-visible, never faked)

- **`runtime_proof_hash` and `e2e_evidence_hash` provenance.** These two digests
  originate from **separate authorities** (the runtime governance proof and the
  PB-E2E-005 E2E evidence authority) and are **not** present in the
  PB-RUNTIME-013 freshness index. They therefore **cannot be re-derived** from
  the index during validation. The package binds them **only** by inclusion in
  the tamper-evident `package_hash` (and transitively the id): tampering either
  hash changes the binding digest and id, but the validator cannot independently
  confirm that the supplied values are the *correct* runtime-proof / E2E digests
  — that anchoring is the responsibility of their own authorities. The builders
  accept both as **caller-supplied inputs** and never fabricate them. This GAP is
  intentional and surfaced rather than hidden.
- Without the source index, the export/freshness components are likewise only
  internally consistent (see Verification modes).

## Fail-closed evidence

- Non-dict package → `..._INCOMPLETE`, `is_valid=False`.
- Any missing component hash / freshness field → precise missing code, package
  fails; classifier yields `INCOMPLETE` / `INVALID`, never vacuously `VALID`.
- Stale package → `STALE`, fails the currency assertion.
- Any bound-field tamper → `package_hash` no longer recomputes, the id no longer
  recomputes, and (with the index) a precise mismatch code fires.
- No raw sensitive material can ever be present without rejection.

## Non-sensitive guarantee

The package carries only the whitelisted fields and the four carried-forward
hashes. The builder is verified by `test_rep_package_only_whitelisted_fields`,
`test_rep_sensitive_data_rejected`, and `test_rep_extra_field_rejected`.

## Tests (tests/test_gateway_app.py)

20 PB-RUNTIME-015 tests, all passing, covering: the happy path (status `VALID`,
prefixed id, validates clean); the exact field whitelist; each of the four
component-hash missing modes; each of the three freshness/generation missing
modes; stale package; `package_hash` mismatch; id mismatch; forged-`VALID`-over-
`STALE` (`..._STATUS_MISMATCH`); duplicate via `seen_hashes`; sensitive data;
extra field; cross-check against the source index (match passes;
record-count mismatch and export-index-hash mismatch fail); and a chain-derived
package built over a real `/execute` decision that validates against the live
PB-RUNTIME-013 freshness index.

## Validation performed

- `python3.11 -m py_compile gateway/app.py tests/test_gateway_app.py` → OK.
- `pytest -k rep_` → 20 passed.
- Regression `tests/test_voucher_authority.py tests/test_travel_voucher.py` →
  77 passed.
- Full `tests/test_gateway_app.py` — the new tests pass; the only full-suite
  failures are pre-existing **order/shared-state-dependent** system-wide tests
  (the audit chain accumulates across system-wide tests) that pass in isolation.
  These are unrelated to this change.
- `git diff --check` → clean.

## Rollback

This change is purely additive (new constants, functions, tests, and this audit
doc). To revert: `git revert --no-edit HEAD`.
