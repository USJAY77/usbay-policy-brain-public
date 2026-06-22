# PB-RUNTIME-016 — Regulator Package SELF-DERIVATION Authority — Audit Evidence

## Purpose

PB-RUNTIME-015 produced a regulator-grade evidence package that *binds* four
governance digests under one tamper-evident package hash, but documented a
**GAP**: two of those digests — the **runtime proof hash** and the **canonical
E2E evidence hash** — were accepted **caller-supplied** and could not be
re-derived during validation.

PB-RUNTIME-016 **closes that GAP**. Each component hash is now **DERIVED** from
the existing runtime / export / freshness evidence whenever that source is
available, and a caller-supplied value is accepted **only as a documented
fallback** when the source is genuinely unavailable. Every hash now carries an
explicit **provenance classification**, and the package **fails closed** on a
derived/caller conflict, malformed source evidence, a false DERIVED claim, an
undocumented fallback over an available source, or any raw sensitive data.

This capability is **additive, evidence-only, read-only, deterministic, and
fail-closed**. It is **NOT** wired into `/execute`, makes **no** runtime
decision change, **reuses** (and never weakens) the PB-RUNTIME-015 core builder
and validator UNCHANGED, and **does not weaken** PB-RUNTIME-013 or
PB-RUNTIME-015.

## Scope (strictly)

- `gateway/app.py`
- `tests/test_gateway_app.py`
- `evidence/audit/RUNTIME_REGULATOR_PACKAGE_SELF_DERIVATION_AUDIT.md`

No simulator / voucher / travel / tenant / RFC3161 / Codex changes. No
`/execute` behavior change. No `policy_context_id` / `gateway_context_id`
invented. The PB-TRAVEL-005 voucher approval-chain work is already merged and is
**out of scope** for this task.

## Provenance model

Each of the four component hashes is classified with an exact source vocabulary
(`RUNTIME_REGULATOR_PACKAGE_HASH_SOURCES`):

- `DERIVED` — recomputed from existing runtime/export/freshness/E2E evidence; the
  derived value is authoritative.
- `CALLER_SUPPLIED` — the source was genuinely unavailable, so a caller-supplied
  value was accepted as a **documented fallback**.
- `UNAVAILABLE` — neither a derivable source nor a caller fallback was present.
- `MISMATCH` — a derived/caller conflict, or malformed source evidence
  (fail-closed).

The overall `source_derivation_status` summarises the four per-hash sources with
fail-closed precedence: `MISMATCH` > `UNAVAILABLE` > `CALLER_SUPPLIED` >
`DERIVED`. `source_derivation_reason_code` is the canonical reason for that
status.

### Derivation sources

- `runtime_proof_hash` ← `compute_runtime_proof_hash_from_export(...)` over the
  PB-RUNTIME-011 governance proof **export** evidence (ordered, non-sensitive
  proof verdict facets + count), namespaced `usbay.runtime.proof.hash.v1` and
  GENESIS-bound. (Closes the first half of the 015 GAP.)
- `export_index_hash` ← the PB-RUNTIME-012 export index hash from the
  PB-RUNTIME-013 freshness index over the chain.
- `freshness_index_hash` ← the PB-RUNTIME-013 freshness index hash over the
  chain.
- `e2e_evidence_hash` ← `compute_e2e_evidence_hash(...)` over a **canonical
  PB-E2E-005 E2E evidence object** (a non-sensitive dict), namespaced
  `usbay.runtime.e2e.evidence.hash.v1` and GENESIS-bound. (Closes the second
  half of the 015 GAP. When no E2E evidence object is supplied the source is
  genuinely unavailable, so a caller fallback is the documented path.)

## Package model (exact 18-field whitelist)

The self-derived package carries **exactly** the 12 PB-RUNTIME-015 core fields
(reused UNCHANGED via the 015 builder) plus **six** non-sensitive provenance /
audit fields
(`RUNTIME_REGULATOR_PACKAGE_SELF_DERIVATION_FIELDS`):

- `runtime_proof_hash_source`
- `export_index_hash_source`
- `freshness_index_hash_source`
- `e2e_evidence_hash_source`
- `source_derivation_status`
- `source_derivation_reason_code`

The package never carries per-record evidence, raw payloads, signatures,
secrets, client identifiers, or the raw source evidence objects — only the
derived digests and their provenance labels.

## Functions added (gateway/app.py)

- `compute_runtime_proof_hash_from_export(export_report)` — deterministic,
  namespaced, GENESIS-bound digest over the export proof facets; `None` when no
  usable export evidence exists. Pure; never raises.
- `compute_e2e_evidence_hash(e2e_evidence)` — deterministic, namespaced,
  GENESIS-bound digest over a canonical E2E evidence dict; `None` when no usable
  object exists. Pure; never raises.
- `_classify_runtime_regulator_package_hash_source(derived, caller, *,
  source_malformed=False)` — per-hash provenance classifier returning
  `(value, source)`; fail-closed precedence (malformed/conflict → MISMATCH,
  derived authoritative, caller fallback, else UNAVAILABLE).
- `classify_runtime_regulator_package_self_derivation_status(sources)` —
  summarises the four per-hash sources into `(status, reason_code)`.
- `build_runtime_regulator_package_self_derivation_from_chain(chain=None, *,
  e2e_evidence=None, runtime_proof_hash=None, export_index_hash=None,
  freshness_index_hash=None, e2e_evidence_hash=None, ...)` — derives each hash
  from the chain / E2E object, records provenance, accepts caller values only as
  documented fallback, and **reuses the PB-RUNTIME-015 core builder UNCHANGED**.
- `validate_runtime_regulator_package_self_derivation(package,
  freshness_index=None, *, chain=None, e2e_evidence=None, seen_hashes=None)` —
  pure, fail-closed validator returning `(is_valid, codes)`; **reuses the
  PB-RUNTIME-015 core validator UNCHANGED** on the extracted 12-field core.

All functions are pure / read-only and **not** referenced by `/execute`.

## Validation guarantees

`validate_runtime_regulator_package_self_derivation` proves a package is:

- **core-valid** — the 12-field core re-validates clean under the PB-RUNTIME-015
  validator UNCHANGED (currency, tamper-evidence, optional source-index
  cross-check, dedupe); any core failure → `..._CORE_INVALID`;
- **schema-exact** — exactly the 18 whitelisted fields; any extra key →
  `..._INCOMPLETE`;
- **non-sensitive** — reuses the forbidden-key/value scan → `..._SENSITIVE_DATA`;
- **known-provenance** — each per-hash source is a known enum
  (`..._UNKNOWN_SOURCE`) and the overall status is known
  (`..._UNKNOWN_STATUS`), with its reason consistent (`..._REASON_MISMATCH`) and
  the status re-derived from the four per-hash sources (`..._STATUS_MISMATCH`);
- **fully accountable** — a passing package has no `MISMATCH` provenance
  (`..._MISMATCH`) and no `UNAVAILABLE` provenance (`..._UNAVAILABLE`).

### Full evidentiary mode (source supplied)

When `chain` (for the runtime/export/freshness hashes) and/or `e2e_evidence`
(for the E2E hash) is supplied, every covered hash and its provenance are
**RE-DERIVED and compared**:

- a value conflict against the re-derived hash → `..._HASH_MISMATCH`;
- a DERIVED claim where the source re-derives to nothing → `..._FALSE_DERIVED`;
- a `CALLER_SUPPLIED` fallback declared over an **available** source →
  `..._UNDOCUMENTED_FALLBACK`;
- malformed E2E source evidence → `..._SOURCE_MALFORMED`;
- a provenance that is neither DERIVED nor a legitimate fallback for an available
  source → `..._SOURCE_MISMATCH`.

## Verification modes (what each proves)

- **Standalone** (package alone): structural + internal-consistency + full
  accountability. Proves the package is schema-exact, non-sensitive,
  core-valid, declares known provenance whose overall status re-derives, and is
  fully accountable (no MISMATCH / UNAVAILABLE). It does **not** by itself anchor
  the hashes to their sources.
- **Full evidentiary** (`chain=...` and/or `e2e_evidence=...`): additionally
  re-derives every covered hash and proves provenance truthfulness
  (HASH_MISMATCH / FALSE_DERIVED / UNDOCUMENTED_FALLBACK / SOURCE_MALFORMED).
  This is the mode USBAY uses to *prove* the package self-derived correctly.

## GAP closure

The PB-RUNTIME-015 documented GAP — that `runtime_proof_hash` and
`e2e_evidence_hash` were caller-supplied and unverifiable — is now closed:

- `runtime_proof_hash` is **DERIVED** from the runtime governance proof export
  evidence and re-derived/compared during full-mode validation.
- `e2e_evidence_hash` is **DERIVED** from the supplied canonical E2E evidence
  object and re-derived/compared during full-mode validation.

A caller-supplied value survives only as a **documented fallback** for a
genuinely unavailable source; declaring a fallback over an available source, or
forging a DERIVED claim, fails closed.

## Fail-closed evidence

- Non-dict package → `..._INCOMPLETE`, `is_valid=False`.
- Derived/caller conflict or malformed source → `MISMATCH` provenance →
  `..._MISMATCH` (and, in full mode, `..._HASH_MISMATCH` / `..._SOURCE_MALFORMED`).
- A DERIVED claim with no re-derivable source → `..._FALSE_DERIVED`.
- A CALLER_SUPPLIED fallback over an available source → `..._UNDOCUMENTED_FALLBACK`.
- Any raw sensitive material → `..._SENSITIVE_DATA`.
- Any forged provenance/status → `..._UNKNOWN_SOURCE` / `..._UNKNOWN_STATUS` /
  `..._REASON_MISMATCH` / `..._STATUS_MISMATCH`.

## Read-only / `/execute` untouched

The builder and validator never mutate the audit chain; `/execute` does not
reference any 016 symbol. `test_sd_execute_unchanged_and_read_only` asserts the
chain length is unchanged across a build + validate cycle and that `/execute`
still returns 200 and remains the sole writer.

## Tests (tests/test_gateway_app.py)

11 PB-RUNTIME-016 tests, all passing, covering: fully derived passes (all four
sources DERIVED, full-mode validates clean); exact 18-field whitelist; documented
caller fallback passes (E2E source genuinely unavailable); undocumented fallback
over an available source fails; derived/caller mismatch fails; malformed source
fails; false DERIVED (re-derived against an empty chain) fails; unknown source
guard; forged overall status guard; sensitive data fails; and `/execute`
unchanged + read-only.

## Validation performed

- `python3.11 -m py_compile gateway/app.py tests/test_gateway_app.py` → OK.
- `pytest -k "test_sd_ or rep_"` → 31 passed (016 + 015 together).
- Regression `tests/test_voucher_authority.py tests/test_travel_voucher.py` →
  77 passed.
- Full `tests/test_gateway_app.py` → 282 passed.
- `git diff --check` → clean.
- `USBAY Gateway` workflow running.

## Rollback

This change is purely additive (new constants, functions, tests, and this audit
doc). To revert: `git revert --no-edit HEAD`.
