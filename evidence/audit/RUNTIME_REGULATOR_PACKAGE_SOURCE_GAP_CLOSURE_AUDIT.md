# PB-RUNTIME-017 — REGULATOR PACKAGE SOURCE GAP CLOSURE — AUDIT EVIDENCE

## Purpose

PB-RUNTIME-016 made the regulator evidence package self-deriving but documented a
residual GAP: a component hash value **may still be caller-supplied** when its
source evidence is unavailable. PB-RUNTIME-017 closes that gap by adding a strict,
auditor-readable **source gap closure report** that, for every one of the four
required component hashes, records an **explicit source state**, requires a
**non-sensitive justification** before any caller-supplied fallback is accepted,
documents a genuinely-unavailable source, and **fails closed** on an undocumented
fallback, a false claim, a mismatch, malformed evidence, sensitive data, a
mixed-state inconsistency, or a missing report.

This layer is **additive, evidence-only, read-only**. It is **NOT** wired into
`/execute` and does **NOT** weaken PB-RUNTIME-013, PB-RUNTIME-015, or
PB-RUNTIME-016. It introduces **no** new endpoint, no simulator change, no
travel/voucher change, no tenant change, and no RFC3161 change.

## Files changed

| File | Change |
| --- | --- |
| `gateway/app.py` | Added the PB-RUNTIME-017 constants block (6 source states, 3 report statuses, namespace + id prefix, exact 8-field whitelist, hash→state-field map, `RHC_REP_GAP_*` reason codes, status→reason and blocked-state→reason maps) and 6 pure functions (state classifier, report-status classifier, report hash + id, the shared state re-derivation helper, the builder, and the fail-closed validator). |
| `tests/test_gateway_app.py` | Added 16 PB-RUNTIME-017 tests (`test_gap_*`) + a re-seal helper. |
| `evidence/audit/RUNTIME_REGULATOR_PACKAGE_SOURCE_GAP_CLOSURE_AUDIT.md` | This document. |

## Tracked sources (independent)

Each of the four required regulator-package component hashes is tracked and
classified **independently**:

- `runtime_proof_hash`   → `runtime_proof_source_state`   (derived from PB-RUNTIME-011 export evidence)
- `export_index_hash`    → `export_index_source_state`    (derived from PB-RUNTIME-012 export index)
- `freshness_index_hash` → `freshness_index_source_state` (derived from PB-RUNTIME-013 freshness index)
- `e2e_evidence_hash`    → `e2e_evidence_source_state`     (derived from a canonical E2E evidence object)

## Source gap closure model

The builder re-derives every component hash from its source evidence (the audit
`chain` for the runtime/export/freshness hashes; the canonical `e2e_evidence`
object for the E2E hash), honours any caller-supplied value + per-source
justification, classifies each into one explicit state, then seals the four
states into a self-binding report:

- `source_gap_report_hash` = `sha256(NAMESPACE | GENESIS_HASH | canonical({4 state fields}))` — tamper-evident binding of the four states.
- `source_gap_report_status` = classified from the four states (see precedence below).
- `source_gap_report_reason_code` = canonical reason for the status.
- `source_gap_report_id` = `usbsgr-` + `sha256(NAMESPACE | GENESIS_HASH | canonical({report_hash, status, reason}))[:32]` — content-derived id binding the hash + status + reason.

The justification **text is never stored** — only the resulting state — so the
report is non-sensitive by construction.

### Source states (6)

| State | Meaning |
| --- | --- |
| `DERIVED` | Hash derived from available source evidence. |
| `CALLER_SUPPLIED_DOCUMENTED` | Source genuinely unavailable; caller value supplied **with** a non-sensitive justification. |
| `UNAVAILABLE_DOCUMENTED` | Source unavailable and no value supplied (documented absence). |
| `MISMATCH_BLOCKED` | Derived/caller conflict (source hash mismatch) **or** a caller value with no documented (justified) unavailable source. |
| `MALFORMED_BLOCKED` | Source evidence is malformed. |
| `SENSITIVE_DATA_BLOCKED` | The caller justification carries sensitive data. |

Closed (accountable) states: `DERIVED`, `CALLER_SUPPLIED_DOCUMENTED`,
`UNAVAILABLE_DOCUMENTED`. Blocked states: `MISMATCH_BLOCKED`,
`MALFORMED_BLOCKED`, `SENSITIVE_DATA_BLOCKED`.

### Report status (3), fail-closed precedence

1. `INCOMPLETE` — any per-source state is unknown / absent.
2. `BLOCKED` — any per-source state is a `*_BLOCKED` state.
3. `CLOSED` — every per-source state is an accountable closed state.

A report only passes validation when its status is `CLOSED`.

## Audit fields (8, non-sensitive)

`source_gap_report_id`, `source_gap_report_status`,
`source_gap_report_reason_code`, `source_gap_report_hash`,
`runtime_proof_source_state`, `export_index_source_state`,
`freshness_index_source_state`, `e2e_evidence_source_state`.

The validator enforces this as the **exact** whitelist (a missing or extra key
fails with `..._INCOMPLETE`).

## Reason codes

Status: `..._CLOSED`, `..._BLOCKED`, `..._INCOMPLETE`.
Structural / tamper: `..._MISSING_REPORT`, `..._UNKNOWN_STATE`,
`..._UNKNOWN_STATUS`, `..._STATUS_MISMATCH`, `..._REASON_MISMATCH`,
`..._HASH_MISMATCH`, `..._ID_MISMATCH`, `..._SENSITIVE_DATA`.
Blocked-state accountability: `..._MISMATCH_BLOCKED`, `..._MALFORMED_BLOCKED`,
`..._SENSITIVE_BLOCKED`.
Full-evidentiary divergence: `..._STATE_MISMATCH`, `..._FALSE_DERIVED`,
`..._FALSE_UNAVAILABLE`, `..._UNDOCUMENTED_FALLBACK`,
`..._MISSING_JUSTIFICATION`. (All prefixed `RUNTIME_REGULATOR_SOURCE_GAP_`.)

## Fail-closed evidence (validation modes)

**Standalone** (structural + internal consistency) proves: the report exists and
carries no raw sensitive data; the exact 8-field whitelist; a known state per
component hash; a known overall status whose reason re-derives and whose value
re-derives from the four states; that the hash + content-derived id re-bind the
sealed states/status/reason (tamper-evident); and — as accountability — that a
passing report is `CLOSED` (any blocked state fails with its specific code).

**Full evidentiary** (any of `chain` / `e2e_evidence` / a caller hash /
`justifications` supplied) additionally RE-DERIVES every state from the source
evidence and compares: a false `DERIVED` claim (`FALSE_DERIVED`), a false
`UNAVAILABLE` claim (`FALSE_UNAVAILABLE`), a caller fallback over an available
source (`UNDOCUMENTED_FALLBACK`), a documented caller state whose justification is
actually missing (`MISSING_JUSTIFICATION`), or any other divergence
(`STATE_MISMATCH`) all fail closed.

Each required fail-closed case has a dedicated test (`test_gap_*`):

| Case | Test | Outcome |
| --- | --- | --- |
| fully derived package | `test_gap_fully_derived_passes` | PASS (CLOSED) |
| exact 8-field schema | `test_gap_only_whitelisted_fields` | PASS |
| documented caller fallback | `test_gap_documented_caller_fallback_passes` | PASS (CLOSED) |
| undocumented fallback | `test_gap_undocumented_fallback_fails` | FAIL `MISMATCH_BLOCKED` |
| fallback over available source | `test_gap_fallback_over_available_source_fails` | FAIL `UNDOCUMENTED_FALLBACK` |
| missing justification | `test_gap_missing_justification_fails` | FAIL `MISSING_JUSTIFICATION` |
| derived/caller mismatch | `test_gap_mismatch_fails` | FAIL `MISMATCH_BLOCKED` |
| malformed source | `test_gap_malformed_source_fails` | FAIL `MALFORMED_BLOCKED` |
| sensitive justification | `test_gap_sensitive_justification_fails` | FAIL `SENSITIVE_BLOCKED` (and report stays non-sensitive) |
| false DERIVED | `test_gap_false_derived_fails` | FAIL `FALSE_DERIVED` |
| false UNAVAILABLE | `test_gap_false_unavailable_fails` | FAIL `FALSE_UNAVAILABLE` |
| missing report | `test_gap_missing_report_fails` | FAIL `MISSING_REPORT` |
| unknown state | `test_gap_unknown_state_fails` | FAIL `UNKNOWN_STATE` |
| mixed-state / forged status | `test_gap_status_mismatch_fails` | FAIL `STATUS_MISMATCH` |
| tampered state (no re-seal) | `test_gap_hash_mismatch_fails` | FAIL `HASH_MISMATCH` |
| /execute unchanged + read-only | `test_gap_execute_unchanged_and_read_only` | PASS (chain unchanged by build/validate; `/execute` remains the only writer) |
| forged self-consistent CLOSED report | `test_gap_forged_closed_passes_standalone_caught_in_full_mode` | standalone PASS (binding is tamper-evidence, not provenance); full mode FAIL `FALSE_DERIVED` |
| documented-caller claim over conflicting source | `test_gap_documented_conflict_is_state_mismatch_not_missing_just` | FAIL `STATE_MISMATCH` (not `MISSING_JUSTIFICATION`) |

`MISSING_JUSTIFICATION` is emitted **only** when a caller claims
`CALLER_SUPPLIED_DOCUMENTED` and the per-source justification is genuinely absent.
A derived/caller conflict, a malformed source, or a sensitive justification under a
documented claim is a plain `STATE_MISMATCH`, so the divergence reason never
mislabels a conflict as a missing justification.

## Validation results

- `python3.11 -m py_compile gateway/app.py tests/test_gateway_app.py` → PASS
- `python3.11 -m pytest tests/test_gateway_app.py -k gap_ -q` → 18 passed
- `python3.11 -m pytest tests/test_gateway_app.py -q` → 300 passed (282 non-gap + 18 gap)
- `python3.11 -m pytest tests/test_travel_voucher.py tests/test_voucher_authority.py -q` → 77 passed
- `git diff --check` / `git diff --cached --check` → clean
- `USBAY Gateway` workflow boots
- No `/execute` behaviour change; no sensitive data exported

## Remaining GAPs

- The report is an **off-band attestation**: it is intentionally **not** wired
  into `/execute` and does not gate live execution (by design, per scope).
- `MALFORMED_BLOCKED` is detected for the canonical `e2e_evidence` object (which
  has a checkable shape); a malformed audit `chain` instead yields an unavailable
  derived value (the runtime/export/freshness sources have no separate malformed
  signal).
- Full evidentiary verification still requires the verifier to **supply** the
  source evidence (`chain` / `e2e_evidence` / `justifications`); standalone mode
  proves internal consistency and tamper-evidence only.

## Rollback command

```
git checkout HEAD -- gateway/app.py tests/test_gateway_app.py
git rm -f evidence/audit/RUNTIME_REGULATOR_PACKAGE_SOURCE_GAP_CLOSURE_AUDIT.md
```
