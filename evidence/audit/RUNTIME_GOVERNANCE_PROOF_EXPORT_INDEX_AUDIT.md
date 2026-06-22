# PB-RUNTIME-012 — Runtime Governance Proof Export Index — Audit Evidence

## 1. Purpose

Add a **read-only, evidence-only, deterministic** index over the PB-RUNTIME-011
governance proof **export packages** so auditors can discover, count, and
integrity-check **which** proof packages exist, confirm they are **unique**, and
verify the **index integrity** — without exposing raw payloads, signatures,
secrets, or raw client identifiers, and without altering the `/execute` path.

This capability is **not** wired into `/execute`. It never mutates the audit
chain, never invents missing context ids, and fails closed.

## 2. Scope (exactly the files changed)

- `gateway/app.py` — export-index constants + four pure functions.
- `tests/test_gateway_app.py` — 15 new index tests appended.
- `evidence/audit/RUNTIME_GOVERNANCE_PROOF_EXPORT_INDEX_AUDIT.md` — this file.

No simulator / travel / voucher / tenant / RFC3161 / Codex changes. No `/execute`
behavior change. No runtime decision weakening.

## 3. Export index model

The index is **derived from** the PB-RUNTIME-011 system-wide export report
(`build_runtime_governance_proof_export`). For every governed `/execute` decision
already present as a proof export package, the index emits one **non-sensitive
index record** stamped with a deterministic `export_record_hash`, and the index as
a whole carries a deterministic `export_index_hash`.

Functions (all pure, read-only, fail-closed, never raise):

- `compute_runtime_governance_proof_export_record_hash(record)` — SHA-256 over a
  **fixed whitelist** of the record's non-sensitive metadata fields, in canonical
  sorted-key JSON, domain-separated by the record namespace. Because the digest is
  computed from a whitelist only, any injected/extra field is **ignored by the
  hash** and caught separately by the sensitive-data scan.
- `compute_runtime_governance_proof_export_index_hash(records)` — rolling SHA-256
  chaining each record's `export_record_hash` in order, **seeded with the audit
  `GENESIS_HASH`**, domain-separated by the index namespace. An empty index yields
  the genesis seed (deterministic).
- `build_runtime_governance_proof_export_index_record(package)` — builds one index
  record from an export package using a whitelist (raw fields can never leak),
  emitting optional ids only when present, and stamping `export_record_hash`.
- `build_runtime_governance_proof_export_index(chain=None)` — system-wide index
  over every governed decision; carries forward the underlying export hash-chain
  verdict and optional-context availability counts.

### Determinism

`export_record_hash` and `export_index_hash` are pure functions of the indexed
metadata (which itself derives from the deterministic PB-RUNTIME-011 packages,
whose `proof_generated_at` is the envelope timestamp, **not** wall-clock). Building
the same index twice yields identical hashes (test:
`test_export_index_record_hash_is_deterministic`).

## 4. Index fields

Per index **record**:

| Field | Required | Notes |
|---|---|---|
| `decision_id` | yes | uniqueness key |
| `audit_hash` | yes | uniqueness key (the package `audit_hash`) |
| `previous_audit_hash` | optional | emitted only when present in the source package |
| `governance_context_id` | yes | |
| `proof_status` | yes | carried from the PB-RUNTIME-011 proof verdict |
| `proof_reason_code` | yes | carried from the PB-RUNTIME-011 proof verdict |
| `proof_generated_at` | yes | deterministic envelope timestamp |
| `policy_context_id` | optional | emitted only when present; never invented |
| `gateway_context_id` | optional | emitted only when present; never invented |
| `export_record_hash` | yes | deterministic digest of the record (whitelist) |

Per **index** (top level): `index_supported`, `hash_chain_supported`, `count`,
`records`, `export_index_hash`, `export_valid`, `hash_chain_valid`,
`policy_context_available`, `gateway_context_available`,
`optional_context_unavailable`, `index_integrity_valid`, `reason_codes`, `valid`.

`export_index_hash` is a **top-level** integrity value only. It is intentionally
not stamped onto each record: the index hash is computed *from* the record hashes,
so embedding it back into a record would be circular.

## 5. Reason codes (`RUNTIME_GOVERNANCE_PROOF_EXPORT_INDEX_*` namespace)

- `..._VALID` — index passes.
- `..._INCOMPLETE` — non-dict index/records, or a record missing a required field.
- `..._DUPLICATE_DECISION` — a `decision_id` appears more than once.
- `..._DUPLICATE_AUDIT_HASH` — an `audit_hash` appears more than once.
- `..._RECORD_HASH_MISMATCH` — a record's `export_record_hash` does not recompute.
- `..._HASH_MISMATCH` — the top-level `export_index_hash` does not recompute.
- `..._POLICY_CONTEXT_MALFORMED` — `policy_context_id` present but malformed.
- `..._GATEWAY_CONTEXT_MALFORMED` — `gateway_context_id` present but malformed.
- `..._SENSITIVE_DATA` — a record carries raw sensitive data (defense-in-depth).

`validate_runtime_governance_proof_export_index` returns `(is_valid, [codes])`,
deduped. Pure and fail-closed.

## 6. Hash / index status

- **Record integrity:** each `export_record_hash` is recomputed during validation;
  any tamper to the indexed metadata flips the digest →
  `..._RECORD_HASH_MISMATCH`.
- **Index integrity:** the top-level `export_index_hash` is recomputed from the
  ordered record hashes; reordering, insertion, deletion, or hash tamper →
  `..._HASH_MISMATCH`.
- **Underlying chain:** `build_runtime_governance_proof_export_index` carries
  forward `hash_chain_valid` from the PB-RUNTIME-011 export report, so an upstream
  audit-chain tamper propagates into the index's overall `valid` verdict.
- In this workspace the full pipeline resolves: system-wide index over a real
  `/execute` decision is `valid` (test: `test_export_index_system_wide_valid`).

## 7. Documented GAPs

- **Optional context ids** (`policy_context_id`, `gateway_context_id`,
  `previous_audit_hash`) are emitted **only when genuinely present** in the source
  export package and are **never synthesized**. When the underlying layer is
  unavailable they are simply absent (the documented-unavailable GAP), which does
  **not** by itself fail the index. Availability is surfaced via
  `policy_context_available` / `gateway_context_available` /
  `optional_context_unavailable`. Tests:
  `test_export_index_omits_absent_optional_ids_never_faked`,
  `test_export_index_includes_optional_ids_when_present`.
- The index is **discovery/verification metadata only**. It deliberately does not
  carry the full proof package (e.g. `runtime_health_profile`,
  `execution_allowed`); the PB-RUNTIME-011 export remains the source of the full
  evidence package.

## 8. Fail-closed evidence

- All four functions are pure and never raise; non-dict / missing inputs degrade to
  empty/failed verdicts rather than exceptions.
- The index is **never wired into `/execute`** — no route, middleware, or decision
  path references it.
- Building the index does **not** mutate the audit chain (test:
  `test_export_index_is_read_only` asserts `audit_chain.load()` is unchanged
  before/after).
- Raw-sensitive leakage is prevented primarily by **whitelist construction**
  (`build_runtime_governance_proof_export_index_record`), with
  `runtime_health_evidence_contains_sensitive_data` as defense-in-depth in the
  validator. Tests:
  `test_export_index_record_never_carries_raw_sensitive_fields`,
  `test_export_index_sensitive_data_rejected`.

## 9. Validation results

- `python3.11 -m py_compile gateway/app.py tests/test_gateway_app.py` — **passes**.
- `pytest -q tests/test_gateway_app.py` — **190 passed** (175 prior + 15 new).
- `pytest -q tests/test_voucher_authority.py tests/test_governance_actions_policy_approvals.py`
  — **74 passed**.
- `git diff --check` — **clean**.
- `git diff --cached --check` — **clean**.

Required validation cases, all covered by passing tests:

| Requirement | Test |
|---|---|
| valid export index passes | `test_export_index_valid_passes`, `test_export_index_system_wide_valid` |
| missing required index fields fails | `test_export_index_missing_required_field_fails` |
| duplicate decision_id fails | `test_export_index_duplicate_decision_id_fails` |
| duplicate audit_hash fails | `test_export_index_duplicate_audit_hash_fails` |
| export_record_hash mismatch fails | `test_export_index_record_hash_mismatch_fails` |
| export_index_hash mismatch fails | `test_export_index_hash_mismatch_fails` |
| sensitive raw data rejected | `test_export_index_sensitive_data_rejected`, `test_export_index_record_never_carries_raw_sensitive_fields` |
| optional ids omitted when unavailable / never faked | `test_export_index_omits_absent_optional_ids_never_faked`, `test_export_index_includes_optional_ids_when_present` |
| execution path unchanged | `test_export_index_is_read_only` (+ no `/execute` wiring) |

## 10. Rollback

```
git revert --no-edit HEAD
```

The change is purely additive (new constants, four new functions, new tests, this
doc) and is unreferenced by the execution path, so a revert removes the capability
with no impact on `/execute`.
