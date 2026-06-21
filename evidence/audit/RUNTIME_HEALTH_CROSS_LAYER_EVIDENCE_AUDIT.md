# Runtime Health Cross-Layer Evidence Linkage Audit (PB-RUNTIME-008)

**Scope:** `gateway/app.py`, `tests/test_gateway_app.py`, this document.
**Goal:** Link Runtime Health evidence to the wider USBAY governance evidence
chain so every governed `/execute` decision can be traced across runtime state,
policy profile, decision outcome, audit hash, and upstream governance context —
without leaking sensitive data or weakening the existing fail-closed path.

This work is **additive and evidence-only**. It does **not** change the `/execute`
decision path, fail-closed behaviour, or any enforcement. No Codex, simulator,
travel/voucher, tenant, or RFC3161 surfaces were touched.

---

## 1. Linkage fields added

Building on PB-RUNTIME-007, each persisted `runtime_health_profile_decision`
record now carries cross-layer linkage. The full field set:

| Field | Layer | Source / status |
|---|---|---|
| `decision_id` | runtime | per-decision UUID (PB-RUNTIME-006). |
| `runtime_health_state` | runtime | `HEALTHY`/`DEGRADED`/`FAILED`. |
| `runtime_health_profile` | policy | active profile. |
| `profile_reason_code` | policy | why the profile decided (None for HEALTHY). |
| `execution_allowed` | runtime | boolean outcome. |
| `audit_event_type` | audit | `runtime_health_profile_decision` (PB-RUNTIME-007). |
| `audit_hash` | audit | envelope `hash_current` — see §3. |
| `previous_audit_hash` | audit | envelope `hash_prev` — see §3. |
| **`governance_context_id`** | governance | **NEW** — deterministic, from `decision_id`. |
| `policy_context_id` | policy | NEW — best-effort, from signed policy registry version. |
| `gateway_context_id` | gateway | NEW — best-effort, from runtime provenance commit. |

### Deterministic, non-sensitive derivation

- `governance_context_id = "gctx-" + SHA-256("usbay-runtime-health-governance-context-v1|" + decision_id)[:32]`
  — REQUIRED. Always present for a governed decision; binds the runtime-health
  record to a governance correlation token reproducible by anyone holding the
  (already non-sensitive) `decision_id`.
- `policy_context_id = "pctx-" + SHA-256("…policy-context-v1|" + policy_registry_version)[:32]`
  — POLICY layer. Best-effort.
- `gateway_context_id = "gwctx-" + SHA-256("…gateway-context-v1|" + current_commit)[:32]`
  — GATEWAY layer. Best-effort.

All three are opaque SHA-256-derived tokens — **never** raw payload, signatures,
secrets, or raw client identifiers. The source values (a UUID, a policy version
string, a git commit SHA) are themselves non-sensitive; hashing them adds defence
in depth and yields stable, joinable correlation ids.

The derivers **never raise**: a failure returns `None`, so the mandatory
PB-RUNTIME-006 profile-decision record can never be suppressed by linkage logic.

---

## 2. GAP documentation (no faked IDs)

Per the task: if `policy_context_id` or `gateway_context_id` is not available, it is
documented as a GAP and **not invented**.

- **In this workspace, all three layers resolve** — sampled at audit time:
  `governance` ✓, `policy` ✓ (signed policy registry has a `version`),
  `gateway` ✓ (runtime provenance exposes `current_commit`). So there is **no hard
  GAP** in the current environment.
- **Conditional GAP path (designed, not faked):** if the policy registry is
  unavailable / has no version, `policy_context_id` is `null`. If runtime
  provenance has no `current_commit`, `gateway_context_id` is `null`. The record
  key is still present (so the schema is stable) but the value is `null` — an
  honest "unavailable" signal, never a fabricated id. `audit_runtime_health_cross_layer_linkage`
  reports `policy_context_available` / `gateway_context_available` counts so any
  partial availability is visible.
- `governance_context_id` is **not** subject to a GAP: it derives only from
  `decision_id`, which is always present for a governed decision, and its absence
  is a hard validation failure (§4).

---

## 3. Hash linkage — `audit_hash` / `previous_audit_hash`

Consistent with PB-RUNTIME-007: records are persisted inside SHA-256 hash-chained
entry **envelopes** (`audit/hash_chain.py`). The task's `audit_hash` /
`previous_audit_hash` correspond to the envelope `hash_current` / `hash_prev`. They
are **not inlined** into the `decision` record (inlining a record's own hash into
the record it hashes is circular). The cross-layer validators read them from the
envelope.

Because `decision_id` lives **inside** the hashed `decision` payload, the audit
hash **binds** `decision_id` to `audit_hash`: any mutation of `decision_id` changes
the canonical record, so `hash_current` no longer recomputes — the tamper is
detected. This is exactly the "mismatched decision_id/audit_hash fails validation"
requirement, demonstrated by `test_tampered_decision_id_breaks_linkage_and_hash`.

**Hash-chain status: SUPPORTED and valid after linkage.** Adding the new linkage
fields to the record simply makes them part of the hashed payload; the
deterministic recompute remains consistent (`hash_chain_valid: True` in the
post-`/execute` audit report).

---

## 4. Validation added

All functions are pure / fail-closed and **never raise**:

- `derive_governance_context_id(decision_id)` — deterministic token (or `None`).
- `validate_runtime_health_cross_layer_record(record) -> (bool, [codes])` —
  PB-RUNTIME-007 evidence integrity **plus** governance-context linkage:
  - missing/null `governance_context_id` → `RUNTIME_HEALTH_LINKAGE_MISSING_GOVERNANCE_CONTEXT`.
  - `governance_context_id` not equal to the derivation from `decision_id` →
    `RUNTIME_HEALTH_LINKAGE_CONTEXT_MISMATCH`.
- `validate_runtime_health_cross_layer_entry(entry, *, prev_hash=None)` — record
  linkage + envelope action + deterministic hash integrity
  (`RUNTIME_HEALTH_LINKAGE_HASH_MISMATCH`).
- `audit_runtime_health_cross_layer_linkage(chain=None) -> report` — walks the full
  persisted chain, verifies tamper-evident linkage across **every** entry, validates
  every runtime-health record, and reports policy/gateway availability:
  `{ hash_chain_supported, checked, linked, valid, hash_chain_valid,
  policy_context_available, gateway_context_available, failures[] }`.

These are **offline/CI auditors** — deliberately **not** wired into `/execute`,
preserving the existing fail-closed decision path (no new runtime failure mode).

### Reason codes

`RUNTIME_HEALTH_LINKAGE_VALID`, `_MISSING_GOVERNANCE_CONTEXT`, `_CONTEXT_MISMATCH`,
`_HASH_MISMATCH`.

---

## 5. Test coverage (`tests/test_gateway_app.py`)

- `governance_context_id` derivation is deterministic, namespaced, and `None` for
  empty input.
- valid cross-layer record passes; **missing** `governance_context_id` fails;
  **null** `governance_context_id` fails; **mismatched** `governance_context_id`
  (not derived from `decision_id`) fails.
- cross-layer validation still inherits the PB-RUNTIME-007 integrity checks
  (incomplete record fails).
- the new context-id fields are not treated as sensitive data.
- **integration (real `/execute`):** persisted record is governance-linked
  (`governance_context_id == derive(decision_id)`), policy/gateway keys present;
  full entry validation passes; cross-layer audit report is `valid` with
  `hash_chain_valid` and `linked == checked`.
- **tamper:** mutating a persisted `decision_id` without recomputing the hash →
  `hash_chain_valid=False`, `valid=False`, `CONTEXT_MISMATCH` surfaced.
- **no sensitive data:** every persisted record passes the sensitive-data scan.
- empty chain is vacuously valid.

---

## 6. Validation results

- `python3.11 -m py_compile gateway/app.py tests/test_gateway_app.py` → **passes**.
- `pytest -q tests/test_gateway_app.py` → **127 passed**.
- `pytest -q tests/test_voucher_authority.py tests/test_governance_actions_policy_approvals.py`
  → **74 passed**.
- `git diff --check` → clean. `git diff --cached --check` → clean.
- runtime evidence has `governance_context_id` ✓; incomplete linkage fails ✓; hash
  chain remains valid ✓; no raw sensitive data in audit logs ✓.

## 7. Fail-closed evidence

- Context-id derivers never raise; the mandatory PB-RUNTIME-006 record is always
  persisted (verified by the existing always-on profile-decision tests, still green).
- Validators/auditors are evidence-only and not in the `/execute` path; the
  fail-closed gate behaviour is unchanged.

## 8. Files changed

- `gateway/app.py`
- `tests/test_gateway_app.py`
- `evidence/audit/RUNTIME_HEALTH_CROSS_LAYER_EVIDENCE_AUDIT.md` (this file)

## 9. Rollback

```
git revert --no-edit HEAD
```
(or roll back to the pre-task checkpoint `62c71a0`).
