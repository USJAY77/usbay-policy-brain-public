# Runtime Health Cross-Layer Reconciliation Audit (PB-RUNTIME-009)

**Scope:** `gateway/app.py`, `tests/test_gateway_app.py`, this document.
**Goal:** Reconcile Runtime Health cross-layer evidence **over time** so every
governed `/execute` audit record can prove its runtime state, profile decision,
hash chain, and governance/policy/gateway context remain **synchronized and
internally consistent** — without leaking sensitive data and without weakening the
existing fail-closed path.

This builds on PB-RUNTIME-007 (evidence integrity) and PB-RUNTIME-008 (cross-layer
linkage). Where 008 proved the layers were *linked*, 009 proves they stay
*reconciled*: the same decision_id, hashes, state, profile, and context ids must
still agree with one another whenever the chain is re-audited.

This work is **additive and evidence-only**. It does **not** change the `/execute`
decision path, fail-closed behaviour, or any enforcement. No Codex, simulator,
travel/voucher, tenant, or RFC3161 surfaces were touched.

---

## 1. Reconciliation model

A runtime-health decision record is **reconciled** only when every layer agrees:

| Reconciled element | Layer | Rule |
|---|---|---|
| `decision_id` | runtime | present; equals the value bound into `governance_context_id` and into the hashed envelope. |
| `runtime_health_state` ↔ `execution_allowed` | runtime | HEALTHY⇒allow, FAILED⇒block (fail-closed invariant), DEGRADED⇒per-profile (STRICT block, BALANCED/CONTINUITY warn-allow). |
| `runtime_health_profile` ↔ `profile_reason_code` | policy | HEALTHY⇒no reason; a DEGRADED branch carries exactly its profile's reason code; FAILED not reason-constrained. |
| `audit_event_type` | audit | the runtime-health evidence event type. |
| `audit_hash` (`hash_current`) | audit | deterministically recomputes — also proves `decision_id` unchanged. |
| `previous_audit_hash` (`hash_prev`) | audit | links to the preceding entry (chain intact). |
| `governance_context_id` | governance | **required**; equals `derive(decision_id)` (binds runtime⇄governance). |
| `policy_context_id` | policy | best-effort; if present, well-formed (`pctx-` + 32 hex). |
| `gateway_context_id` | gateway | best-effort; if present, well-formed (`gwctx-` + 32 hex). |

Reconciliation is performed by three pure, fail-closed functions (none raise):

- `reconcile_runtime_health_cross_layer_record(record)` — record-level: structural
  completeness, governance binding, state/outcome + profile/reason synchronization,
  optional-id well-formedness, sensitive-data absence.
- `reconcile_runtime_health_cross_layer_entry(entry, *, prev_hash=None)` — adds the
  envelope hash checks (audit_hash recompute + previous_audit_hash linkage).
- `audit_runtime_health_cross_layer_reconciliation(chain=None)` — walks the whole
  persisted chain, reconciles every runtime-health entry, verifies whole-chain
  tamper-evidence, and reports availability + a documented-unavailable count.

These are **offline/CI auditors** — deliberately **not** wired into `/execute`, so
the existing fail-closed decision path gains no new runtime failure mode.

---

## 2. Reconciliation reason codes

| Code | Raised when |
|---|---|
| `RUNTIME_HEALTH_RECONCILIATION_VALID` | (semantic "ok" token.) |
| `..._INCOMPLETE` | required field missing or a non-null field is null. |
| `..._MISSING_GOVERNANCE_CONTEXT` | `governance_context_id` absent/null. |
| `..._DECISION_ID_MISMATCH` | `governance_context_id` ≠ `derive(decision_id)` (decision_id desynchronized from its governance binding). |
| `..._AUDIT_HASH_MISMATCH` | `hash_current` does not deterministically recompute. |
| `..._PREVIOUS_HASH_MISMATCH` | `hash_prev` breaks linkage to the prior entry. |
| `..._PROFILE_REASON_CONFLICT` | profile and `profile_reason_code` disagree. |
| `..._STATE_OUTCOME_CONFLICT` | `runtime_health_state` and `execution_allowed` disagree. |
| `..._POLICY_CONTEXT_MALFORMED` | `policy_context_id` present but not `pctx-`+32 hex. |
| `..._GATEWAY_CONTEXT_MALFORMED` | `gateway_context_id` present but not `gwctx-`+32 hex. |
| `..._SENSITIVE_DATA` | raw payload/signature/secret/raw client id detected. |

All codes are de-duplicated per record. A record with no codes is reconciled.

---

## 3. Hash-chain status

**SUPPORTED and valid after reconciliation.** Records persist inside SHA-256
hash-chained entry envelopes (`audit/hash_chain.py`). `audit_hash` /
`previous_audit_hash` correspond to envelope `hash_current` / `hash_prev`. 009
**splits** the verification into two reconciliation signals:

- `hash_current` recompute → `AUDIT_HASH_MISMATCH` (also fires on any `decision_id`
  tamper, because `decision_id` lives inside the hashed `decision` payload).
- `hash_prev` linkage → `PREVIOUS_HASH_MISMATCH`.

Because `decision_id` is hashed **and** independently bound through
`governance_context_id = derive(decision_id)`, a tampered `decision_id` is caught
twice — by `AUDIT_HASH_MISMATCH` and by `DECISION_ID_MISMATCH` — and the chain
report's `hash_chain_valid` flips to `False`. Demonstrated by
`test_reconciliation_detects_tampered_decision_id`. A deliberately broken
`hash_prev` is caught by `test_reconciliation_detects_broken_previous_hash_chain`.

---

## 4. Documented GAPs (no faked IDs)

- `governance_context_id` is **required**: its absence is a hard reconciliation
  failure (`MISSING_GOVERNANCE_CONTEXT`); it is never fabricated.
- `policy_context_id` / `gateway_context_id` are **best-effort**. When the
  underlying layer is unavailable the value is `None` (the documented-unavailable
  GAP) and reconciliation does **not** fail on that basis
  (`test_reconciliation_passes_when_optional_context_ids_absent`). They are **never
  invented** — the only optional-id failure is *malformed-when-present*.
- The chain auditor reports `policy_context_available`, `gateway_context_available`,
  and `optional_context_unavailable` so any partial-availability GAP is visible
  without faking ids.
- **In this workspace all three layers resolve** (sampled at audit time:
  governance ✓, policy ✓, gateway ✓), so there is no hard GAP here; the
  conditional-null path is designed and tested, not faked.

---

## 5. Sensitive-data protection

Reconciliation reuses the PB-RUNTIME-007 sensitive-data scan: any raw payload,
signature, secret, or raw client identifier (by key or by value marker) yields
`RECONCILIATION_SENSITIVE_DATA`. The new context ids
(`gctx-`/`pctx-`/`gwctx-` opaque hashes) are non-sensitive and do not trip the
scan. Verified by `test_reconciliation_rejects_sensitive_data` and the persisted
no-sensitive-data assertions.

---

## 6. Test coverage (`tests/test_gateway_app.py`)

- valid reconciliation passes; reconciliation passes when optional context ids are
  absent (documented-unavailable).
- missing `governance_context_id` fails; `decision_id` mismatch fails.
- profile/reason conflict fails; state/outcome conflict fails (FAILED⇒allowed=True).
- malformed `policy_context_id` fails when present; malformed `gateway_context_id`
  fails when present; the malformed-helper accepts absent and well-formed ids.
- sensitive data is rejected; incomplete record fails.
- **integration (real `/execute`):** persisted chain reconciliation is `valid`
  with `hash_chain_valid` and `reconciled == checked`; persisted entry reconciles.
- **tamper:** mutated `decision_id` → `DECISION_ID_MISMATCH` + `AUDIT_HASH_MISMATCH`,
  `hash_chain_valid=False`; broken `hash_prev` → chain invalid.
- empty chain is vacuously valid.

---

## 7. Validation results

- `python3.11 -m py_compile gateway/app.py tests/test_gateway_app.py` → **passes**.
- `pytest -q tests/test_gateway_app.py` → **143 passed**.
- `pytest -q tests/test_voucher_authority.py tests/test_governance_actions_policy_approvals.py`
  → **74 passed**.
- `git diff --check` → clean. `git diff --cached --check` → clean.
- valid reconciliation passes ✓; incomplete reconciliation fails ✓; hash-chain
  break fails ✓; no sensitive data in reconciliation evidence ✓; optional context
  ids documented when absent, never faked ✓.

## 8. Fail-closed evidence

- Reconciliation functions/auditors are evidence-only and **not** in the `/execute`
  path; the fail-closed gate behaviour is unchanged.
- The state/outcome reconciliation rule encodes the fail-closed invariant directly:
  FAILED must always block in every profile; any `allowed=True` for FAILED is a
  `STATE_OUTCOME_CONFLICT`.
- All helpers/derivers never raise, so the mandatory PB-RUNTIME-006 profile-decision
  record can never be suppressed by reconciliation logic.

## 9. Files changed

- `gateway/app.py`
- `tests/test_gateway_app.py`
- `evidence/audit/RUNTIME_HEALTH_CROSS_LAYER_RECONCILIATION_AUDIT.md` (this file)

## 10. Rollback

```
git revert --no-edit HEAD
```
(or roll back to the pre-task checkpoint `d458f43`).
