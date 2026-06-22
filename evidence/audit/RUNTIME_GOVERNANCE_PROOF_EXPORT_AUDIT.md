# Runtime Governance Proof Export (PB-RUNTIME-011)

## Purpose

This capability lets USBAY produce a **deterministic, non-sensitive,
auditor-readable evidence package** for every governed `/execute` decision,
derived from the PB-RUNTIME-010 system-wide governance proof — **without
weakening the execution path**.

The export is **read-only / evidence-only**: it is **not** wired into `/execute`,
does not alter live execution behaviour, and changes no simulator, voucher,
travel, tenant, RFC3161, or Codex flow. It never exports raw payloads,
signatures, secrets, or raw client identifiers, and it never invents missing
`policy_context_id` / `gateway_context_id`.

## Scope of change

- `gateway/app.py` — export reason codes, export field whitelist, the export
  package builder, the export validator, and the system-wide export report
  builder (all additive; no existing logic changed).
- `tests/test_gateway_app.py` — 14 export tests.
- `evidence/audit/RUNTIME_GOVERNANCE_PROOF_EXPORT_AUDIT.md` — this document.

No other files were modified.

## Proof export model

Three deterministic, pure, fail-closed, never-raising surfaces:

### 1. `build_runtime_governance_proof_export_entry(entry, *, prev_hash=None) -> package`

Builds the non-sensitive evidence package for a single audit envelope. The
package is assembled from a **fixed whitelist only**, so raw record fields can
never leak into an export. It carries the PB-RUNTIME-010 proof verdict
(`proof_status` + reason codes). Optional fields are emitted **only when present**
and are never invented. `proof_generated_at` reuses the envelope's existing
**deterministic** timestamp — no wall-clock — so exports are reproducible.

### 2. `validate_runtime_governance_proof_export(package) -> (ok, [codes])`

Validates an export package: all required fields present and non-null
(`profile_reason_code` may legitimately be `None` for `HEALTHY`), `proof_status`
is `VALID`, optional context ids well-formed **when present**, and no raw
sensitive data (defense-in-depth scan over the whole package).

### 3. `build_runtime_governance_proof_export(chain=None) -> report`

Builds the system-wide export report over every persisted
`runtime_health_profile_decision` entry, verifying whole-chain tamper-evidence
with the **rolling** previous hash (seeded with `GENESIS_HASH`) and reporting
best-effort policy/gateway context availability plus a documented-unavailable
count.

## Export fields

Each export package contains:

| Field | Always present? | Source |
|-------|-----------------|--------|
| `decision_id` | yes | decision record |
| `runtime_health_state` | yes | decision record |
| `runtime_health_profile` | yes | decision record |
| `profile_reason_code` | key always present (value `None` for `HEALTHY`) | decision record |
| `execution_allowed` | yes | decision record |
| `audit_event_type` | yes | decision record |
| `audit_hash` | yes | envelope `hash_current` |
| `governance_context_id` | yes | decision record |
| `proof_status` | yes | PB-RUNTIME-010 proof verdict (`VALID` / `FAILED`) |
| `proof_reason_code` | yes | canonical proof code (`…_PROOF_VALID` or first failure) |
| `proof_reason_codes` | yes | full proof reason-code list |
| `proof_generated_at` | yes | envelope timestamp (deterministic) |
| `previous_audit_hash` | only when present | envelope `hash_prev` |
| `policy_context_id` | only when present | decision record (best-effort) |
| `gateway_context_id` | only when present | decision record (best-effort) |

Example valid package (synthetic):

```json
{
  "decision_id": "dec-1",
  "runtime_health_state": "HEALTHY",
  "runtime_health_profile": "BALANCED",
  "profile_reason_code": null,
  "execution_allowed": true,
  "audit_event_type": "runtime_health_profile_decision",
  "audit_hash": "<64-hex audit hash>",
  "governance_context_id": "gctx-<32-hex>",
  "proof_status": "VALID",
  "proof_reason_code": "RUNTIME_HEALTH_GOVERNANCE_PROOF_VALID",
  "proof_reason_codes": ["RUNTIME_HEALTH_GOVERNANCE_PROOF_VALID"],
  "proof_generated_at": 1,
  "previous_audit_hash": "GENESIS"
}
```

No raw payloads, signatures, secrets, or raw client identifiers appear in any
package — the whitelist guarantees it and the validator re-checks it.

## Reason codes

Distinct `RUNTIME_GOVERNANCE_PROOF_EXPORT_*` namespace (separate from the
PB-RUNTIME-007/008/009/010 namespaces):

| Constant | Code | Raised when |
|----------|------|-------------|
| `RHC_RH_EXPORT_VALID` | `…_VALID` | Reserved positive marker. |
| `RHC_RH_EXPORT_INCOMPLETE` | `…_INCOMPLETE` | A required export field is missing or null. |
| `RHC_RH_EXPORT_PROOF_NOT_VALID` | `…_PROOF_NOT_VALID` | The carried proof verdict is not `VALID` (e.g. hash / previous-hash mismatch — the specific cause is preserved in `proof_reason_codes`). |
| `RHC_RH_EXPORT_POLICY_CONTEXT_MALFORMED` | `…_POLICY_CONTEXT_MALFORMED` | `policy_context_id` malformed when present. |
| `RHC_RH_EXPORT_GATEWAY_CONTEXT_MALFORMED` | `…_GATEWAY_CONTEXT_MALFORMED` | `gateway_context_id` malformed when present. |
| `RHC_RH_EXPORT_SENSITIVE_DATA` | `…_SENSITIVE_DATA` | Raw payload / signature / secret / raw client id present in the package. |

Underlying proof failures (hash mismatch, previous-hash mismatch, etc.) surface
as `RHC_RH_EXPORT_PROOF_NOT_VALID` at the export level while the precise
`RUNTIME_HEALTH_GOVERNANCE_PROOF_*` codes remain visible in the package's
`proof_reason_codes`.

## Hash-chain status

The system-wide export report independently verifies whole-chain tamper-evidence
by recomputing each entry's `hash_current` against the **rolling** previous hash
(seeded with `GENESIS_HASH`). Any tampering — including a mutated `decision_id` —
flips the affected package's `proof_status` to `FAILED`, sets report-level
`hash_chain_valid` to `False`, and forces overall `valid` to `False`. Proven by
`test_system_wide_proof_export_detects_tamper`.

## Documented GAPs

- **Optional context ids**: `policy_context_id` and `gateway_context_id` are
  best-effort. When absent they are **omitted** from the package (never faked) and
  counted in `optional_context_unavailable`. Only malformed-when-present fails. In
  this workspace all governed records resolve all three context ids, so no hard
  GAP is observed.
- **Export is read-only / evidence-only**: intentionally **not** wired into
  `/execute`. This deliberate GAP preserves fail-closed execution (see below).

## Fail-closed evidence

- The export builders and validator are **pure**: they never raise and are never
  invoked from the request/execution path.
  `test_proof_export_is_read_only` proves that building an export does not mutate
  the audit chain, and the execution path is unchanged.
- The whitelist-only construction means a malicious or buggy record can never
  leak raw sensitive fields into an export; the validator additionally rejects any
  injected sensitive data (`test_proof_export_validation_rejects_injected_sensitive_data`).
- Execution behaviour is unchanged: the full gateway suite and the voucher /
  policy-approval regression suites all pass unmodified.

## Validation results

- `python3.11 -m py_compile gateway/app.py tests/test_gateway_app.py` — **passes**.
- `pytest -q tests/test_gateway_app.py` — **174 passed** (160 prior + 14 new).
- `pytest -q tests/test_voucher_authority.py tests/test_governance_actions_policy_approvals.py` — **74 passed**.
- `git diff --check` — **clean**.
- `git diff --cached --check` — **clean**.
- Export behaviours proven by tests: valid export passes; incomplete export fails;
  hash mismatch fails; previous-hash mismatch fails; malformed optional context
  ids fail; sensitive data rejected; unavailable optional ids documented and never
  faked; export is read-only; execution path unchanged.

## Files changed

- `gateway/app.py`
- `tests/test_gateway_app.py`
- `evidence/audit/RUNTIME_GOVERNANCE_PROOF_EXPORT_AUDIT.md`

## Rollback

```bash
git revert --no-edit HEAD
```

The change is purely additive (new constants, new functions, new tests, new
evidence doc) and is not referenced by the execution path, so reverting fully
removes the export capability with no effect on `/execute`.
