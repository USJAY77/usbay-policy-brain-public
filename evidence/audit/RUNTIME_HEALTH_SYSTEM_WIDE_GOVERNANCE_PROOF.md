# Runtime Health System-Wide Governance Proof (PB-RUNTIME-010)

## Purpose

This is the runtime-side **capstone** governance proof. It demonstrates that every
governed `/execute` decision persisted by the USBAY gateway is traceable
end-to-end across **all six** runtime governance capabilities, with a
tamper-evident hash chain and no raw sensitive data — **without weakening the
execution path**.

It ties together the capabilities delivered by the prior runtime work:

| # | Capability | Source | What the proof asserts |
|---|------------|--------|------------------------|
| 1 | Runtime Health Authority | PB-RUNTIME (authority/profiles core) | `runtime_health_state` is a known canonical state (`HEALTHY` / `DEGRADED` / `FAILED`). |
| 2 | Runtime Health Profiles | PB-RUNTIME (profiles) | `runtime_health_profile` is a known profile (`STRICT` / `BALANCED` / `CONTINUITY`). |
| 3 | Runtime Health Profile Persistence | PB-RUNTIME-006 | The profile decision is actually persisted as a `runtime_health_profile_decision` audit entry carrying an audit hash. |
| 4 | Runtime Evidence Integrity | PB-RUNTIME-007 | The decision record is structurally complete, consistent, and sensitive-data-free. |
| 5 | Runtime Cross-Layer Linkage | PB-RUNTIME-008 | The record is bound to its governance context (and best-effort policy/gateway context when present). |
| 6 | Runtime Cross-Layer Reconciliation | PB-RUNTIME-009 | State / profile / reason / outcome stay synchronized and the hash chain reconciles over time. |

This proof is **evidence-only**. It is **not** wired into `/execute`, does not
alter live execution behaviour, and does not change simulator, voucher, travel,
tenant, RFC3161, or Codex flows.

## Scope of change

- `gateway/app.py` — proof reason codes, the deterministic proof validators, and
  the system-wide proof report builder (additive; no existing logic changed).
- `tests/test_gateway_app.py` — 16 proof tests (record, envelope, and
  system-wide report including tamper detection and evidence-only invariants).
- `evidence/audit/RUNTIME_HEALTH_SYSTEM_WIDE_GOVERNANCE_PROOF.md` — this document.

No other files were modified.

## Governance proof model

The proof has three deterministic, pure, fail-closed, never-raising surfaces:

### 1. `validate_runtime_health_governance_proof_record(record) -> (ok, [codes])`

The record-level half of the proof. It proves a runtime-health decision record
is:

- **Complete** — every required field present and non-null
  (`decision_id`, `runtime_health_state`, `runtime_health_profile`,
  `profile_reason_code` *key present* — legitimately `None` for `HEALTHY`,
  `execution_allowed`, `audit_event_type`).
- **Governance-bound** — `governance_context_id` exists and recomputes from
  `decision_id` (`derive_governance_context_id`).
- **Internally consistent** — state ↔ outcome and profile ↔ reason agree (reusing
  the exact PB-RUNTIME-009 helpers, so proof and reconciliation can never diverge
  in logic).
- **Well-formed on optional context** — `policy_context_id` / `gateway_context_id`
  are validated **only when present** (prefix + 32 hex). Absent optional ids are a
  documented GAP, never a failure, and are **never invented**.
- **Sensitive-data-free** — no raw payloads, signatures, secrets, or raw client
  identifiers.

### 2. `validate_runtime_health_governance_proof_entry(entry, *, prev_hash=None) -> (ok, [codes])`

The envelope-level proof. On top of the record proof it adds the **audit-hash
proof**:

- `audit_hash` (`hash_current`) **must exist** — proving the record was persisted
  in the tamper-evident chain (Profile Persistence).
- The hash **must deterministically recompute** — which also proves `decision_id`
  and the record body are unchanged.
- The **previous-hash linkage** must hold when a prior hash is supplied.

### 3. `build_runtime_health_governance_proof(chain=None) -> report`

The **system-wide** report. It walks the persisted audit chain and, for every
`runtime_health_profile_decision` entry, scores each of the six capabilities and
applies the unified per-entry proof, while independently verifying whole-chain
tamper-evidence by pinning each entry against the **rolling** previous hash
(starting from `GENESIS_HASH`). It surfaces best-effort policy/gateway context
availability and a documented-unavailable count.

Report shape:

```json
{
  "proof_supported": true,
  "hash_chain_supported": true,
  "checked": <int>,
  "proven": <int>,
  "valid": <bool>,
  "hash_chain_valid": <bool>,
  "policy_context_available": <int>,
  "gateway_context_available": <int>,
  "optional_context_unavailable": <int>,
  "capabilities_proven": <bool>,
  "capabilities": {
    "runtime_health_authority": {"checked": N, "passed": M, "proven": bool},
    "runtime_health_profiles": {"checked": N, "passed": M, "proven": bool},
    "runtime_health_profile_persistence": {"checked": N, "passed": M, "proven": bool},
    "runtime_evidence_integrity": {"checked": N, "passed": M, "proven": bool},
    "runtime_cross_layer_linkage": {"checked": N, "passed": M, "proven": bool},
    "runtime_cross_layer_reconciliation": {"checked": N, "passed": M, "proven": bool}
  },
  "failures": [{"index": int, "decision_id": str, "reason_codes": [str]}]
}
```

Overall `valid` is `True` only when **all** of: every checked entry passes the
unified proof, the whole hash chain reconciles, and every capability is proven.
An empty chain is vacuously valid (nothing governed yet, nothing to prove).

## Reason codes

Distinct `RUNTIME_HEALTH_GOVERNANCE_PROOF_*` namespace (separate from the
PB-RUNTIME-007 evidence, 008 linkage, and 009 reconciliation namespaces):

| Constant | Code | Raised when |
|----------|------|-------------|
| `RHC_RH_PROOF_VALID` | `…_VALID` | Reserved positive marker. |
| `RHC_RH_PROOF_INCOMPLETE` | `…_INCOMPLETE` | A required runtime-health field is missing or null. |
| `RHC_RH_PROOF_MISSING_GOVERNANCE_CONTEXT` | `…_MISSING_GOVERNANCE_CONTEXT` | `governance_context_id` absent. |
| `RHC_RH_PROOF_DECISION_ID_MISMATCH` | `…_DECISION_ID_MISMATCH` | Governance context does not recompute from `decision_id`. |
| `RHC_RH_PROOF_MISSING_AUDIT_HASH` | `…_MISSING_AUDIT_HASH` | Envelope carries no `audit_hash` (not persisted). |
| `RHC_RH_PROOF_AUDIT_HASH_MISMATCH` | `…_AUDIT_HASH_MISMATCH` | `audit_hash` present but does not recompute. |
| `RHC_RH_PROOF_PREVIOUS_HASH_MISMATCH` | `…_PREVIOUS_HASH_MISMATCH` | Previous-hash linkage broken. |
| `RHC_RH_PROOF_CONSISTENCY_CONFLICT` | `…_CONSISTENCY_CONFLICT` | State/profile/reason/outcome conflict. |
| `RHC_RH_PROOF_POLICY_CONTEXT_MALFORMED` | `…_POLICY_CONTEXT_MALFORMED` | `policy_context_id` malformed when present. |
| `RHC_RH_PROOF_GATEWAY_CONTEXT_MALFORMED` | `…_GATEWAY_CONTEXT_MALFORMED` | `gateway_context_id` malformed when present. |
| `RHC_RH_PROOF_SENSITIVE_DATA` | `…_SENSITIVE_DATA` | Raw payload / signature / secret / raw client id present. |

## Hash-chain status

The system-wide report independently verifies whole-chain tamper-evidence by
recomputing each entry's `hash_current` against the **rolling** previous hash
(seeded with `GENESIS_HASH`). Any tampering — including a mutated `decision_id` —
flips both the per-entry `AUDIT_HASH_MISMATCH` proof code and the report-level
`hash_chain_valid` to `False`, and forces overall `valid` to `False`. This is
proven by `test_system_wide_proof_detects_tampered_decision_id`.

## Documented GAPs

- **Optional context ids**: `policy_context_id` and `gateway_context_id` are
  best-effort. When absent they are reported via `optional_context_unavailable`
  and the availability counters — they are a **documented GAP**, never a failure,
  and are **never fabricated**. Only malformed-when-present fails. In this
  workspace all governed records resolve all three context ids, so no hard GAP is
  observed.
- **Proof is evidence-only**: it is intentionally **not** wired into `/execute`.
  This is a deliberate GAP that preserves fail-closed execution (see below).

## Fail-closed evidence

- The proof validators and report builder are **pure auditors**: they never raise
  and are never invoked from the request/execution path.
  `test_governance_proof_evidence_only_does_not_touch_execution` proves that
  running the report does not mutate the audit chain or change any `/execute`
  outcome.
- Execution behaviour is unchanged: the full gateway suite (including every
  existing `/execute`, runtime-health, and fail-closed test) and the voucher /
  policy-approval regression suites all pass unmodified.
- The proof itself is fail-closed: any missing/malformed/inconsistent/tampered
  input yields a deterministic failure code, never a silent pass.

## Validation results

- `python3.11 -m py_compile gateway/app.py tests/test_gateway_app.py` — **passes**.
- `pytest -q tests/test_gateway_app.py` — **159 passed** (143 prior + 16 new).
- `pytest -q tests/test_voucher_authority.py tests/test_governance_actions_policy_approvals.py` — **74 passed**.
- `git diff --check` — **clean**.
- `git diff --cached --check` — **clean**.
- Proof behaviours proven by tests: valid proof passes; incomplete fails; audit
  hash mismatch fails; previous-hash mismatch fails; governance/context mismatch
  fails; sensitive data rejected; optional-absent passes; tamper detected
  system-wide; execution path unchanged.

## Files changed

- `gateway/app.py`
- `tests/test_gateway_app.py`
- `evidence/audit/RUNTIME_HEALTH_SYSTEM_WIDE_GOVERNANCE_PROOF.md`

## Rollback

```bash
git revert --no-edit HEAD
```

The change is purely additive (new constants, new functions, new tests, new
evidence doc) and is not referenced by the execution path, so reverting fully
removes the proof capability with no effect on `/execute`.
