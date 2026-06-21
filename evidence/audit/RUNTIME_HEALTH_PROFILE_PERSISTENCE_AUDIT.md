# Runtime Health Profile Persistence Audit — PB-RUNTIME-006

**Capability:** Per-execution persistence of the Runtime Health Policy Profile decision.
**Scope:** `gateway/app.py`, `tests/test_gateway_app.py`, this evidence doc.
**Status:** Implemented, validated, fail-closed preserved.

## 1. Problem

PB-RUNTIME-005 made DEGRADED handling policy-driven via named Runtime Health Policy
Profiles (STRICT / BALANCED / CONTINUITY) and recorded the profile on the DEGRADED
warning and on the block response. Two gaps remained that prevented the profile
selection from being *provably* stable and auditable on every governed execution:

1. **HEALTHY `/execute` emitted no runtime-health audit event at all.** When the
   system was healthy, the audit trail was silent about which profile governed the
   decision — the profile could be silently changed (e.g. via the selector
   environment variable) between two HEALTHY executions with no audit evidence of
   the change.
2. **The persisted audit record did not carry `execution_allowed` or
   `runtime_health_state`.** The PB-RUNTIME-005 audit allowlist persisted
   `runtime_health_profile` and `profile_reason_code` but dropped the resolved
   `execution_allowed` flag and the health `runtime_health_state`, so a persisted
   record could not, on its own, prove what the profile *decided*.

PB-RUNTIME-006 closes both gaps without altering any execution behavior: it adds an
explicit, always-emitted profile-decision audit record and extends the persisted
allowlist so the four required fields survive into the hash-chained ledger.

## 2. Guarantee

On **every** governed `/execute` decision — HEALTHY, DEGRADED-allowed, and blocked
alike, plus the gate-exception / authority-error fail-closed path — the gateway
emits a dedicated `runtime_health_profile_decision` audit event recording which
Runtime Health Policy Profile governed the decision. The record is hash-chained and
persisted, carries the four required fields, and can never be silently omitted.

The profile selection itself is unchanged (still resolved by PB-RUNTIME-005's
`runtime_health_profile()` selector); this task only proves it is **persistent,
auditable, and never able to silently change execution behavior**.

## 3. Audit record

**Action:** `runtime_health_profile_decision`
**Event-level reason code:** `RHC_RUNTIME_HEALTH_PROFILE_DECISION` =
`"RUNTIME_HEALTH_PROFILE_DECISION"`

Persisted (allowlisted) fields:

| Field                        | Meaning                                                            |
|------------------------------|-------------------------------------------------------------------|
| `runtime_health_profile`     | The active profile (STRICT / BALANCED / CONTINUITY)               |
| `profile_reason_code`        | Profile-specific code when the profile drove the DEGRADED branch; `null` otherwise |
| `execution_allowed`          | Resolved boolean — `true` on allow, `false` on block             |
| `runtime_health_state`       | Underlying health state (HEALTHY / DEGRADED / FAILED)            |
| `runtime_health_decision`    | Normalized execution decision (e.g. BLOCKED)                      |
| `runtime_health_reason_codes`| Non-sensitive health reason codes                                |
| `decision_id`, `action`, `timestamp` | Correlation metadata                                     |

All four task-required fields — `runtime_health_profile`, `profile_reason_code`,
`execution_allowed`, `runtime_health_state` — are present on the in-memory event
**and** persisted via the `audit_governance_event` allowlist (PB-RUNTIME-006 added
`execution_allowed` and `runtime_health_state` to that allowlist; the other two
were added by PB-RUNTIME-005). The same `execution_allowed` field is now also
present on the DEGRADED warning and block audit records for completeness.

## 4. No raw / sensitive data

The event is built from an allowlist of vetted policy identifiers and flags only.
It never includes raw request payload, decision/request signatures, secrets, or
raw client/actor identifiers — `audit_governance_event` drops everything not on the
allowlist. Tests assert that neither `actor-alice` nor `decision_signature` appears
in the serialized in-memory event or in the persisted ledger entry.

## 5. Fail-safe / fail-closed

- **Evidence is fail-safe:** `runtime_health_profile_audit_event(...)` swallows any
  audit exception, so recording the profile can never raise, alter, or block the
  execution decision it is recording (it is evidence, not a gate).
- **Execution stays fail-closed:** the audit event is emitted *after* the gate has
  decided and *before* the block-return, on both the allow and block paths. It does
  not touch `gate_allowed`. FAILED, authority errors, gate/probe exceptions, and
  invalid profiles still block, exactly as in PB-RUNTIME-005. An invalid
  `USBAY_RUNTIME_HEALTH_PROFILE` value still resolves to STRICT, so a
  misconfiguration tightens (never loosens) enforcement, and that STRICT decision
  is what gets persisted.

## 6. Persistence and stability

The record is written through the existing hash-chained audit ledger
(`audit_chain.append`), so each profile decision is tamper-evident and ordered.
Across repeated `/execute` calls with an unchanged profile, exactly one
`runtime_health_profile_decision` record is persisted per execution and the
recorded profile is identical on every call — proving the selection is stable and
that no execution can omit the profile decision from the evidence.

## 7. Tests (in `tests/test_gateway_app.py`)

| Test | Proves |
|------|--------|
| `test_profile_decision_reason_code_is_stable` | Event-level reason code constant is stable |
| `test_profile_audit_event_includes_required_fields_without_raw_data` | All four required fields present; no raw payload/signature |
| `test_profile_audit_event_is_fail_safe` | Audit-backend failure never raises / alters the decision |
| `test_execute_healthy_emits_profile_decision_event` | HEALTHY `/execute` now emits the profile decision (the closed gap) |
| `test_execute_degraded_emits_profile_decision_event` | DEGRADED-allowed records profile + `execution_allowed=true` |
| `test_execute_blocked_emits_profile_decision_event` | Blocked decision still records profile + `execution_allowed=false` |
| `test_profile_decision_event_persists_in_audit_chain` | Four fields survive into the persisted ledger; no raw data |
| `test_profile_persists_across_repeated_execute` | Profile stable & one record per call across 3 executions |
| `test_execute_invalid_profile_falls_back_to_strict` | Invalid profile → STRICT (fail-closed) and is what gets recorded |
| `test_profile_decision_cannot_be_omitted_on_allow_or_block` | Record present & persisted on both allow and block paths |

## 8. Validation

- `python3.11 -m py_compile gateway/app.py tests/test_gateway_app.py` — OK
- `python3.11 -m pytest -q tests/test_gateway_app.py` — **92 passed**
- `python3.11 -m pytest -q tests/test_voucher_authority.py tests/test_governance_actions_policy_approvals.py` — **74 passed** (no regression)
- `git diff --check` / `git diff --cached --check` — clean

## 9. Scope discipline

Only `gateway/app.py`, `tests/test_gateway_app.py`, and this evidence doc were
changed. No simulator / travel / voucher / tenant / RFC3161 / Codex changes. The
fail-closed invariant is preserved; the profile selector and behavior matrix from
PB-RUNTIME-005 are unchanged.
