# Runtime Health Policy Profile Audit — PB-RUNTIME-005

**Capability:** Runtime Health Policy Profiles (STRICT / BALANCED / CONTINUITY)
**Scope:** `gateway/app.py`, `tests/test_gateway_app.py`, this evidence doc.
**Status:** Implemented, validated, fail-closed preserved.

## 1. Problem

PB-RUNTIME-004 left DEGRADED execution behavior *hardcoded* (always warning-only).
Operators had no policy lever to make DEGRADED block in a high-assurance posture,
and the audit trail did not record *which policy* governed a DEGRADED decision.
PB-RUNTIME-005 makes DEGRADED handling **policy-driven and auditable** via named
Runtime Health Policy Profiles, without changing the fail-closed invariant.

## 2. Policy Profiles (canonical behavior matrix)

| Profile     | HEALTHY | DEGRADED        | FAILED | EXCEPTION/AUTHORITY-ERROR |
|-------------|---------|-----------------|--------|---------------------------|
| STRICT      | execute | **block**       | block  | block                     |
| BALANCED *  | execute | warning-only    | block  | block                     |
| CONTINUITY  | execute | warning-only    | block  | block                     |

`* BALANCED` is the default and preserves the PB-RUNTIME-004 contract.

**Fail-closed invariant (every profile):** FAILED, authority error, probe
exception, gate exception, and any unknown/unexpected state → **block**. Profiles
only govern the DEGRADED branch; they can tighten DEGRADED (STRICT) but can never
loosen FAILED.

## 3. Reason Codes

| Constant                                   | Value                              | Meaning                                  |
|--------------------------------------------|------------------------------------|------------------------------------------|
| `RHC_PROFILE_STRICT_DEGRADED_BLOCK`        | `PROFILE_STRICT_DEGRADED_BLOCK`    | STRICT blocked a DEGRADED execution      |
| `RHC_PROFILE_BALANCED_DEGRADED_WARNING`    | `PROFILE_BALANCED_DEGRADED_WARNING`| BALANCED allowed DEGRADED with a warning |
| `RHC_PROFILE_CONTINUITY_DEGRADED_WARNING`  | `PROFILE_CONTINUITY_DEGRADED_WARNING`| CONTINUITY allowed DEGRADED with a warning |

The PB-RUNTIME-004 code `RHC_RUNTIME_HEALTH_DEGRADED_WARNING` remains the stable
event-level `reason_code` of the warning audit record; the profile-specific code
is recorded alongside it as `profile_reason_code`.

## 4. Profile Selector

`runtime_health_profile()` resolves the active profile from environment variable
`USBAY_RUNTIME_HEALTH_PROFILE`:

- unset / empty / whitespace → `BALANCED` (documented default; preserves PB-RUNTIME-004)
- valid value (case-insensitive: STRICT / BALANCED / CONTINUITY) → that profile
- set-but-unrecognised value → `STRICT` (**fail-closed**: a misconfiguration can
  never silently loosen enforcement)

## 5. Enforcement Point

Profile evaluation happens **inside** `runtime_execution_gate(profile=None)`:

1. `runtime_health_snapshot()` produces the pure, canonical health snapshot
   (unchanged; still returns `reason_codes == []` when healthy).
2. The active profile is resolved (explicit arg if valid, else the selector).
3. `apply_runtime_health_profile(profile, snapshot)` returns
   `(execution_allowed, profile_reason_code)` — FAILED/unknown block in every
   profile; only DEGRADED is profile-governed.
4. The gate returns a **decorated copy** of the snapshot annotated with `profile`,
   `execution_allowed`, and (when the profile drove the DEGRADED branch)
   `profile_reason_code` (also appended to `reason_codes` as evidence).

The snapshot function stays pure; only the gate's returned copy is decorated, so
existing tests asserting snapshot purity are preserved.

**Decision consistency:** whenever the profile blocks (e.g. STRICT on DEGRADED),
the gate normalizes the decorated `decision` to `RUNTIME_EXEC_BLOCKED` so a blocked
execution can never be recorded as `EXECUTION_ALLOWED_WITH_WARNING` in the response
or audit record.

## 6. Auditability — proving which profile decided

The decided profile is persisted in the governance audit chain. The
`audit_governance_event` allowlist was extended with two **non-sensitive** keys —
`runtime_health_profile` and `profile_reason_code` — populated by both:

- `runtime_health_block_response` (STRICT/DEGRADED and all FAILED blocks): includes
  `runtime_health_profile` + `profile_reason_code` in both the 503 JSON body and
  the `execution_blocked_runtime_health` audit event.
- `runtime_health_degraded_warning_event` (BALANCED/CONTINUITY warnings): includes
  `runtime_health_profile` + `profile_reason_code` in the
  `execution_allowed_runtime_health_degraded` audit event.

No raw request payload, signature material, or actor identity is ever echoed — the
audit allowlist drops everything not explicitly enumerated, and the profile name +
profile reason code are non-sensitive policy identifiers.

## 7. Validation Results

- `python3.11 -m py_compile gateway/app.py tests/test_gateway_app.py` → OK
- `python3.11 -m pytest -q tests/test_gateway_app.py` → **82 passed** (60 prior + 22 new)
- `python3.11 -m pytest -q tests/test_voucher_authority.py tests/test_governance_actions_policy_approvals.py` → **74 passed**
- `git diff --check` / `git diff --cached --check` → clean
- Workflow `USBAY Gateway` boots; `/runtime/health` → 200

## 8. Fail-Closed Evidence

- `test_apply_profile_failed_blocks_in_every_profile` — FAILED blocks in STRICT, BALANCED, CONTINUITY.
- `test_gate_failed_blocks_in_every_profile` — gate blocks FAILED in every profile.
- `test_execute_strict_profile_still_blocks_failed` — end-to-end FAILED → 503 under STRICT.
- `test_apply_profile_unknown_state_fails_closed` — unknown state blocks in every profile.
- `test_runtime_health_profile_selector_invalid_fails_closed_to_strict` — bad config → STRICT.
- `test_execute_strict_profile_blocks_degraded` — STRICT/DEGRADED → 503 with profile reason code; no raw data.

## 9. Remaining Gaps

- BALANCED and CONTINUITY are behaviorally identical today (both warning-only), per
  the canonical spec. CONTINUITY exists as a distinct, separately-auditable named
  posture for future divergence; no behavioral difference is implied now.
- Profile is process-level (env-driven); per-tenant / per-action profile selection
  is out of scope for this capability.

## 10. Rollback

```
git checkout HEAD -- gateway/app.py tests/test_gateway_app.py
rm -f evidence/audit/RUNTIME_HEALTH_POLICY_PROFILE_AUDIT.md
```
