# Runtime Health DEGRADED Policy Audit (PB-RUNTIME-004)

## Objective

Close the remaining policy ambiguity left by PB-RUNTIME-003: DEGRADED runtime
health was *warning-only* but proceeded through `POST /execute` **silently**, with
no explicit, machine-readable audit record. PB-RUNTIME-004 decides, documents, and
enforces the canonical behavior for DEGRADED.

## Decision

**Option B — DEGRADED remains warning-only, now with explicit audited policy
justification.** Execution is allowed under DEGRADED, but every DEGRADED execution
now emits a dedicated, fail-safe audit event carrying the stable reason code
`RHC_RUNTIME_HEALTH_DEGRADED_WARNING`.

### Why Option B (not Option A / fail-closed)

The task mandates Option A (DEGRADED blocks fail-closed) **unless existing tests or
the product contract prove DEGRADED must remain warning-only**. They do:

| Proof | Location | Asserts |
|-------|----------|---------|
| `test_runtime_health_degraded_warns_but_allows` | `tests/test_gateway_app.py` | DEGRADED → `decision == EXECUTION_ALLOWED_WITH_WARNING`, `execution_allowed is True` |
| `test_degraded_runtime_health_still_allows_execute` | `tests/test_gateway_app.py` | end-to-end `/execute` under DEGRADED → `200` `EXECUTED` |
| PB-RUNTIME-001 contract | `gateway/app.py` `_runtime_health_decision` | DEGRADED maps to `RUNTIME_EXEC_WARNING`, not `RUNTIME_EXEC_BLOCKED` |

Promoting DEGRADED to fail-closed would break both tests and violate the task rules
"Preserve existing fail-closed behavior" and the PB-RUNTIME-003 lineage rule to
preserve existing tests. Functionally, DEGRADED denotes a subsystem that is still
serving correctly but carries a *non-fatal* integrity/reachability signal (e.g.
audit hash-chain re-verification deferred, runtime storage read-only, policy engine
loadable but in a non-NORMAL mode). Blocking every governed execution on such a
signal converts a soft observability warning into a hard outage and incentivises
operators to silence probes — the opposite of the safety goal. Only **FAILED**
(subsystem unavailable / authority error / probe exception) blocks.

The genuine gap was not the *allow* decision; it was that DEGRADED proceeded with
**no explicit audit trail**. Option B closes exactly that gap.

## Files changed

| File | Change |
|------|--------|
| `gateway/app.py` | Added reason code `RHC_RUNTIME_HEALTH_DEGRADED_WARNING`; added `runtime_health_degraded_warning_event()` (fail-safe, non-blocking audit emitter); wired it into `POST /execute` after the gate allow and before `route_execution()`, guarded on `state == DEGRADED`; expanded the Runtime Health Authority header comment with the canonical DEGRADED policy rationale. |
| `tests/test_gateway_app.py` | Added 5 PB-RUNTIME-004 tests (reason-code stability, warning-event content + no-raw-data, audit-failure-never-blocks, end-to-end DEGRADED emits warning + still executes, HEALTHY emits no warning). |
| `evidence/audit/RUNTIME_HEALTH_DEGRADED_POLICY_AUDIT.md` | This document. |

## Behavior matrix (after PB-RUNTIME-004)

| Runtime health state | `/execute` outcome | Audit event | Reason code |
|----------------------|--------------------|-------------|-------------|
| HEALTHY | executes (200) | none (no degraded warning) | — |
| DEGRADED | executes (200) | `execution_allowed_runtime_health_degraded` | `RHC_RUNTIME_HEALTH_DEGRADED_WARNING` |
| FAILED | blocked (503) | `execution_blocked_runtime_health` | `RHC_RUNTIME_HEALTH_EXECUTION_BLOCKED` |
| probe exception | blocked (503) | `execution_blocked_runtime_health` | `RHC_RUNTIME_HEALTH_EXECUTION_BLOCKED` (+ `RHC_RUNTIME_HEALTH_AUTHORITY_ERROR`) |
| gate exception | blocked (503) | `execution_blocked_runtime_health` | `RHC_RUNTIME_HEALTH_EXECUTION_BLOCKED` |

## Fail-closed / fail-safe evidence

- **FAILED still blocks** — unchanged from PB-RUNTIME-003; `runtime_execution_gate()`
  returns falsy → `runtime_health_block_response()` (503). Verified by
  `test_execute_blocked_when_runtime_health_failed`,
  `test_no_execute_bypass_remains_when_health_failed`.
- **Exceptions still block** — probe raise and gate raise both fail closed to 503.
  Verified by `test_execute_blocked_when_health_probe_raises`,
  `test_execute_gate_exception_fails_closed`.
- **`/execute` still traverses the gate** — verified by
  `test_execute_invokes_runtime_execution_gate`.
- **DEGRADED warning is fail-SAFE (never blocks)** — `runtime_health_degraded_warning_event`
  swallows audit exceptions so a logging failure cannot downgrade a warning-only
  (allowed) path into a block. Verified by
  `test_degraded_warning_event_never_blocks_on_audit_failure`.
- **No raw sensitive data in audit logs** — the warning event is written through
  `audit_governance_event`, whose fixed allowlist schema drops everything except
  approved fields; the function never passes raw payload or signature material.
  Verified by `test_degraded_warning_event_emits_reason_code_without_raw_data`
  (asserts no `decision_signature` / `actor-alice` in the serialized event).

## Audit reason codes

- `RHC_RUNTIME_HEALTH_DEGRADED_WARNING = "RUNTIME_HEALTH_DEGRADED_WARNING"` — new;
  attached to the explicit warning record for DEGRADED-but-allowed executions.
- `RHC_RUNTIME_HEALTH_EXECUTION_BLOCKED` — unchanged (FAILED / exception blocks).

### Persistence note

`audit_governance_event` sanitizes through a fixed allowlist, so the persisted
chain entry retains `reason_code` (= `RHC_RUNTIME_HEALTH_DEGRADED_WARNING`),
`decision_id`, and `timestamp`; the richer `runtime_health_*` evidence fields are
passed but intentionally dropped at persistence — identical to PB-RUNTIME-003's
block event. This is a deliberate data-minimisation property (it is also what
prevents raw payload/signature leakage). The persisted reason code is sufficient to
make every DEGRADED execution explicitly attributable. Extending the allowlist to
persist vetted runtime-health evidence fields is a possible future enhancement, not
required for this policy decision.

## Validation

- `python3.11 -m py_compile gateway/app.py tests/test_gateway_app.py` — PASS.
- `pytest -q tests/test_gateway_app.py` — 60 passed.
- `pytest -q tests/test_voucher_authority.py tests/test_governance_actions_policy_approvals.py` — PASS.
- `git diff --check` / `git diff --cached --check` — clean.

## Remaining gaps

- DEGRADED remains allowed by design. If product later decides DEGRADED must block,
  that is a deliberate contract change: flip the decision in `_runtime_health_decision`
  (or gate on DEGRADED in `/execute`), introduce a `*_DEGRADED_BLOCKED` reason code,
  and update the two warning-only contract tests. Not in scope here.
- Warning-event coverage is scoped to the single live governed execution path
  (`POST /execute`), consistent with PB-RUNTIME-003. No other execution sink exists.

## Rollback

```
git checkout HEAD -- gateway/app.py tests/test_gateway_app.py
rm -f evidence/audit/RUNTIME_HEALTH_DEGRADED_POLICY_AUDIT.md
```
