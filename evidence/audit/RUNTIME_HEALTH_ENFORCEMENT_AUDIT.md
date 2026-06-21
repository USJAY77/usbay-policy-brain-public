# Runtime Health Enforcement Audit (PB-RUNTIME-003)

Closes **PB-RUNTIME-002 GAP-1**: the Runtime Health Authority was observability-only
(`runtime_execution_gate()` had zero production callers, 0% coverage of live execution
paths). This change wires the gate into the single live `/execute` path so it becomes an
enforceable, fail-closed control.

Scope is one governance capability. No codex/lineage/tenant/RFC3161/inventory/travel/
voucher behavior was changed. Existing tests and fail-closed semantics are preserved.

---

## 1. Files changed

| File | Change |
| --- | --- |
| `gateway/app.py` | Added `RHC_RUNTIME_HEALTH_EXECUTION_BLOCKED` reason code; added `runtime_health_block_response(...)` (fail-closed 503 builder + audit emission); wired `runtime_execution_gate()` into the live `/execute` handler. |
| `tests/test_gateway_app.py` | Added 8 enforcement tests (gate invocation, FAILED block, probe-exception block, gate-exception fail-closed, evidence content, DEGRADED warning-only allow, no-bypass). |
| `evidence/audit/RUNTIME_HEALTH_ENFORCEMENT_AUDIT.md` | This audit (new). |

Net diff: 2 source files, +178 lines, 0 deletions. No unrelated dirty files touched.

---

## 2. Canonical gate

- **Function:** `runtime_execution_gate()` — `gateway/app.py` (def at the Runtime Health
  Authority block). Returns `(execution_allowed: bool, snapshot: dict)`.
- **Source of truth:** `runtime_health_snapshot()` — probes all 5 subsystems
  (`policy_engine`, `audit_subsystem`, `runtime_storage`, `approval_subsystem`,
  `revocation_subsystem`) and collapses to `HEALTHY` / `DEGRADED` / `FAILED`.
- **Decision mapping** (`_runtime_health_decision`, unchanged):
  - `HEALTHY` → `EXECUTION_ALLOWED` → allowed
  - `DEGRADED` → `EXECUTION_ALLOWED_WITH_WARNING` → allowed (warning-only)
  - `FAILED` → `EXECUTION_BLOCKED` → blocked
  - Any authority/probe exception → collapses to `FAILED` → blocked (fail-closed).

---

## 3. Every caller of `runtime_execution_gate()`

| Location | Type | Purpose |
| --- | --- | --- |
| `gateway/app.py` — live `POST /execute` handler | **Production** (NEW) | Hard gate before compute routing. |
| `tests/test_gateway_app.py::test_runtime_health_all_healthy_allows_execution` | Test | Direct allow assertion. |
| `tests/test_gateway_app.py::test_runtime_health_failed_blocks_execution` | Test | Direct block assertion. |
| `tests/test_gateway_app.py` (PB-RUNTIME-003 suite) | Test | End-to-end `/execute` enforcement. |

Before this change there were **zero** production callers.

---

## 4. Gate placement and ordering (why it is safe)

The gate is placed inside `/execute` **after** `validate_execution_decision()` and the
`verify` step, and **before** `route_execution()` (the single execution sink).

```
POST /execute
  -> validate_execution_decision()   # missing_decision_id, unknown_decision,
  |                                  # invalid_signature, replay_detected (record.used),
  |                                  # decision_*_mismatch, redis/dependency failures
  -> verify (...)                    # HYDRA_DENIED / POLICY_DENIED / fail_closed
  -> [ runtime_execution_gate() ]    # <-- NEW gate (fail-closed)
  -> route_execution()               # single execution sink (security/compute_router.py)
  -> mark_decision_used() -> audit -> {"status": "EXECUTED"}
```

This ordering is deliberate:

- **All specific deny paths still win.** Replay is caught inside
  `validate_execution_decision` (`record.get("used") is True -> "replay_detected"`) and
  `missing_decision_id` is caught at the top of the same function — both return *before*
  the gate runs. PB-RUNTIME-001's earlier attempt failed only because it placed the gate
  at the very top, pre-empting these reason codes; placing it after validation/verify
  resolves that while still guaranteeing nothing executes without passing the gate.
- **No execution can bypass the gate.** `route_execution()` is the only execution sink
  (confirmed in PB-RUNTIME-002 `RUNTIME_BYPASS_MATRIX.md`), and the gate is the
  immediately-preceding statement on the only path that reaches it.

---

## 5. Fail-closed behavior

| Runtime health condition | Gate result | `/execute` response |
| --- | --- | --- |
| HEALTHY | allowed | proceeds to `route_execution` → `EXECUTED` (200) |
| DEGRADED | allowed (warning) | proceeds → `EXECUTED` (200) — see §6 |
| FAILED (any subsystem) | blocked | `503 runtime_health_blocked` |
| Health authority/probe raises | FAILED → blocked | `503 runtime_health_blocked` |
| `runtime_execution_gate()` itself raises | blocked (synthetic FAILED snapshot) | `503 runtime_health_blocked` |

Blocked responses (`runtime_health_block_response`) carry, with **no raw request/signature
data**:

- `error: "runtime_health_blocked"`
- `reason_code: RUNTIME_HEALTH_EXECUTION_BLOCKED`
- `execution_allowed: false`
- `runtime_health_state`, `runtime_health_decision`, `reason_codes[]`
- `decision_id` when available
- An audit event `execution_blocked_runtime_health` (reason code, decision_id, action,
  state/decision, reason codes, and the health audit trail). An audit failure cannot
  downgrade a block to an allow.

---

## 6. DEGRADED decision (documented, intentional)

`DEGRADED` is **warning-only (execution allowed)**. This is the existing PB-RUNTIME-001
design (`_runtime_health_decision` → `EXECUTION_ALLOWED_WITH_WARNING`) and is asserted by
the existing test `test_runtime_health_degraded_warns_but_allows`. PB-RUNTIME-003 RULES
require preserving existing tests and behavior, so DEGRADED is left as warning-only rather
than promoted to a block. Only `FAILED` / unavailable / indeterminate states block.

---

## 7. Coverage: before / after

| Metric | Before (PB-RUNTIME-002) | After (PB-RUNTIME-003) |
| --- | --- | --- |
| Live `/execute` paths | 1 | 1 |
| Live `/execute` paths traversing `runtime_execution_gate` | 0 | 1 |
| **Runtime Health Authority coverage of live execution** | **0%** | **100%** |
| Production callers of `runtime_execution_gate` | 0 | 1 |

---

## 8. Validation results

| Check | Result |
| --- | --- |
| `py_compile gateway/app.py tests/test_gateway_app.py` | PASS |
| `pytest tests/test_gateway_app.py` | PASS — 55 passed (47 prior + 8 new) |
| `pytest tests/test_voucher_authority.py tests/test_travel_voucher.py` | PASS — 77 passed (approval suites preserved) |
| Existing deny-path tests (replay / missing_decision_id / provenance / policy) | PASS (reason codes unchanged) |
| Existing runtime-health tests | PASS |
| `git diff --check` / `git diff --cached --check` | PASS (no whitespace errors) |
| Natural test-env health snapshot | HEALTHY (all 5 probes green) — allow-path unaffected |

---

## 9. Remaining gaps

- **GAP-2 (carried from PB-RUNTIME-002):** `runtime/enforcement_gateway.py` remains
  execution-capable but non-live (no Python importers; CLI-only via `governance_check.sh`).
  Out of scope here; no live path reaches it.
- **DEGRADED tri-state policy:** if governance later wants DEGRADED to block, that is a
  deliberate design change to `_runtime_health_decision` plus its test — explicitly **not**
  done here to preserve existing behavior.

---

## 10. Rollback

```bash
git checkout HEAD -- gateway/app.py tests/test_gateway_app.py
rm -f evidence/audit/RUNTIME_HEALTH_ENFORCEMENT_AUDIT.md
```

This restores the observability-only state (gate present but with zero production callers).
