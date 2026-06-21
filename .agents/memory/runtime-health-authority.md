---
name: Runtime Health Authority enforcement constraint
description: Why the governance runtime health gate cannot be enforced inline at /execute without breaking existing deny-path tests.
---

# Runtime Health Authority (governance gateway)

A fail-closed runtime health authority lives in `gateway/app.py` near the
`/health` route: a canonical snapshot over 5 read-only subsystem probes (policy
engine, audit, runtime storage, approval, revocation) that aggregates to
HEALTHY / DEGRADED / FAILED and exposes `GET /runtime/health` (HTML panel +
audit table, or JSON; 200/503) and `GET /runtime/health/selftest`.

## Enforcement placement (RESOLVED — gate is now live)

`runtime_execution_gate()` IS now wired into `POST /execute` (fail-closed). The
single safe placement is **after `validate_execution_decision()` + `verify`, and
immediately before `route_execution()`** (the only execution sink).

**Why this exact spot:** the specific deny reasons are emitted *inside*
`validate_execution_decision` — `missing_decision_id` (early) and `replay_detected`
(`record.get("used") is True`) — which runs BEFORE the gate, so those deny tests
(`test_replay_fails`, `test_missing_decision_id_precedes_provenance`, which install a
bad runtime authority) still get their specific `403`. Do NOT wire the gate at the
TOP of `/execute`: that returns a generic `503 runtime_health_blocked` first and
breaks deny-path ordering (that earlier attempt was reverted). Placing it after
validate/verify keeps deny precedence AND guarantees nothing executes while health
is FAILED/unavailable/indeterminate.

**Block response:** `runtime_health_block_response()` → `503`,
`error="runtime_health_blocked"`, `reason_code=RHC_RUNTIME_HEALTH_EXECUTION_BLOCKED`,
decision_id when known, reason_codes, + audit event `execution_blocked_runtime_health`;
never echoes raw payload/signature. A gate/probe exception synthesizes a FAILED
snapshot and blocks (fail-closed).

**DEGRADED is intentionally warning-only (allowed)** — existing PB-RUNTIME-001 design
(`_runtime_health_decision` → `EXECUTION_ALLOWED_WITH_WARNING`), asserted by
`test_runtime_health_degraded_warns_but_allows`. Only FAILED blocks. Promoting
DEGRADED to a block is a deliberate future design change, not a bug.

**Natural test-env health = HEALTHY** (all 5 probes green under `configure_gateway`),
so allow-path `/execute` tests pass through the gate unchanged.

## Execution-path coverage (audit conclusion — now closed by PB-RUNTIME-003)

A prior execution-path coverage audit found `runtime_execution_gate()` had ZERO
production callers — observability-only, 0% coverage (GAP-1). PB-RUNTIME-003 CLOSED
this: the gate now has exactly one production caller in `/execute`, giving 100%
coverage of the single live governed execution path. Evidence:
`evidence/audit/RUNTIME_HEALTH_ENFORCEMENT_AUDIT.md`. (Historical 0%-coverage note
below kept for context.) There is exactly one governed compute path
(`POST /execute` -> `route_execution` in `security/compute_router.py` -> single
`executor.execute` sink); no alternate executor caller exists. This is a *coverage
gap*, not a classic bypass (no alternate route around an enforced gate, because the
gate is enforced nowhere). `runtime/enforcement_gateway.py` is execution-capable but
non-live (no Python importers; CLI-only via `governance_check.sh`). Evidence lives in
`evidence/audit/EXECUTION_PATH_{COVERAGE_AUDIT,GRAPH}.md` + `RUNTIME_BYPASS_MATRIX.md`.
