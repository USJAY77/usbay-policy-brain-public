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

## Enforcement constraint (the non-obvious part)

Do NOT wire `runtime_execution_gate()` inline at the top of `POST /execute`.

**Why:** the policy-engine health probe calls `policy_runtime_state(...)`, which
depends on the provenance context. Existing tests (`test_replay_fails`,
`test_missing_decision_id_precedes_provenance`) deliberately install a bad/degraded
runtime authority and require the endpoint's *specific* deny paths (e.g.
`403 replay_detected`) to take precedence. A health gate at the top returns a
generic `503 runtime_health_blocked` first, which breaks that required deny
ordering. This was attempted and reverted.

**How to apply:** keep `runtime_execution_gate()` as the canonical fail-closed
entrypoint callers invoke explicitly. Any future broadening of enforcement to
action routes must first reconcile the deny-path ordering (provenance/replay
denials must still win over a generic health block).

## Execution-path coverage (audit conclusion)

An execution-path coverage audit confirmed `runtime_execution_gate()` has ZERO
production callers — the Runtime Health Authority is observability-only and covers
0% of governed execution. There is exactly one governed compute path
(`POST /execute` -> `route_execution` in `security/compute_router.py` -> single
`executor.execute` sink); no alternate executor caller exists. This is a *coverage
gap*, not a classic bypass (no alternate route around an enforced gate, because the
gate is enforced nowhere). `runtime/enforcement_gateway.py` is execution-capable but
non-live (no Python importers; CLI-only via `governance_check.sh`). Evidence lives in
`evidence/audit/EXECUTION_PATH_{COVERAGE_AUDIT,GRAPH}.md` + `RUNTIME_BYPASS_MATRIX.md`.
