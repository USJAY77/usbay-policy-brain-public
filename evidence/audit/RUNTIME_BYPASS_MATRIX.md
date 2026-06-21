# PB-RUNTIME-002 — Runtime Bypass Matrix

Every execution-capable path × whether it traverses Runtime Health Authority controls
(`runtime_execution_gate()` / `runtime_health_snapshot()`).

Legend: **Covered** = path calls a Runtime Health Authority control. **Gap** = path
does not. **Live** = reachable in the running FastAPI app.

| # | Path / surface | Location | Live? | Reaches executor? | Traverses Runtime Health Authority? | Classification |
|---|---|---|---|---|---|---|
| 1 | `POST /execute` → `route_execution` → executor | `gateway/app.py:14599`; sink `security/compute_router.py:41` | Yes | **Yes** | **No** | **GAP-1 — uncovered governed execution** |
| 2 | `POST /decide` → `create_governance_decision` | `gateway/app.py:14524` (fn `1487`) | Yes | No | No | Not execution (decision creation); n/a |
| 3 | `GET /simulator/voucher/{issue,verify,redeem,revoke}` | `14164/14204/14303/14410` | Yes | No | No | Not governed compute; out-of-scope to change |
| 4 | `PUT`/`DELETE /simulator/state/{client_id}` | `14046/14073` | Yes | No | No | Simulator KV state; not execution |
| 5 | `GET /runtime/health`, `/runtime/health/selftest` | `15109/15124` | Yes | No | Calls snapshot (observability only) | Observability; not an execution gate |
| 6 | `runtime_execution_gate()` | `gateway/app.py:15008` | Yes (defined) | No | Is the control itself | **0 production callers** |
| 7 | `runtime/enforcement_gateway.py` (`_execute_automation`, `serve_attestation`) | `runtime/enforcement_gateway.py:437/663` | **No** (no Python importers; not in FastAPI app; CLI-only via `governance_check.sh`) | Automation execution | No | **GAP-2 — non-live execution-capable surface** |
| 8 | Direct executor call outside `route_execution` | — | — | — | — | **None found** (every other `.execute(` is SQLite) |

## Findings

- **One** live governed compute execution path exists (row 1). It does **not** traverse the Runtime Health Authority → **GAP-1**. Coverage of governed execution = **0%**.
- **No classic bypass** exists: the gate is enforced on no path, so there is no alternate route circumventing an otherwise-enforced control. The condition is a coverage gap, not a bypass.
- **No hidden execution sink**: `route_execution` has a single caller (`gateway/app.py:14629`) and `executor.execute` a single caller (`security/compute_router.py:41`). All other `.execute(` calls in the repo are SQLite cursors.
- **GAP-2**: `runtime/enforcement_gateway.py` is execution-capable but not in the live app (no Python importers; not wired into FastAPI; invoked only as a CLI script by `governance_check.sh`). Not a live request bypass; tracked so no execution-capable surface is left undocumented.

## Remediation (proposed, not implemented)

Wiring `runtime_execution_gate()` into `POST /execute` is blocked by an existing-test
conflict (policy-engine health probe overlaps provenance/replay deny ordering; breaks
`test_replay_fails` and `test_missing_decision_id_precedes_provenance`). See
`EXECUTION_PATH_COVERAGE_AUDIT.md` §8 for proposals R1/R2. Per task rules ("preserve
existing tests", "audit evidence before remediation"), **no code change was made.**
