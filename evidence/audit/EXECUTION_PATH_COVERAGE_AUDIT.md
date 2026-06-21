# PB-RUNTIME-002 — Execution Path Coverage Audit

**Capability audited:** Governance Runtime Health Authority (built in PB-RUNTIME-001).
**Question:** Is every execution path covered by the Runtime Health Authority, and does any runtime bypass path exist?
**Workspace:** Replit Agent only.
**Mode:** Audit-first. Evidence is recorded BEFORE any remediation. Remediation in this document is a *proposal only* — no code was changed.

## Scope

| In scope | Notes |
|---|---|
| `gateway/app.py` | FastAPI app — all routes, execution handler, Runtime Health Authority. |
| `runtime/*` | `enforcement_gateway.py`, `policy_validator.py`, `command_model.py`, `websocket_server.py`, `__init__.py`. |
| `security/compute_router.py` | `route_execution`, `ComputeRoutingError`, executor selection. |

Out of scope for change (per task rules): simulator, travel/voucher, adapter, tenant, RFC3161, lineage. These are still *inventoried read-only* where they intersect routing.

## Method

Static evidence collected with `rg`/`sed`/`awk` and `py_compile`:
1. Enumerated every FastAPI route in `gateway/app.py`.
2. Located the definition and every caller of `route_execution`, `validate_execution_decision`, `verify`, `runtime_execution_gate`, `runtime_health_snapshot`.
3. Traced the single governed compute sink (`executor.execute`) back to its only caller.
4. Searched the whole repo for importers of every `runtime/*` module.
5. Confirmed there is no alternate executor caller (every other `.execute(` is a SQLite cursor).

## 1. Execution entrypoints (live FastAPI app)

| Entrypoint | Location | Triggers governed compute? |
|---|---|---|
| `POST /execute` → `execute()` | `gateway/app.py:14599` | **YES — the only governed compute execution entrypoint.** |
| `POST /decide` → `create_governance_decision()` | `gateway/app.py:14524` (fn `1487`) | No. Creates/validates a governance decision; calls `validate_compute_request` (`1511`) for pre-validation but never reaches an executor. |
| `PUT /simulator/state/{client_id}` | `gateway/app.py:14046` | No. Simulator KV state mutation. |
| `DELETE /simulator/state/{client_id}` | `gateway/app.py:14073` | No. Simulator KV state mutation. |
| `GET /simulator/voucher/{issue,verify,redeem,revoke}` | `14164 / 14204 / 14303 / 14410` | No. Simulator voucher lifecycle; never calls `route_execution`. |
| All other `GET` routes (`/runtime/health`, `/policy/*`, `/health`, `/api/*`, `/audit/*`, `/replay/*`, `/assets/*`) | various | No. Read-only / observability. |

## 2. Routes capable of triggering execution

Only **`POST /execute`** reaches the governed compute sink. Verified: `route_execution` is called at exactly one site (`gateway/app.py:14629`), and `executor.execute(payload)` is called at exactly one site (`security/compute_router.py:41`, inside `route_execution`). All other `.execute(` occurrences in the repo are SQLite cursor calls (`security/store.py`, `security/decision_store.py`, `simulator/storage.py`) and are not compute execution.

## 3. Internal execution helpers

| Helper | Location | Role |
|---|---|---|
| `validate_execution_decision(payload)` | `gateway/app.py:1620` | Redis/replay readiness, decision-id, signature, decision-record, actor checks. Deny → `_deny_decision_response`. |
| `verify(payload)` | `gateway/app.py:1932` | Policy + Hydra verification → `POLICY_DENIED` / `HYDRA_DENIED` / falsy → `fail_closed`. |
| `route_execution(payload, decision)` | `security/compute_router.py:24` | `validate_compute_request` → `_executor_for_target` → executor; mismatch/verification deny via `ComputeRoutingError`. |
| `_executor_for_target(target)` | `security/compute_router.py:12` | Returns `executors.cpu_executor` / `executors.npu_executor`; unknown target → `ComputeRoutingError`. |
| `mark_decision_used(...)` | `gateway/app.py` | Replay consumption (single-use). |
| `fail_closed(action)` | `gateway/app.py:358` | Fail-closed deny. |
| `_deny_decision_response(...)` | `gateway/app.py:1377` | Structured deny response. |

**Execution sink:** `executors/cpu_executor.py`, `executors/npu_executor.py` (reached only through `route_execution`).

## 4. Runtime Health Authority components

| Component | Location | Production callers |
|---|---|---|
| `runtime_health_snapshot()` | `gateway/app.py:14927` | `/runtime/health` (`15109` → `15115`) and `/runtime/health/selftest` (`15124` → `15129`) **only** — both observability endpoints. |
| `runtime_execution_gate()` | `gateway/app.py:15008` | **ZERO production callers.** Only referenced by tests (`tests/test_gateway_app.py:939, 962`). |

## 5. `runtime_execution_gate` callers

**None on any execution path.** The function exists and is unit-tested, but no route, helper, or `runtime/*` module calls it. Coverage of governed execution by the Runtime Health Authority is therefore **0%**.

## 6. Execution paths not protected by Runtime Health Authority — GOVERNANCE GAP (FAIL CLOSED)

> Recorded as a governance gap **before** any remediation proposal, per the FAIL-CLOSED rule.

- **GAP-1 (primary):** `POST /execute` — the sole governed compute execution path — does **not** invoke `runtime_execution_gate()` or `runtime_health_snapshot()` at any point. The Runtime Health Authority is **observability-only**; no admission check based on runtime health gates execution. 100% of governed executions proceed without a runtime-health admission decision.
- **GAP-2 (informational):** `runtime/enforcement_gateway.py` is an execution-capable governance surface (`_execute_automation` `:437`, `serve_attestation` `:663`, `BaseHTTPRequestHandler`/`ThreadingHTTPServer`) that also does **not** consult the Runtime Health Authority. It has **no Python importers** and is **not wired into the FastAPI app**; it is invoked only as a standalone CLI script by the offline `governance_check.sh` (lines 93/102/110/144). It is therefore not a *live* request bypass — but it is an execution-capable surface outside the gateway and is tracked here.

## 7. Bypass findings

There is **no classic bypass** (no alternate route that circumvents an otherwise-enforced gate) because the gate is enforced **nowhere**. The condition is a **coverage gap**, not a bypass:

- Exactly one governed compute path exists (`POST /execute` → `route_execution` → executor).
- No direct executor callers exist outside `route_execution`.
- The Runtime Health Authority gate sits entirely off this path.

`runtime/enforcement_gateway.py` is documented (GAP-2) as a non-live execution-capable surface (CLI-only, invoked by `governance_check.sh`; no Python importers; not in the FastAPI app) so that no execution-capable code is left undocumented.

## 8. Remediation findings — PROPOSED, NOT IMPLEMENTED

- **R1 — wire the gate into `/execute`.** Invoke `runtime_execution_gate()` in `execute()` and return a fail-closed `503` when `allowed is False`.
- **Blocking constraint (must reconcile first):** Per PB-RUNTIME-001, inline enforcement at `/execute` **breaks existing deny-path tests** (`test_replay_fails`, `test_missing_decision_id_precedes_provenance`). The policy-engine health probe overlaps provenance/replay deny ordering, so a generic health `503` preempts the specific required deny reason and ordering. Task rules **"Preserve existing tests"** and **"Preserve fail-closed"** mean R1 cannot be applied as-is.
- **R2 — reconciliation (design proposal).** Either (a) order the gate **after** decision/provenance validation but **before** `route_execution`, so specific deny reasons still take precedence, or (b) scope the gate's policy-engine probe so it does not duplicate provenance checks. Requires a deny-ordering test-design review.
- **Decision for this audit:** Because remediation is a proposal and any `/execute` change is risky w.r.t. existing tests, **no code change is made.** The gap is documented; remediation is deferred to a dedicated change with test reconciliation.

## 9. Validation results

| Check | Result |
|---|---|
| Every execution path documented | PASS (§1–§3) |
| Every execution path mapped | PASS (`EXECUTION_PATH_GRAPH.md`) |
| `runtime_execution_gate` coverage documented | PASS — 0 production callers (§5) |
| No undocumented execution path | PASS — single `route_execution` caller, single executor sink |
| No undocumented bypass path | PASS — `enforcement_gateway` documented as unwired surface (GAP-2) |
| Compile clean | PASS — `py_compile` of `gateway/app.py`, `security/compute_router.py`, `runtime/enforcement_gateway.py` OK (no code changed) |
| `git diff --check` clean | PASS — only additive audit `.md` files |

## 10. Rollback command

These deliverables are additive, untracked Markdown files. To roll back:

```bash
rm -f evidence/audit/EXECUTION_PATH_COVERAGE_AUDIT.md \
      evidence/audit/EXECUTION_PATH_GRAPH.md \
      evidence/audit/RUNTIME_BYPASS_MATRIX.md
```

No source files were modified, so no code rollback is required.
