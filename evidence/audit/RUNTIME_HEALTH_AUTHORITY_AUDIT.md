# Governance Runtime Health Authority — Audit Evidence (PB-RUNTIME-001)

**Scope:** `gateway/app.py` only (Replit workspace). Additive, fail-closed,
read-only. No adapter / lineage / tenant / RFC3161 / inventory /
GitHub-governance changes.

**Date:** 2026-06-21

## 1. What was added

A single canonical runtime health authority that validates the five core
governance subsystems and decides whether execution paths may proceed *before*
a user action is processed.

| State | Decision | Execution |
|-------|----------|-----------|
| `HEALTHY` | `EXECUTION_ALLOWED` | allowed |
| `DEGRADED` | `EXECUTION_ALLOWED_WITH_WARNING` | allowed (warning) |
| `FAILED` | `EXECUTION_BLOCKED` | blocked |

The authority itself fails closed: any unexpected error in a probe or in the
aggregator collapses to `FAILED` so a degraded gateway can never present itself
as healthy.

### Components (all in `gateway/app.py`)

- Canonical health model: `RUNTIME_HEALTH_SCHEMA` (`usbay.runtime_health.v1`),
  states `HEALTHY` / `DEGRADED` / `FAILED`, execution decisions
  `EXECUTION_ALLOWED` / `EXECUTION_ALLOWED_WITH_WARNING` / `EXECUTION_BLOCKED`.
- 11 stable reason codes (`RHC_*`).
- 5 read-only subsystem probes:
  1. **policy_engine** — `policy_runtime_state(...)` must load a signed registry
     in `NORMAL` mode.
  2. **audit_subsystem** — `audit_chain.load()` readable; `audit_chain.verify()`
     integrity (verify failure ⇒ DEGRADED).
  3. **runtime_storage** — `_sim_storage().health()` `available` / `writable`.
  4. **approval_subsystem** — `make_approval_evidence` → `verify_approval_evidence`
     round-trip on a sentinel payload (no persistence, no mutation).
  5. **revocation_subsystem** — `_sim_revocation_registry().is_revoked(sentinel)`
     reachability lookup.
- Aggregator `runtime_health_snapshot()` (fail-closed) + `runtime_execution_gate()`
  — the canonical fail-closed entrypoint a caller invokes before an action.
- HTML evidence panel + audit table renderer `_runtime_health_html()`.
- Endpoints:
  - `GET /runtime/health` — HTML panel (browser) or JSON snapshot (machine);
    `200` when execution allowed, `503` when blocked.
  - `GET /runtime/health/selftest` — exercises every probe and confirms the
    authority produced a coherent decision; `200` pass / `503` fail.

## 2. Live evidence (running workspace gateway)

`GET /runtime/health` (JSON):

```
state=HEALTHY  decision=EXECUTION_ALLOWED  execution_allowed=true  reason_codes=[]
policy_engine        HEALTHY  policy registry loaded and signature valid
audit_subsystem      HEALTHY  audit chain readable and verified
runtime_storage      HEALTHY  storage backend local available and writable
approval_subsystem   HEALTHY  approval sign/verify round-trip ok
revocation_subsystem HEALTHY  revocation registry reachable
```

`GET /runtime/health/selftest`: **HTTP 200** — `selftest_passed=true`,
`state=HEALTHY`, `decision=EXECUTION_ALLOWED`, `execution_allowed=true`.

`GET /runtime/health` with `Accept: text/html`: renders the evidence panel
("Runtime health evidence") and the audit table ("Runtime health audit table").

## 3. Fail-closed evidence (unit tests)

`tests/test_gateway_app.py` (runtime-health cases) — **11 passed**:

- all subsystems healthy ⇒ `HEALTHY` / `EXECUTION_ALLOWED` / allowed.
- one subsystem degraded ⇒ `DEGRADED` / `EXECUTION_ALLOWED_WITH_WARNING` /
  allowed, reason code surfaced.
- one subsystem failed ⇒ `FAILED` / `EXECUTION_BLOCKED` / **blocked**.
- failed dominates degraded ⇒ `FAILED` / blocked.
- a probe that raises ⇒ authority fails closed (`FAILED`, blocked,
  `RUNTIME_HEALTH_AUTHORITY_ERROR`).
- an internal aggregator error ⇒ authority fails closed (`FAILED`, blocked).
- endpoint `200` when healthy, `503` when failed.
- HTML panel + audit table render.
- self-test returns `200` on pass, `503` when the authority errors.

## 4. Regression evidence

- `python3.11 -m py_compile gateway/app.py` ⇒ OK.
- `pytest tests/test_gateway_app.py` ⇒ **48 passed** (existing + new).
- `pytest tests/test_voucher_authority.py tests/test_travel_voucher.py
  tests/test_simulator_storage.py` ⇒ **90 passed** (approval / voucher /
  revocation / storage flows unchanged).
- `git diff --check` ⇒ clean (no whitespace errors).

## 5. Remaining gaps / notes

- **Inline enforcement on action endpoints is intentionally deferred.** Wiring
  `runtime_execution_gate()` at the top of `POST /execute` was attempted and
  reverted: it conflicts with the existing test contract. Tests such as
  `test_replay_fails` and `test_missing_decision_id_precedes_provenance`
  deliberately install a degraded/bad runtime authority and require the
  endpoint's *specific* deny paths (e.g. `403 replay_detected`) to take
  precedence. The policy-engine health probe overlaps with those
  provenance/policy checks, so a generic health `503` at the top of the handler
  breaks the required deny ordering. Per the task RULES ("preserve existing
  tests", "preserve fail-closed"), the existing deny semantics win.
  `runtime_execution_gate()` is therefore provided as the canonical fail-closed
  entrypoint for callers to invoke explicitly; broadening enforcement to action
  routes is a follow-up that must first reconcile the deny-path ordering.
- Probes are reachability/self-test oriented and read-only by design; deeper
  per-subsystem assertions (e.g. quorum freshness) are out of scope.
