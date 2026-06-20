# EXECUTION_SURFACE_MAP — Canonical Execution Surface Inventory

PB-INVENTORY-001 — single source of truth for every USBAY execution surface.

- actor: replit-agent
- action: consolidate canonical execution surface inventory
- scope: gateway/app.py, runtime/enforcement_gateway.py, security/compute_router.py,
  security/execution_guard.py, executors/*, plus test-only helpers
- method: static enumeration of every code path that can cause a command, compute
  request, or automation action to actually run, cross-checked against caller graphs
  (see EXECUTION_CALL_GRAPH.md) and the governance gate proof (see CANONICAL_GATE_AUDIT.md).

This document maps each execution entrypoint to the governance gate it MUST traverse
and the owner module accountable for that surface. "Canonical execution governance
gate" is the conceptual name used by PB-INVENTORY-001 deliverable #4; in this codebase
it is implemented as the composite `/decide` + `/execute` gate (no single function of
that literal name exists — see CANONICAL_GATE_AUDIT.md §1).

## Surface inventory

| # | Execution surface | Entrypoint (file:symbol) | Owner module | Required governance gate | Status |
|---|-------------------|--------------------------|--------------|--------------------------|--------|
| 1 | Runtime HTTP execution | `gateway/app.py` `@app.post("/execute")` → `execute()` (line 14445) | `gateway/app.py` | Full canonical gate: `validate_execution_decision` → `verify` → `route_execution` → `mark_decision_used` | GOVERNED |
| 2 | Decision issuance (execution authority) | `gateway/app.py` `@app.post("/decide")` → `decide()` (line 14370) → `create_governance_decision` (line 1487) | `gateway/app.py` | `create_governance_decision`: fail-closed deps, metadata, signature, `validate_compute_request`, nonce reservation, hydra consensus, `execution_command_allowed` allowlist; mints signed single-use decision record | GOVERNED (issuer) |
| 3 | Compute dispatch | `security/compute_router.py` `route_execution()` (line 24) | `security/compute_router.py` | `validate_compute_request` (re-validation) + requested/stored target binding + executor result verification; only reachable from surface #1 | GOVERNED |
| 4 | Executor invocation | `security/compute_router.py` `executor.execute(payload)` (line 41) via `_executor_for_target` | `executors/cpu_executor`, `executors/npu_executor` | Reached ONLY inside `route_execution`; no other caller | GOVERNED |
| 5 | Client execution harness | `security/execution_guard.py` `execute_command()` (line 460) | `security/execution_guard.py` | Local fail-closed pre-flight (`enforce_local_execution_policy` → `classify_command` tiers T0–T3) + `_redis_dependency_allows_execution`; then proxies to gateway `/decide` then `/execute`; runs locally (`_run_command`) only after gateway returns `status == EXECUTED` | GOVERNED (delegates to canonical gate) |
| 6 | Air-gapped CLI command | `runtime/enforcement_gateway.py` `evaluate_command_request()` (line 925) → `replit_executor.execute_command` (line 954) | `runtime/enforcement_gateway.py` | Independent offline gate: `check_private_key_not_present`, `check_audit_log_writability`, `validate_signed_policy`, runtime attestation, `validate_audit_chain`, `_enforce_zero_trust_device`, signed `_generate_action_token`, attested executor | GOVERNED (separate enforcement domain) |
| 7 | Air-gapped CLI automation | `runtime/enforcement_gateway.py` `evaluate_automation_request()` (line 863) → `_execute_automation` (line 437) | `runtime/enforcement_gateway.py` | `_validate_automation_request` + `_validate_automation_context` + `validate_signed_policy` before `_execute_automation`; deny path appends audit event | GOVERNED (separate enforcement domain) |
| 8 | Test-only request helpers | `tests/test_decide_first.py` (`configure_gateway`, `build_payload`, `approve`), `tests/request_signing_helpers.py` (`sign_payload_ed25519`) | tests (non-runtime) | None — these construct and sign requests; every request still traverses the real `/decide`+`/execute` gate. They cannot dispatch executors directly. | TEST-ONLY — no bypass |

## Owner accountability summary

- `gateway/app.py` owns the **canonical runtime gate** (surfaces 1–2) and is the only
  module that calls `route_execution`.
- `security/compute_router.py` owns **compute dispatch** (surfaces 3–4) and is the only
  module that calls `executor.execute`.
- `security/execution_guard.py` owns the **client harness** (surface 5); it never
  executes a command until the gateway has authorized it. Its local classifier is
  defense-in-depth, not the authority of record.
- `runtime/enforcement_gateway.py` owns the **air-gapped/offline enforcement domain**
  (surfaces 6–7). This is a deliberately separate governance domain from the HTTP gate;
  it uses signed policy + zero-trust device attestation + signed action tokens rather
  than the `/decide`+`/execute` decision-record protocol. It does NOT share or bypass
  the HTTP gate, and the HTTP gate does not delegate to it.
- tests own surface 8 and carry no runtime authority.

## Non-executing adjudication (not an execution surface)

- `runtime/enforcement_gateway.py` `evaluate_governance_request()` (line 791) is a
  policy allow/deny adjudication path; it does **not** run commands or dispatch
  executors and is therefore not an execution surface. It is listed here only to
  preempt ambiguity — it cannot bypass any execution gate because it never executes.

## Out of scope (untouched per PB-INVENTORY-001 rules)

- simulator / travel / voucher logic
- tenant logic
- RFC3161 / timestamp logic

No runtime semantics were added or changed by this inventory; see CANONICAL_GATE_AUDIT.md
§4 and BYPASS_MATRIX_V2.md for the no-bypass proof and validation evidence.
