# PB-RUNTIME-002 — Execution Call Graph

Caller → callee map for the only governed compute execution path, plus the Runtime
Health Authority (shown disconnected, because nothing on the execution path calls it).

## Governed compute execution path

```
POST /execute                                 gateway/app.py:14599  (execute)
  ├─ validate_execution_decision(payload)      gateway/app.py:1620
  │    ├─ redis_dependency_state / replay_protection_active
  │    ├─ decision_store.load_decision(decision_id)
  │    └─ _deny_decision_response(...)          gateway/app.py:1377   [DENY]
  ├─ verify(payload)                            gateway/app.py:1932
  │    ├─ HYDRA_DENIED  -> 403 denied_by_hydra  [DENY]
  │    ├─ POLICY_DENIED -> 403 execution_denied [DENY]
  │    └─ falsy         -> fail_closed(action)  gateway/app.py:358  [DENY]
  ├─ route_execution(payload, decision)         security/compute_router.py:24
  │    ├─ validate_compute_request(payload)     security/compute_governance.py:139
  │    │     └─ != ALLOW -> ComputeRoutingError [DENY]
  │    ├─ _executor_for_target(target)          security/compute_router.py:12
  │    │     ├─ "cpu" -> executors.cpu_executor
  │    │     ├─ "npu" -> executors.npu_executor
  │    │     └─ else   -> ComputeRoutingError    [DENY]
  │    ├─ executor.execute(payload)             security/compute_router.py:41  <== EXECUTION SINK
  │    └─ mismatch / unverified -> ComputeRoutingError [DENY]
  ├─ mark_decision_used(decision, proof)        replay single-use consume
  │    └─ not used -> _deny_decision_response("replay_detected") [DENY]
  ├─ audit_chain.append(action, {...})          post-exec audit
  ├─ audit_governance_event("execution_allowed", {...})
  └─ return {"status": "EXECUTED"}              [ALLOW]
```

## Decision-creation path (prerequisite, not execution)

```
POST /decide                                   gateway/app.py:14524
  └─ create_governance_decision(payload)        gateway/app.py:1487
       ├─ tenant_execution_context / _request_policy_version / _signature_validation
       └─ validate_compute_request(payload)     gateway/app.py:1511  (validation only; no executor)
```

## Runtime Health Authority (DISCONNECTED from execution)

```
runtime_health_snapshot()                       gateway/app.py:14927
  ├─ GET /runtime/health           gateway/app.py:15109 -> snapshot @15115   (observability)
  └─ GET /runtime/health/selftest  gateway/app.py:15124 -> snapshot @15129   (observability)

runtime_execution_gate()                        gateway/app.py:15008
  └─ (no production callers — referenced only by tests/test_gateway_app.py:939,962)
```

> The gate and snapshot are **not** referenced anywhere on the `POST /execute`
> path. There is no edge from any execution node into the Runtime Health Authority.

## `runtime/*` module wiring

```
gateway/app.py:18  from runtime import websocket_server   (voice-alert client registry; not execution)

runtime/enforcement_gateway.py   STANDALONE governance HTTP/CLI server (BaseHTTPRequestHandler,
                                 serve_attestation:663, _execute_automation:437)
                                 -> NO Python importers; NOT wired into FastAPI app;
                                    invoked only as a CLI script by governance_check.sh (93/102/110/144)
runtime/command_model.py         -> wraps runtime/policy_validator.py
runtime/policy_validator.py      -> command-request validation helpers
```
