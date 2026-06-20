# EXECUTION_CALL_GRAPH — Execution Path Call Graphs

PB-INVENTORY-001 — caller→callee graphs for every execution surface in
EXECUTION_SURFACE_MAP.md. Line numbers are anchors at time of audit.

## 1. Runtime HTTP execution (canonical gate)

```
POST /decide  →  decide() [app.py:14370]
                   └─ create_governance_decision(payload) [app.py:1487]
                        ├─ redis_dependency_state() / require_redis()      (fail-closed)
                        ├─ _basic_request_valid()
                        ├─ validate_metadata()
                        ├─ tenant_execution_context()
                        ├─ _request_policy_version()                       (missing_policy → DENY)
                        ├─ _signature_validation()                         (request signature)
                        ├─ validate_compute_request(payload) [compute_governance.py:139]   ← compute policy gate
                        ├─ decision_store.reserve_nonce()                  (replay reservation)
                        ├─ load_policy_registry() / policy_signature_mode()
                        ├─ validate_simulation()
                        ├─ evaluate_hydra_request(...)                     (consensus)
                        ├─ execution_command_allowed(command) [app.py:1140] ← command allowlist (type==execution)
                        └─ decision_store.create_decision()                → SIGNED single-use decision record

POST /execute →  execute() [app.py:14445]
                   ├─ validate_execution_decision(payload) [app.py:1620]
                   │    ├─ redis_dependency_state() / require_redis()      (fail-closed)
                   │    ├─ decision_id present
                   │    ├─ decision signatures present (classic and/or pqc)
                   │    ├─ decision_store.load_decision()                  (unknown_decision → DENY)
                   │    ├─ actor_hash binding                              (actor_mismatch → DENY)
                   │    ├─ is_supported_alg_version()
                   │    ├─ verify_submitted_decision_signatures()
                   │    ├─ record.used is True?                            (replay_detected → DENY)
                   │    ├─ validate_decision_time()
                   │    ├─ nonce_hash binding                             (decision_nonce_mismatch → DENY)
                   │    └─ request_hash binding                           (decision_request_mismatch → DENY)
                   ├─ verify(payload) [app.py:1932]                        (HYDRA_DENIED / POLICY_DENIED / fail_closed)
                   ├─ route_execution(payload, decision_record) [compute_router.py:24]
                   │    ├─ validate_compute_request(payload)               ← compute policy RE-validation (defense in depth)
                   │    ├─ requested_target == stored_target               (compute_target_mismatch)
                   │    ├─ tpu ⇒ human_review required                    (human_review_required)
                   │    ├─ executor = _executor_for_target(target)        [compute_router.py:12]
                   │    ├─ result = executor.execute(payload)              ← ONLY executor invocation site
                   │    ├─ actual_execution_target == requested_target     (compute_execution_mismatch)
                   │    └─ result.execution_verified is True               (compute_execution_unverified)
                   ├─ mark_decision_used(...)                              (single-use enforcement; replay_detected)
                   └─ audit_chain.append() + audit_governance_event("execution_allowed")
```

Key invariant: `/execute` cannot run anything unless it presents a valid, signed,
unused decision record that `/decide` minted for the *same* request hash, nonce, actor,
and compute target. `route_execution` (and therefore `executor.execute`) is reachable
from exactly ONE caller: `execute()` at app.py:14475, after all checks above.

## 2. Client execution harness (security/execution_guard.py)

```
execute_command(cmd, metadata) [execution_guard.py:460]
  ├─ enforce_local_execution_policy(cmd, metadata) [execution_guard.py:222]
  │    └─ classify_command() → tier T0–T3; APPROVAL_REQUIRED_REASONS gate; fail-closed
  │       (policy_engine_unavailable / unknown_classification / explicit_approval_required
  │        / execution_evidence_unavailable → allowed=False)
  ├─ _redis_dependency_allows_execution(metadata)                          (redis_unavailable → deny)
  ├─ build_execution_payload() + sign_payload()                            (request signing; fail-closed on missing key)
  ├─ POST /decide   (via gateway_client or HTTP)  → must return decision == ALLOW
  ├─ POST /execute  (with decision_id + decision signatures) → must return status == EXECUTED
  └─ _run_command(cmd) [execution_guard.py:433]                            ← local run ONLY after gateway EXECUTED
```

The harness is a *client* of the canonical gate. Its local classifier is an additional
deny layer; it never substitutes for the gateway authorization.

## 3. Air-gapped CLI command (runtime/enforcement_gateway.py)

```
main(argv) [enforcement_gateway.py:1048]
  └─ evaluate_command_request(request_path) [enforcement_gateway.py:925]
       ├─ _load_command_request()
       ├─ check_private_key_not_present()
       ├─ check_audit_log_writability()
       ├─ validate_signed_policy()                       → policy_version, loaded_policy_hash
       ├─ generate_runtime_attestation() / _record_runtime_loaded()
       ├─ policy_validator.validate_runtime_attestation()
       ├─ policy_validator.validate_audit_chain()
       ├─ _enforce_zero_trust_device(request)
       ├─ _generate_action_token(command, policy_hash)   → signed action token
       ├─ replit_executor.execute_command(... signed token + attestation ...)
       └─ _append_audit_event(remote_execution event)    (deny path → _deny + audit)
```

## 4. Air-gapped CLI automation (runtime/enforcement_gateway.py)

```
main(argv) [enforcement_gateway.py:1048]
  └─ evaluate_automation_request(request_path) [enforcement_gateway.py:863]
       ├─ validate_signed_policy()
       ├─ _validate_automation_request(request_path) [line 386]
       ├─ _validate_automation_context(metadata, request) [line 429]
       ├─ _execute_automation(request) [line 437]
       └─ _append_audit_event(automation event)          (deny path → _deny + audit)
```

## 5. Test-only helpers

```
tests/test_decide_first.py: configure_gateway / build_payload / approve
tests/request_signing_helpers.py: sign_payload_ed25519 / configure_request_signing
  → build & sign payloads, POST /decide then /execute through the REAL gate.
  → no direct call to route_execution or executor.execute exists in tests.
```
