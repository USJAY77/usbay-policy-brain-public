# BYPASS_MATRIX_V2 — Fail-Closed / No-Bypass Evidence

PB-INVENTORY-001 — enumerate every plausible way to reach execution without proper
governance and show the gate denies it (fail-closed). Each row cites the enforcing
check from EXECUTION_CALL_GRAPH.md.

## Runtime HTTP gate (`/decide` + `/execute`)

| # | Attempted bypass vector | Enforcing check (file:symbol) | Outcome |
|---|-------------------------|-------------------------------|---------|
| 1 | Call `/execute` with no decision_id | `validate_execution_decision` missing_decision_id (app.py:1635) | DENY |
| 2 | Call `/execute` with a forged/absent decision signature | `verify_submitted_decision_signatures` (app.py:1677) → invalid_signature | DENY |
| 3 | Replay a decision (reuse `used` record) | `record.used is True` (app.py:1688) + `mark_decision_used` (app.py:14490) | DENY (replay_detected) |
| 4 | Swap actor after approval | `actor_hash` binding (app.py:1663) | DENY (actor_mismatch) |
| 5 | Reuse a decision for a different command/body | `request_hash` binding (app.py:1709) | DENY (decision_request_mismatch) |
| 6 | Reuse a decision with a different nonce | `nonce_hash` binding (app.py:1702) | DENY (decision_nonce_mismatch) |
| 7 | Submit an expired decision | `validate_decision_time` (app.py:1695) | DENY (decision_time_invalid) |
| 8 | Get approval for a forbidden command at `/decide` | `execution_command_allowed` allowlist (app.py:1568) | DENY (policy_denied) |
| 9 | Request a compute target not in policy / sensitive on cloud | `validate_compute_request` (compute_governance.py:139) | DENY (compute_target_not_allowed / sensitive_data_compute_denied) |
| 10 | Pass `/decide` then mutate compute target before `/execute` | `route_execution` target binding requested==stored (compute_router.py:34) | DENY (compute_target_mismatch) |
| 11 | Executor runs on a different target than requested | actual==requested check (compute_router.py:46) | DENY (compute_execution_mismatch) |
| 12 | Executor returns unverified result | `execution_verified is True` (compute_router.py:48) | DENY (compute_execution_unverified) |
| 13 | Redis/replay store down while REQUIRE_REDIS | `redis_dependency_state` / `require_redis` (app.py:1488, 1491, 1621, 1628) | DENY (redis_unavailable) — fail-closed |
| 14 | Replay nonce at decision time | `decision_store.reserve_nonce` (app.py:1522) | DENY (replay_detected) |
| 15 | Hydra consensus not "allow" | `evaluate_hydra_request` (app.py:1547) | DENY (hydra denial reason) |
| 16 | Reach an executor via any non-`/execute` route | only callers: /execute→route_execution→executor.execute (single-site, §2 of CANONICAL_GATE_AUDIT) | UNREACHABLE |
| 17 | Run a shell command inside the gateway directly | no subprocess/os.system/exec/eval in gateway/app.py | NO SUCH PATH |

## Client harness (`security/execution_guard.py`)

| # | Attempted bypass vector | Enforcing check | Outcome |
|---|-------------------------|-----------------|---------|
| 18 | Run a command locally without gateway approval | `execute_command` requires /decide ALLOW + /execute EXECUTED before `_run_command` (execution_guard.py:474–489) | DENY |
| 19 | Run an approval-required command (rm -rf, network, unsandboxed, chain) without explicit approval | `enforce_local_execution_policy` APPROVAL_REQUIRED_REASONS (execution_guard.py:242) | DENY (explicit_approval_required) |
| 20 | Run an unclassifiable command | `classify_command` unknown_classification (execution_guard.py:240) | DENY |
| 21 | Local policy engine unavailable | `enforce_local_execution_policy` except → policy_engine_unavailable (execution_guard.py:225) | DENY — fail-closed |
| 22 | Audit evidence unwritable | evidence append failure → execution_evidence_unavailable (execution_guard.py:255) | DENY — fail-closed |
| 23 | Sign request without a signing key | `sign_payload` raises EXECUTION_GUARD_FAIL_CLOSED (execution_guard.py:357) | DENY — fail-closed |
| 24 | Redis dependency required but gateway unhealthy | `_redis_dependency_allows_execution` (execution_guard.py:418) | DENY (redis_unavailable) |

## Air-gapped CLI enforcement domain (`runtime/enforcement_gateway.py`)

| # | Attempted bypass vector | Enforcing check | Outcome |
|---|-------------------------|-----------------|---------|
| 25 | Execute with invalid/unverifiable signed policy | `validate_signed_policy` + `_enforce_expected_policy_hash` | DENY |
| 26 | Execute from an unregistered/unattested device | `_enforce_zero_trust_device` (enforcement_gateway.py:743) | DENY |
| 27 | Execute without a signed action token | `_generate_action_token` + attested `replit_executor.execute_command` (enforcement_gateway.py:951–963) | DENY |
| 28 | Private key present on runtime host | `check_private_key_not_present` (enforcement_gateway.py:463) | DENY — fail-closed |
| 29 | Audit log not writable | `check_audit_log_writability` (enforcement_gateway.py:468) | DENY — fail-closed |
| 30 | Automation request/context invalid | `_validate_automation_request` + `_validate_automation_context` (lines 386, 429) | DENY |
| 31 | Any exception in command/automation evaluation | `_deny(...)` + audit append in `except` (lines 932, 964) | DENY — fail-closed |

## Test-only helpers

| # | Vector | Reality | Outcome |
|---|--------|---------|---------|
| 32 | A test directly invokes `route_execution` / `executor.execute` to skip the gate | No such call exists in `tests/`; helpers only build+sign payloads and POST to the real `/decide`+`/execute` | NO BYPASS |

## Conclusion

Every enumerated vector terminates in a deny (most fail-closed) or is structurally
unreachable. No execution surface escapes governance. No new runtime semantics were
required to close a bypass (none was found), so none were added.

Validation evidence: see CANONICAL_GATE_AUDIT.md §4 — py_compile clean; 87 tests passed
(37 gateway + 16 execution_guard + 12 compute_governance + 16 governance_validation +
6 policy_verification_workflow). The runtime policy validator is covered by the latter
two suites; the spec-listed runtime policy-validator extraction test is a
non-canonical reference that was never part of the repository — see
INVENTORY_CONSISTENCY_AUDIT.md.
