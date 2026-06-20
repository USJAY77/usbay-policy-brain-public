# CANONICAL_GATE_AUDIT — Canonical Execution Governance Gate Coverage

PB-INVENTORY-001 deliverable #4: prove no unmanaged execution path bypasses the
canonical execution governance gate.

## 1. What the canonical gate IS in this codebase

PB-INVENTORY-001 refers to `canonical_execution_governance_gate()`. There is **no
function with that literal name** in the repository (confirmed by repo-wide search;
the only occurrence is the task spec itself). The canonical gate is implemented as a
**composite two-phase protocol**, not a single function:

1. **Authorization phase — `/decide`** (`create_governance_decision`, app.py:1487):
   validates the request and mints a *signed, single-use, request-bound decision
   record*. A request that fails any check never produces a record (returns `None`).
2. **Execution phase — `/execute`** (`execute`, app.py:14445): refuses to run unless a
   valid decision record from phase 1 is presented and re-verified
   (`validate_execution_decision`), policy re-checked (`verify`), compute re-validated
   and dispatched (`route_execution`), then the record is burned (`mark_decision_used`).

Treat the canonical gate as: **`/decide` (issuer) + `/execute` (consumer)**, with
`route_execution` as the single dispatch chokepoint and `executor.execute` as the
single executor invocation site.

This audit deliberately does **not** introduce a new `canonical_execution_governance_gate()`
function: PB-INVENTORY-001 rule #6 forbids inventing runtime semantics unless required
to close a verified bypass, and no bypass was found (see §4 and BYPASS_MATRIX_V2.md).

## 2. Chokepoint proof (single-caller invariants)

- `route_execution` callers: exactly one — `gateway/app.py:14475`, inside `/execute`,
  after `validate_execution_decision` and `verify`. (Definition at compute_router.py:24.)
- `executor.execute(payload)` call sites: exactly one — `compute_router.py:41`, inside
  `route_execution`, after `validate_compute_request` and target binding.
- `gateway/app.py` contains **no** `subprocess`, `os.system`, `os.popen`, `os.exec*`,
  `eval(`, or bare `exec(` calls. The gateway's only execution effect is via
  `route_execution`.
- Only two POST routes exist on the app: `/decide` and `/execute`. No other HTTP route
  dispatches executors or runs commands.

## 3. Coverage matrix — every surface to its gate

| Surface | Governed by canonical gate? | Enforcing checks | Result |
|---------|-----------------------------|------------------|--------|
| POST /execute | YES (is the gate) | decision sig/nonce/replay/time/request binding + verify + route_execution + single-use | COVERED |
| POST /decide | YES (issuer) | deps + metadata + signature + compute policy + nonce + hydra + command allowlist | COVERED |
| route_execution | YES (only via /execute) | compute re-validation + target binding + executor verification | COVERED |
| executor.execute | YES (only via route_execution) | unreachable except through route_execution | COVERED |
| execution_guard.execute_command | YES (HTTP client of the gate) | local fail-closed pre-flight + must get /decide ALLOW + /execute EXECUTED before local run | COVERED |
| enforcement_gateway.evaluate_command_request | Separate offline domain | signed policy + zero-trust device + signed action token + attested executor | COVERED (independent gate) |
| enforcement_gateway.evaluate_automation_request | Separate offline domain | validated automation request + context + signed policy | COVERED (independent gate) |
| test helpers (test_decide_first, request_signing_helpers) | N/A — test-only | construct/sign requests; always traverse the real gate | NO BYPASS |

## 4. Validation evidence (run at audit time)

Toolchain: `/home/runner/workspace/.pythonlibs/bin/python3.11`.

```
$ python3.11 -m py_compile gateway/*.py runtime/*.py security/*.py governance/*.py
py_compile OK

$ pytest -q tests/test_gateway_app.py
37 passed

$ pytest -q tests/test_execution_guard.py
16 passed

$ pytest -q tests/test_compute_governance.py
12 passed

# runtime policy validator coverage — the canonical tests that exercise
# runtime/policy_validator.py. (The PB-INVENTORY-001 spec listed a runtime
# policy-validator extraction test that never existed in the repository; it is
# non-canonical and excluded. See INVENTORY_CONSISTENCY_AUDIT.md.)
$ pytest -q tests/test_governance_validation.py
16 passed

$ pytest -q tests/test_policy_verification_workflow.py
6 passed
```

Totals: **87 tests passed, 0 failed.** Compile clean across gateway/runtime/security/governance.

## 5. Findings

- All eight execution surfaces are either governed by the canonical HTTP gate, governed
  by the explicitly-separate air-gapped enforcement domain, or test-only. **No unmanaged
  execution path was found.**
- No assertion gap was found that would require adding a test (PB-INVENTORY-001 rule #5):
  existing suites already assert deny-on-mismatch, replay rejection, fail-closed on redis,
  compute-target mismatch fail-closed, and tampered/missing-signature rejection.
- No runtime code change was required; the inventory is documentation-only.

## 6. Inventory consistency note (resolved — PB-INVENTORY-002)

- The runtime policy validator (`runtime/policy_validator.py`) is covered by
  `tests/test_governance_validation.py` (16) and `tests/test_policy_verification_workflow.py` (6).
- The PB-INVENTORY-001 spec's validation list named a runtime policy-validator
  extraction test that never existed in the repository or its git history. That
  reference is stale/non-canonical and is not part of repository reality. Full
  classification and proof (including the exact filename): see INVENTORY_CONSISTENCY_AUDIT.md.
