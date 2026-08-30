# PB-E2E-004 - Simulator Runtime Proof Binding Audit

Date: 2026-06-22

## Scope

- `execution/adapters/base.py`
- `tests/test_execution_adapters.py`

This capability closes the PB-E2E-001 simulator-to-runtime proof gap for the
adapter governance layer by requiring every adapter action contract to carry a
deterministic simulator/runtime proof binding record before adapter governance
validation can be considered end-to-end reconciled.

No Replit runtime code, simulator implementation, travel/voucher behavior,
tenant logic, RFC3161 logic, lineage rewrite, connector write, deployment
behavior, or policy mutation is introduced.

## Canonical Authority

Canonical Simulator Runtime Proof Binding Authority:

`usbay.simulator.runtime_proof_binding_authority`

Simulator evidence owner:

`tests.test_simulation_governance`

Simulator evidence reference:

`tests/test_simulation_governance.py`

Runtime proof lineage reference:

`tests/test_runtime_parity_validator.py`

## Binding Model

Every adapter action contract must include:

- `simulator_binding_id`
- `simulator_binding_owner`
- `simulator_binding_reference`
- `simulator_binding_lineage`
- `simulator_binding_status`
- `simulator_binding_hash`

Only `SIMULATOR_RUNTIME_BOUND` allows adapter validation to continue without a
simulator/runtime proof binding blocker.

The binding hash deterministically binds:

- simulator/runtime binding identifier
- simulator governance evidence owner
- simulator governance evidence reference
- runtime proof lineage reference
- simulator binding status
- adapter name
- adapter capability
- gateway binding hash
- canonical governance gate reference

The binding is evidence-only. It reconciles simulator governance evidence with
runtime proof evidence references; it does not assert that simulator output was
executed, routed, deployed, or used as live runtime lineage.

## Fail-Closed Reason Codes

| Condition | Reason code |
| --- | --- |
| Missing simulator binding identifier, owner, status, or hash | `SIMULATOR_BINDING_MISSING` |
| Missing simulator authority reference | `SIMULATOR_REFERENCE_MISSING` |
| Missing simulator/runtime proof lineage | `SIMULATOR_LINEAGE_MISSING` |
| Simulator binding owner mismatch | `SIMULATOR_OWNER_MISMATCH` |
| Simulator binding identifier or reference mismatch | `SIMULATOR_REFERENCE_MISMATCH` |
| Simulator binding hash mismatch | `SIMULATOR_HASH_MISMATCH` |
| Binding status is not `SIMULATOR_RUNTIME_BOUND` | `SIMULATOR_BINDING_STALE` |
| Binding identifier duplicates another authority identifier | `SIMULATOR_BINDING_DUPLICATE` |
| Binding exists for an unknown adapter/capability declaration | `SIMULATOR_BINDING_ORPHAN` |

## Validation Path

```text
build_adapter_action_contract()
  -> attach canonical simulator/runtime binding fields
  -> validate_adapter_action_contract()
  -> _simulator_binding_reasons()
  -> _gateway_binding_reasons()
  -> validate_adapter_governance_consistency()
  -> validate_adapter_governance_reconciliation()
  -> validate_canonical_gate_proof()
  -> BLOCK on any simulator, gateway, consistency, reconciliation, or gate proof failure
```

## Evidence Matrix

| Evidence | Coverage |
| --- | --- |
| `test_adapter_capability_map_has_single_canonical_owner` | published adapter map exposes simulator binding authority, owner, reference, lineage, status, and hash |
| `test_missing_simulator_binding_fails_closed` | missing binding id, owner, status, or hash blocks |
| `test_missing_simulator_reference_fails_closed` | missing simulator evidence reference blocks |
| `test_missing_simulator_lineage_fails_closed` | missing runtime proof lineage blocks |
| `test_simulator_owner_mismatch_fails_closed` | simulator evidence owner drift blocks |
| `test_simulator_reference_mismatch_fails_closed` | identifier/reference drift blocks |
| `test_simulator_hash_mismatch_fails_closed` | simulator binding hash drift blocks |
| `test_stale_simulator_binding_fails_closed` | non-`SIMULATOR_RUNTIME_BOUND` status blocks |
| `test_duplicate_simulator_binding_fails_closed` | duplicate simulator binding identifier blocks |
| `test_orphan_simulator_binding_fails_closed` | unknown adapter/capability binding blocks |
| `test_simulator_runtime_bound_adapter_contract_is_allowed` | canonical binding succeeds when all adapter authorities and gate proof are valid |
| `test_adapter_evaluate_blocks_missing_simulator_binding` | adapter evaluation blocks when simulator/runtime binding evidence is missing |

## No-Live-Execution-Lineage Statement

This audit does not invent simulator execution records and does not claim live
runtime execution lineage. It proves deterministic, evidence-only binding
between simulator governance evidence and runtime proof evidence references.

## Fail-Closed Impact

No simulator governance evidence may be considered end-to-end reconciled unless
its adapter action contract includes a simulator/runtime proof binding record
owned by `tests.test_simulation_governance`, linked to runtime parity validator
evidence, in `SIMULATOR_RUNTIME_BOUND` state, and backed by the expected
deterministic binding hash.

Missing, stale, mismatched, orphaned, or duplicated simulator/runtime binding
evidence blocks adapter validation.

## Remaining Gaps

- This binds simulator governance evidence to runtime proof evidence references.
  It does not create simulator execution records.
- It does not claim live runtime execution lineage.
- Concrete live execution request lineage remains outside this scoped
  capability.

## Validation Commands

```text
python3.11 -m py_compile execution/adapters/base.py tests/test_execution_adapters.py
pytest -q tests/test_execution_adapters.py
pytest -q tests/test_gateway_app.py
git diff --check
git diff --cached --check
```
