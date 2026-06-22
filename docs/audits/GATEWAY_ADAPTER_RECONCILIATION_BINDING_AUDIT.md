# PB-E2E-003 - Gateway Adapter Reconciliation Binding Audit

Date: 2026-06-22

## Scope

- `execution/adapters/base.py`
- `tests/test_execution_adapters.py`

This capability closes the PB-E2E-001 gateway-to-adapter reconciliation gap for
the adapter governance layer by requiring every adapter action contract to carry
a deterministic gateway binding record before adapter governance validation can
be considered valid.

No Replit runtime code, simulator behavior, travel/voucher behavior, tenant
logic, RFC3161 logic, lineage rewrite, connector write, deployment behavior, or
policy mutation is introduced.

## Canonical Authority

Canonical Gateway Adapter Reconciliation Binding Authority:

`usbay.gateway.adapter_reconciliation_binding_authority`

Canonical owner:

`gateway.app.canonical_execution_governance_gate`

Canonical authority evidence:

`docs/audits/EXECUTION_SURFACE_MAP.md`

Canonical lineage evidence:

`docs/audits/CANONICAL_GATE_AUDIT.md`

## Binding Model

Every adapter action contract must include:

- `gateway_binding_id`
- `gateway_binding_owner`
- `gateway_binding_reference`
- `gateway_binding_lineage`
- `gateway_binding_status`
- `gateway_binding_hash`

Only `GATEWAY_RECONCILED` allows adapter validation to continue without a
gateway binding blocker.

The binding hash deterministically binds:

- gateway binding identifier
- canonical gateway owner
- gateway binding reference
- gateway binding lineage
- gateway binding status
- adapter name
- adapter capability
- canonical governance gate reference
- adapter reconciliation material

The adapter reconciliation hash includes the gateway binding hash, so gateway
binding drift invalidates adapter reconciliation evidence.

## Fail-Closed Reason Codes

| Condition | Reason code |
| --- | --- |
| Missing gateway binding identifier, owner, status, or hash | `GATEWAY_BINDING_MISSING` |
| Missing gateway authority reference | `GATEWAY_REFERENCE_MISSING` |
| Missing gateway reconciliation lineage | `GATEWAY_LINEAGE_MISSING` |
| Gateway binding owner mismatch | `GATEWAY_OWNER_MISMATCH` |
| Gateway binding identifier or reference mismatch | `GATEWAY_REFERENCE_MISMATCH` |
| Gateway binding hash mismatch | `GATEWAY_HASH_MISMATCH` |
| Binding status is not `GATEWAY_RECONCILED` | `GATEWAY_BINDING_STALE` |
| Binding identifier duplicates another authority identifier | `GATEWAY_BINDING_DUPLICATE` |
| Binding exists for an unknown adapter/capability declaration | `GATEWAY_BINDING_ORPHAN` |

## Validation Path

```text
build_adapter_action_contract()
  -> attach canonical gateway binding fields
  -> validate_adapter_action_contract()
  -> _gateway_binding_reasons()
  -> validate_adapter_governance_consistency()
  -> validate_adapter_governance_reconciliation()
  -> validate_canonical_gate_proof()
  -> BLOCK on any binding, consistency, reconciliation, or gate proof failure
```

## Evidence Matrix

| Evidence | Coverage |
| --- | --- |
| `test_adapter_capability_map_has_single_canonical_owner` | published adapter map exposes gateway binding authority, owner, reference, lineage, status, and hash |
| `test_missing_gateway_binding_fails_closed` | missing binding id, owner, status, or hash blocks |
| `test_missing_gateway_reference_fails_closed` | missing gateway reference blocks |
| `test_missing_gateway_lineage_fails_closed` | missing gateway lineage blocks |
| `test_gateway_owner_mismatch_fails_closed` | gateway owner drift blocks |
| `test_gateway_reference_mismatch_fails_closed` | identifier/reference drift blocks |
| `test_gateway_hash_mismatch_fails_closed` | gateway binding hash drift blocks |
| `test_stale_gateway_binding_fails_closed` | non-`GATEWAY_RECONCILED` status blocks |
| `test_duplicate_gateway_binding_fails_closed` | duplicate gateway binding identifier blocks |
| `test_orphan_gateway_binding_fails_closed` | unknown adapter/capability binding blocks |
| `test_gateway_reconciled_adapter_contract_is_allowed` | canonical binding succeeds when all adapter authorities and gate proof are valid |
| `test_adapter_evaluate_blocks_missing_gateway_binding` | adapter evaluation blocks when gateway binding evidence is missing |

## No-Live-Execution-Lineage Statement

This audit does not invent gateway execution records and does not claim that a
live `/execute` request has been bound to a concrete adapter reconciliation
record. It proves deterministic adapter governance reconciliation to the
existing canonical gateway execution authority path and its audit inventory.

## Fail-Closed Impact

No execution-capable adapter may be considered governance-valid unless its
action contract includes a gateway binding record owned by
`gateway.app.canonical_execution_governance_gate`, linked to the execution
inventory and canonical gate audit, in `GATEWAY_RECONCILED` state, and backed by
the expected deterministic binding hash.

Missing, stale, mismatched, orphaned, or duplicated gateway binding evidence
blocks adapter validation.

## Remaining Gaps

- This binds adapter governance to the canonical gateway authority path. It does
  not create a live gateway execution record.
- Concrete `/execute` request to adapter reconciliation lineage remains a
  separate end-to-end proof gap.
- Simulator-to-runtime proof binding remains outside this capability.

## Validation Commands

```text
python3.11 -m py_compile execution/adapters/base.py tests/test_execution_adapters.py
pytest -q tests/test_execution_adapters.py
pytest -q tests/test_gateway_app.py
git diff --check
git diff --cached --check
```
