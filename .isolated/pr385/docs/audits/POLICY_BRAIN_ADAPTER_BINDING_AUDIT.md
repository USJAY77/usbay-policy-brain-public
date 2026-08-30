# PB-E2E-002 - Policy Brain Adapter Binding Audit

Date: 2026-06-22

## Scope

- `execution/adapters/base.py`
- `tests/test_execution_adapters.py`

This capability closes the PB-E2E-001 `GAP_POLICY_BRAIN_LINKAGE` item for the
adapter governance layer by requiring every adapter action contract to carry a
deterministic Policy Brain binding record before adapter governance validation
can be considered valid.

No Replit runtime behavior, simulator behavior, travel/voucher behavior, tenant
logic, RFC3161 logic, lineage rewrite, connector write, deployment behavior, or
policy mutation is introduced.

## Canonical Authority

Canonical Policy Brain Binding Authority:

`usbay.policy_brain.adapter_binding_authority`

Canonical owner:

`runtime.policy_validator`

Canonical reference:

`runtime/policy_validator.py`

Canonical lineage reference:

`docs/governance/AUDIT_LINEAGE_FRAMEWORK.md`

## Binding Model

Every adapter action contract must include:

- `policy_binding_id`
- `policy_binding_owner`
- `policy_binding_reference`
- `policy_binding_lineage`
- `policy_binding_status`
- `policy_binding_hash`

Only `POLICY_BOUND` allows adapter validation to continue without a policy
binding blocker.

The binding hash deterministically binds:

- Policy Brain binding identifier
- Policy Brain binding owner
- Policy Brain binding reference
- audit lineage reference
- binding status
- adapter name
- adapter capability
- adapter provenance chain hash
- canonical governance gate reference

No fake policy identifiers are introduced. The binding points to the existing
repository Policy Brain authority path, `runtime/policy_validator.py`, and its
governed audit lineage framework reference.

## Fail-Closed Reason Codes

| Condition | Reason code |
| --- | --- |
| Missing binding identifier, owner, status, or hash | `POLICY_BINDING_MISSING` |
| Missing Policy Brain reference | `POLICY_REFERENCE_MISSING` |
| Missing binding lineage | `POLICY_LINEAGE_MISSING` |
| Policy binding owner mismatch | `POLICY_OWNER_MISMATCH` |
| Policy binding identifier or reference mismatch | `POLICY_REFERENCE_MISMATCH` |
| Policy binding hash mismatch | `POLICY_HASH_MISMATCH` |
| Binding status is not `POLICY_BOUND` | `POLICY_BINDING_STALE` |
| Binding identifier duplicates another adapter authority identifier | `POLICY_BINDING_DUPLICATE` |
| Binding exists for an unknown adapter/capability declaration | `POLICY_BINDING_ORPHAN` |

## Validation Path

```text
build_adapter_action_contract()
  -> attach canonical Policy Brain binding fields
  -> validate_adapter_action_contract()
  -> _policy_binding_reasons()
  -> validate_adapter_governance_consistency()
  -> validate_adapter_governance_reconciliation()
  -> validate_canonical_gate_proof()
  -> BLOCK on any binding, consistency, reconciliation, or gate proof failure
```

## Evidence Matrix

| Evidence | Coverage |
| --- | --- |
| `test_adapter_capability_map_has_single_canonical_owner` | published adapter map exposes binding authority, owner, reference, lineage, status, and hash |
| `test_missing_policy_binding_fails_closed` | missing binding id, owner, status, or hash blocks |
| `test_missing_policy_reference_fails_closed` | missing Policy Brain reference blocks |
| `test_missing_policy_lineage_fails_closed` | missing lineage blocks |
| `test_policy_owner_mismatch_fails_closed` | owner drift blocks |
| `test_policy_reference_mismatch_fails_closed` | identifier/reference drift blocks |
| `test_policy_hash_mismatch_fails_closed` | binding hash drift blocks |
| `test_stale_policy_binding_fails_closed` | non-`POLICY_BOUND` status blocks |
| `test_duplicate_policy_binding_fails_closed` | duplicate binding identifier blocks |
| `test_orphan_policy_binding_fails_closed` | unknown adapter/capability binding blocks |
| `test_policy_bound_adapter_contract_is_allowed` | canonical binding succeeds when all adapter authorities and gate proof are valid |
| `test_adapter_evaluate_blocks_missing_policy_binding` | adapter evaluation blocks before disabled response when binding evidence is missing |

## Fail-Closed Impact

No adapter governance authority may be considered valid unless its action
contract includes a Policy Brain binding record owned by `runtime.policy_validator`,
linked to the audit lineage framework, in `POLICY_BOUND` state, and backed by the
expected deterministic binding hash.

Missing, stale, mismatched, orphaned, or duplicated Policy Brain binding
evidence blocks adapter validation.

## Remaining Gaps

- This binds adapter governance to the repository Policy Brain authority path.
  It does not create a live runtime policy lookup or mutate policy state.
- Gateway `/execute` to concrete adapter reconciliation binding remains outside
  this capability and remains a separate PB-E2E gap.
- Simulator-to-runtime proof binding remains outside this capability.

## Validation Commands

```text
python3.11 -m py_compile execution/adapters/base.py tests/test_execution_adapters.py
pytest -q tests/test_execution_adapters.py
pytest -q tests/test_gateway_app.py
git diff --check
git diff --cached --check
```
