# PB-E2E-005 - Canonical E2E Evidence Hash Audit

Date: 2026-06-22

## Scope

- `execution/adapters/base.py`
- `tests/test_execution_adapters.py`

This capability closes the PB-E2E evidence-hash gap for the adapter governance
layer by requiring every adapter action contract to carry a deterministic
end-to-end evidence hash before adapter governance validation can be considered
cross-layer reconciled.

No Replit runtime code, simulator implementation, travel/voucher behavior,
tenant logic, RFC3161 logic, lineage rewrite, connector write, deployment
behavior, policy mutation, execution record, or live execution lineage is
introduced.

## Canonical Authority

Canonical End-to-End Evidence Hash Authority:

`usbay.e2e.canonical_evidence_hash_authority`

Canonical owner:

`execution.adapters.base`

Canonical evidence source:

`docs/audits/CROSS_LAYER_GOVERNANCE_EVIDENCE_MATRIX.md`

Canonical evidence lineage:

`docs/audits/CROSS_LAYER_GOVERNANCE_RECONCILIATION_PROOF.md`

## Evidence Hash Model

Every adapter action contract must include:

- `e2e_evidence_hash_id`
- `e2e_evidence_hash_owner`
- `e2e_evidence_hash_reference`
- `e2e_evidence_hash_lineage`
- `e2e_evidence_hash_status`
- `e2e_evidence_hash`

Only `E2E_EVIDENCE_VERIFIED` allows adapter validation to continue without an
end-to-end evidence hash blocker.

## Deterministic Hash Derivation

The canonical hash binds:

- end-to-end evidence hash identifier
- end-to-end evidence owner
- end-to-end evidence reference
- end-to-end evidence lineage
- end-to-end evidence status
- Policy Brain Binding Authority
- policy binding hash
- Gateway Adapter Reconciliation Binding Authority
- gateway binding hash
- Simulator Runtime Proof Binding Authority
- simulator/runtime binding hash
- Adapter Governance Reconciliation Authority
- adapter reconciliation material
- gateway audit lineage reference
- simulator/runtime proof lineage reference
- canonical governance gate reference

This is an evidence-only hash. It proves that the participating governance
authorities and audit references belong to the same deterministic adapter
governance evidence chain. It does not prove live execution lineage.

## Fail-Closed Reason Codes

| Condition | Reason code |
| --- | --- |
| Missing evidence hash identifier, owner, status, or hash | `E2E_EVIDENCE_HASH_MISSING` |
| Missing evidence lineage | `E2E_EVIDENCE_LINEAGE_MISSING` |
| Missing evidence source reference | `E2E_EVIDENCE_SOURCE_MISSING` |
| Evidence hash status is not `E2E_EVIDENCE_VERIFIED` | `E2E_EVIDENCE_HASH_STALE` |
| Evidence hash exists for an unknown adapter/capability declaration | `E2E_EVIDENCE_HASH_ORPHAN` |
| Evidence hash identifier duplicates another authority identifier | `E2E_EVIDENCE_HASH_DUPLICATE` |
| Evidence source identifier or reference mismatch | `E2E_EVIDENCE_SOURCE_MISMATCH` |
| Evidence hash owner mismatch | `E2E_EVIDENCE_OWNERSHIP_MISMATCH` |
| Evidence hash mismatch | `E2E_EVIDENCE_HASH_MISMATCH` |

## Validation Path

```text
build_adapter_action_contract()
  -> attach canonical E2E evidence hash fields
  -> validate_adapter_action_contract()
  -> _e2e_evidence_hash_reasons()
  -> _simulator_binding_reasons()
  -> _gateway_binding_reasons()
  -> _policy_binding_reasons()
  -> validate_adapter_governance_consistency()
  -> validate_adapter_governance_reconciliation()
  -> validate_canonical_gate_proof()
  -> BLOCK on any evidence hash, authority binding, reconciliation, or gate proof failure
```

## Evidence Matrix

| Evidence | Coverage |
| --- | --- |
| `test_adapter_capability_map_has_single_canonical_owner` | published adapter map exposes E2E evidence hash authority, owner, source, lineage, status, and hash |
| `test_missing_e2e_evidence_hash_fails_closed` | missing hash id, owner, status, or hash blocks |
| `test_missing_e2e_evidence_source_fails_closed` | missing evidence source blocks |
| `test_missing_e2e_evidence_lineage_fails_closed` | missing evidence lineage blocks |
| `test_e2e_evidence_ownership_mismatch_fails_closed` | evidence owner drift blocks |
| `test_e2e_evidence_source_mismatch_fails_closed` | evidence source id/reference drift blocks |
| `test_e2e_evidence_hash_mismatch_fails_closed` | evidence hash drift blocks |
| `test_stale_e2e_evidence_hash_fails_closed` | non-`E2E_EVIDENCE_VERIFIED` status blocks |
| `test_duplicate_e2e_evidence_hash_fails_closed` | duplicate evidence hash identifier blocks |
| `test_orphan_e2e_evidence_hash_fails_closed` | unknown adapter/capability evidence hash blocks |
| `test_e2e_evidence_verified_adapter_contract_is_allowed` | canonical evidence hash succeeds when all authorities and gate proof are valid |
| `test_adapter_evaluate_blocks_missing_e2e_evidence_hash` | adapter evaluation blocks when E2E evidence hash is missing |

## No-Live-Execution-Lineage Statement

This audit does not invent execution records and does not claim live runtime
execution lineage. It proves deterministic, evidence-only chain membership
across Policy Brain, adapter governance, gateway binding, simulator/runtime
proof binding, runtime proof references, and audit evidence references.

## Fail-Closed Impact

No adapter governance evidence chain may be considered end-to-end verified
unless its adapter action contract includes an E2E evidence hash record owned by
`execution.adapters.base`, linked to the cross-layer evidence matrix and
reconciliation proof, in `E2E_EVIDENCE_VERIFIED` state, and backed by the
expected deterministic evidence hash.

Missing, stale, mismatched, orphaned, or duplicated E2E evidence hash records
block adapter validation.

## Remaining Gaps

- This proves deterministic chain membership for existing evidence references.
  It does not create live execution records.
- It does not claim live runtime execution lineage.
- External regulator-grade evidence packaging remains outside this scoped
  capability.

## Validation Commands

```text
python3.11 -m py_compile execution/adapters/base.py tests/test_execution_adapters.py
pytest -q tests/test_execution_adapters.py
pytest -q tests/test_gateway_app.py
git diff --check
git diff --cached --check
```
