# PB-INVENTORY-001 - Canonical Gate Audit

Date: 2026-06-20

Canonical inventory source: `docs/audits/EXECUTION_SURFACE_MAP.md`

## Gate Matrix

| Execution surface | Gate proof | Runtime validation | Production readiness | Route execution |
| --- | --- | --- | --- | --- |
| HTTP `/execute` | from `validate_execution_decision` | `canonical_execution_governance_gate` | `canonical_execution_governance_gate` | `route_execution(..., canonical_gate_proof)` |
| Direct `route_execution` | required by `validate_canonical_gate_proof` | proof must be `VALID` | proof must be `READY` | blocks without proof |
| Runtime automation | `_require_canonical_execution_gate` | imported canonical gate | imported canonical gate | no compute router |
| Runtime command | `_require_canonical_execution_gate` | imported canonical gate | imported canonical gate | command executor only after gate |
| Execution guard helper | gateway `/decide` and `/execute` | delegated to gateway | delegated to gateway | local command only after gateway execute |

## Duplicate Paths

None detected in the canonical inventory.

## Orphan Paths

None detected in the canonical inventory.

## Fail-Closed Evidence

- `security.compute_router.route_execution` rejects missing proof.
- `runtime.enforcement_gateway._require_canonical_execution_gate` returns/raises blocked state when gate import or validation fails.
- `/execute` reaches `route_execution` only after `validate_execution_decision` attaches `_canonical_gate_proof`.

## Drift Test

`tests/test_gateway_app.py::test_execution_inventory_matches_static_call_graph`
