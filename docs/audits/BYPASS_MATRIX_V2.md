# PB-INVENTORY-001 - Bypass Matrix V2

Date: 2026-06-20

Canonical inventory source: `docs/audits/EXECUTION_SURFACE_MAP.md`

| Bypass attempt | Expected result | Evidence |
| --- | --- | --- |
| Missing gate proof to `route_execution` | Block | `validate_canonical_gate_proof` requires proof |
| Direct `route_execution()` | Block unless proof is valid | static call graph permits only gateway call site |
| Blocked canonical proof | Block | proof status must be `READY`, runtime `VALID`, readiness `READY` |
| Runtime automation direct helper | Block unless proof/gate is ready | `_execute_automation` calls `_require_canonical_execution_gate` |
| Runtime command entrypoint | Block unless canonical gate is ready | `evaluate_command_request` calls `_require_canonical_execution_gate` before executor |
| Execution guard helper bypass | Block through gateway denial | helper posts `/decide` then `/execute` before local command |
| Duplicate inventory surface | Block in static test | inventory IDs must be unique |
| Orphan production execution path | Block in static test | production call graph must match inventory |

## Current Result

No verified bypass or orphan execution path remains in the scoped inventory.

## Drift Test

`tests/test_gateway_app.py::test_execution_inventory_matches_static_call_graph`
