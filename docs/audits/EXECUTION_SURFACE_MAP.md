# PB-INVENTORY-001 - Canonical Execution Surface Inventory

Date: 2026-06-20

## Canonical Authority

- Canonical execution gate authority: `gateway.app.canonical_execution_governance_gate`
- Canonical execution routing owner: `security.compute_router.route_execution`
- Canonical inventory source: this document's `canonical-execution-inventory` JSON block

## Canonical Inventory

```json canonical-execution-inventory
{
  "schema": "usbay.execution_surface_inventory.v1",
  "canonical_gate_authority": "gateway.app.canonical_execution_governance_gate",
  "canonical_routing_owner": "security.compute_router.route_execution",
  "duplicate_execution_paths": [],
  "orphan_execution_paths": [],
  "surfaces": [
    {
      "id": "http_execute_route",
      "file": "gateway/app.py",
      "symbol": "execute",
      "type": "http_route",
      "production": true,
      "canonical_gate": "gateway.app.canonical_execution_governance_gate",
      "routes_to": "security.compute_router.route_execution"
    },
    {
      "id": "gateway_decision_validation",
      "file": "gateway/app.py",
      "symbol": "validate_execution_decision",
      "type": "gateway_validation",
      "production": true,
      "canonical_gate": "gateway.app.canonical_execution_governance_gate",
      "routes_to": ""
    },
    {
      "id": "canonical_execution_gate",
      "file": "gateway/app.py",
      "symbol": "canonical_execution_governance_gate",
      "type": "canonical_gate",
      "production": true,
      "canonical_gate": "self",
      "routes_to": ""
    },
    {
      "id": "compute_route_execution",
      "file": "security/compute_router.py",
      "symbol": "route_execution",
      "type": "compute_router",
      "production": true,
      "canonical_gate": "security.compute_router.validate_canonical_gate_proof",
      "routes_to": "executors.*.execute"
    },
    {
      "id": "runtime_automation_request",
      "file": "runtime/enforcement_gateway.py",
      "symbol": "evaluate_automation_request",
      "type": "runtime_automation_entrypoint",
      "production": true,
      "canonical_gate": "runtime.enforcement_gateway._require_canonical_execution_gate",
      "routes_to": "runtime.enforcement_gateway._execute_automation"
    },
    {
      "id": "runtime_execute_automation_helper",
      "file": "runtime/enforcement_gateway.py",
      "symbol": "_execute_automation",
      "type": "runtime_automation_helper",
      "production": true,
      "canonical_gate": "runtime.enforcement_gateway._require_canonical_execution_gate",
      "routes_to": ""
    },
    {
      "id": "runtime_command_request",
      "file": "runtime/enforcement_gateway.py",
      "symbol": "evaluate_command_request",
      "type": "runtime_command_entrypoint",
      "production": true,
      "canonical_gate": "runtime.enforcement_gateway._require_canonical_execution_gate",
      "routes_to": "runtime.replit_executor.execute_command"
    },
    {
      "id": "execution_guard_execute_command",
      "file": "security/execution_guard.py",
      "symbol": "execute_command",
      "type": "guarded_cli_helper",
      "production": false,
      "canonical_gate": "gateway /decide + /execute",
      "routes_to": "security.execution_guard._run_command"
    }
  ]
}
```

## Inventory Summary

| Surface | Type | Production | Gate |
| --- | --- | --- | --- |
| HTTP `/execute` | HTTP route | yes | `canonical_execution_governance_gate` through `validate_execution_decision` |
| `validate_execution_decision` | gateway validation | yes | calls `canonical_execution_governance_gate` |
| `route_execution` | compute router | yes | requires `canonical_gate_proof` |
| `evaluate_automation_request` | runtime automation entrypoint | yes | calls `_require_canonical_execution_gate` |
| `_execute_automation` | runtime automation helper | yes | calls `_require_canonical_execution_gate` |
| `evaluate_command_request` | runtime command entrypoint | yes | calls `_require_canonical_execution_gate` |
| `security.execution_guard.execute_command` | guarded helper | no | goes through `/decide` and `/execute` before local command |

## Duplicate And Orphan Analysis

- Duplicate execution paths: none detected.
- Orphan execution paths: none detected.
- Direct `route_execution` call sites outside `security/compute_router.py`: `gateway/app.py` only, with `canonical_gate_proof`.

## Drift Validation

Static drift validation is enforced by `tests/test_gateway_app.py::test_execution_inventory_matches_static_call_graph`.
