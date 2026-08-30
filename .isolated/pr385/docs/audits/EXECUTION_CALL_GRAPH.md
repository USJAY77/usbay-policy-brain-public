# PB-INVENTORY-001 - Execution Call Graph

Date: 2026-06-20

Canonical inventory source: `docs/audits/EXECUTION_SURFACE_MAP.md`

```mermaid
flowchart TD
  A["POST /execute"] --> B["validate_execution_decision(payload)"]
  B --> C["decision id, signature, actor, nonce, request hash"]
  C --> D["runtime nonce replay validation"]
  D --> E["runtime attestation freshness"]
  E --> F["runtime revocation registry/state"]
  F --> G["canonical_execution_governance_gate"]
  G --> H["runtime_validation_report"]
  G --> I["production_readiness_evidence_package"]
  H --> J{"runtime VALID?"}
  I --> K{"readiness READY?"}
  J -->|no| X["403 deny"]
  K -->|no| X
  J -->|yes| L["attach _canonical_gate_proof"]
  K -->|yes| L
  L --> M["verify(payload)"]
  M -->|pass| N["route_execution(..., canonical_gate_proof)"]
  N --> O["validate_canonical_gate_proof"]
  O --> P["validate_compute_request"]
  P --> Q["executor.execute"]
  Q --> R["mark_decision_used"]
```

```mermaid
flowchart TD
  A["evaluate_command_request"] --> B["validate_signed_policy"]
  B --> C["generate_runtime_attestation"]
  C --> D["validate_runtime_attestation"]
  D --> E["validate_audit_chain"]
  E --> F["_require_canonical_execution_gate"]
  F -->|blocked| X["deny audit event"]
  F -->|ready| G["_enforce_zero_trust_device"]
  G --> H["_generate_action_token"]
  H --> I["runtime.replit_executor.execute_command"]
```

```mermaid
flowchart TD
  A["evaluate_automation_request"] --> B["validate_signed_policy"]
  B --> C["generate_runtime_attestation"]
  C --> D["_validate_automation_request"]
  D --> E["_validate_automation_context"]
  E --> F["_require_canonical_execution_gate"]
  F -->|blocked| X["deny audit event"]
  F -->|ready| G["_execute_automation(..., canonical_gate_proof)"]
  G --> H["_require_canonical_execution_gate(proof)"]
```

## Static Evidence

- `gateway/app.py`: `/execute`, `validate_execution_decision`, `canonical_execution_governance_gate`
- `security/compute_router.py`: `route_execution`, `validate_canonical_gate_proof`
- `runtime/enforcement_gateway.py`: `evaluate_automation_request`, `_execute_automation`, `evaluate_command_request`
- `security/execution_guard.py`: `execute_command` helper routes through gateway `/decide` and `/execute`

## Drift Test

`tests/test_gateway_app.py::test_execution_inventory_matches_static_call_graph`
