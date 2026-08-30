# PB-ADAPTER-009 - Adapter Governance Consistency Matrix

Date: 2026-06-21

## Authority Matrix

| Authority | Canonical owner | Required linkage | Drift result |
| --- | --- | --- | --- |
| Contract | `execution.adapters.base` | `schema`, `contract_version`, `owner` | Block |
| Capability | `execution.adapters.base` | `adapter_name`, `capability`, `action_types` | Block |
| Action Scope | `execution.adapters.base` | `action_scope_id`, `action_scope_hash` | Block |
| Identity | `execution.adapters.base` | `adapter_id`, `adapter_identity_hash`, `attestation_reference` | Block |
| Provenance | `execution.adapters.base` | `provenance_chain_hash`, provenance references | Block |
| Registration | `execution.adapters.base` | `registration_id`, `registration_state`, `registration_reference` | Block |
| Approval | `execution.adapters.base` | `approval_id`, `approval_state`, `approval_reference` | Block |
| Revocation | `execution.adapters.base` | `revocation_id`, `revocation_reason`, `revocation_reference` | Block |

## Consistency Rules

| Rule | Required state |
| --- | --- |
| Owner consistency | every authority owner equals `execution.adapters.base` |
| Reference consistency | every adapter authority reference includes the same adapter name |
| Capability/action consistency | requested action belongs to declared capability action set |
| Identity/provenance consistency | identity hash and provenance chain hash match canonical declaration |
| Registration/approval consistency | `APPROVED` approval requires `ACTIVE` registration |
| Approval/revocation consistency | `APPROVED` approval requires `NOT_REVOKED` revocation reason |
| Identifier consistency | authority identifiers are unique inside the contract |
| Linkage completeness | all required authority fields are present |

## Enforcement Flow

```text
adapter.evaluate(request)
  -> validate_adapter_action_contract()
  -> per-authority validation
  -> validate_adapter_governance_consistency()
  -> canonical gate proof validation
  -> block on any consistency drift
```

## Success Criteria

An adapter can continue validation only when all governance authorities are
present, internally consistent, owned by the canonical adapter authority, linked
to the same adapter, and free of duplicate authority identifiers.
