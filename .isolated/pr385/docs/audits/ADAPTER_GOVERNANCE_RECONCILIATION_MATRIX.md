# PB-ADAPTER-010 - Adapter Governance Reconciliation Matrix

Date: 2026-06-21

## Authority Reconciliation Matrix

| Authority | Reconciled evidence | Required state |
| --- | --- | --- |
| Contract | `schema`, `contract_version`, `owner` | Present and canonical |
| Capability | `adapter_name`, `capability`, `action_types` | Declared and linked |
| Action Scope | `action_scope_id`, `action_scope_hash` | Hash matches declaration |
| Identity | `adapter_id`, `adapter_identity_hash`, `attestation_reference` | Identity matches declaration |
| Provenance | `provenance_chain_hash`, provenance references | Chain matches declaration |
| Registration | `registration_id`, `registration_state`, `registration_reference` | `ACTIVE` |
| Approval | `approval_id`, `approval_state`, `approval_reference` | `APPROVED` |
| Revocation | `revocation_id`, `revocation_reason`, `revocation_reference` | `NOT_REVOKED` |
| Consistency | `governance_consistency_status` | `CONSISTENT` |
| Reconciliation | `reconciliation_id`, `reconciliation_status`, `reconciliation_hash` | `RECONCILED` |

## Reconciliation Rules

| Rule | Failure result |
| --- | --- |
| every authority record must link to the same adapter | Block |
| every authority owner must be canonical | Block |
| every authority timestamp must match the reconciliation timestamp | Block |
| consistency conflicts must be resolved before reconciliation | Block |
| reconciliation hash must match current authority evidence | Block |
| reconciliation identifier must be unique | Block |
| missing authority linkage is unsafe | Block |
| orphan records are unsafe | Block |

## Enforcement Flow

```text
adapter.evaluate(request)
  -> validate_adapter_action_contract()
  -> per-authority validation
  -> validate_adapter_governance_consistency()
  -> validate_adapter_governance_reconciliation()
  -> canonical gate proof validation
  -> block on reconciliation drift
```

## Success Criteria

An adapter can continue validation only when all governance authorities are
present, synchronized, owned by the canonical adapter authority, linked to the
same adapter, free of stale state, free of unresolved conflicts, and reconciled
by the canonical reconciliation authority.
