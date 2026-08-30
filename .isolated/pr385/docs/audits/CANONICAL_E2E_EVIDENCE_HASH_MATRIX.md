# PB-E2E-005 - Canonical E2E Evidence Hash Matrix

Date: 2026-06-22

## Canonical Evidence Hash Fields

| Field | Canonical source | Required state |
| --- | --- | --- |
| `e2e_evidence_hash_id` | deterministic adapter/capability evidence-chain id | present and unique |
| `e2e_evidence_hash_owner` | `execution.adapters.base` | exact match |
| `e2e_evidence_hash_reference` | `docs/audits/CROSS_LAYER_GOVERNANCE_EVIDENCE_MATRIX.md#<adapter>.<capability>` | exact match |
| `e2e_evidence_hash_lineage` | `docs/audits/CROSS_LAYER_GOVERNANCE_RECONCILIATION_PROOF.md` | exact match |
| `e2e_evidence_hash_status` | Canonical E2E Evidence Hash Authority | `E2E_EVIDENCE_VERIFIED` |
| `e2e_evidence_hash` | deterministic SHA-256 over cross-layer evidence material | exact match |

## Hash Inputs

| Input | Bound evidence |
| --- | --- |
| Policy Brain Binding Authority | `POLICY_BRAIN_BINDING_AUTHORITY` and `policy_binding_hash` |
| Gateway Binding Authority | `GATEWAY_ADAPTER_BINDING_AUTHORITY` and `gateway_binding_hash` |
| Simulator Runtime Binding Authority | `SIMULATOR_RUNTIME_BINDING_AUTHORITY` and `simulator_binding_hash` |
| Adapter Governance Evidence | `ADAPTER_GOVERNANCE_RECONCILIATION_AUTHORITY` and adapter reconciliation material |
| Runtime Governance Evidence | gateway lineage and simulator/runtime proof lineage references |
| Audit Evidence References | cross-layer evidence matrix and reconciliation proof references |

## Authority Boundary

| Boundary | Binding rule | Failure result |
| --- | --- | --- |
| E2E hash to adapter declaration | adapter/capability must have a known declaration | `E2E_EVIDENCE_HASH_ORPHAN` |
| E2E hash owner to adapter contract | owner must be `execution.adapters.base` | `E2E_EVIDENCE_OWNERSHIP_MISMATCH` |
| E2E evidence source to adapter contract | source must match adapter/capability evidence reference | `E2E_EVIDENCE_SOURCE_MISMATCH` |
| E2E evidence lineage to reconciliation proof | lineage must be present and canonical | `E2E_EVIDENCE_LINEAGE_MISSING` |
| E2E hash to cross-layer authorities | hash must bind policy, gateway, simulator, adapter, runtime, and audit evidence | `E2E_EVIDENCE_HASH_MISMATCH` |
| E2E evidence freshness | status must be `E2E_EVIDENCE_VERIFIED` | `E2E_EVIDENCE_HASH_STALE` |
| E2E evidence uniqueness | evidence hash id cannot duplicate authority ids | `E2E_EVIDENCE_HASH_DUPLICATE` |

## Adapter Evidence Hash Inventory

| Adapter | Capability | Evidence owner | Evidence source | Evidence lineage | Status |
| --- | --- | --- | --- | --- | --- |
| `browser` | `READ_ONLY_NAVIGATION` | `execution.adapters.base` | `docs/audits/CROSS_LAYER_GOVERNANCE_EVIDENCE_MATRIX.md#browser.read-only-navigation` | `docs/audits/CROSS_LAYER_GOVERNANCE_RECONCILIATION_PROOF.md` | `E2E_EVIDENCE_VERIFIED` |
| `filesystem` | `FILE_READ` | `execution.adapters.base` | `docs/audits/CROSS_LAYER_GOVERNANCE_EVIDENCE_MATRIX.md#filesystem.file-read` | `docs/audits/CROSS_LAYER_GOVERNANCE_RECONCILIATION_PROOF.md` | `E2E_EVIDENCE_VERIFIED` |
| `github` | `ISSUE_COMMENT_DRAFT` | `execution.adapters.base` | `docs/audits/CROSS_LAYER_GOVERNANCE_EVIDENCE_MATRIX.md#github.issue-comment-draft` | `docs/audits/CROSS_LAYER_GOVERNANCE_RECONCILIATION_PROOF.md` | `E2E_EVIDENCE_VERIFIED` |
| `github` | `PR_DESCRIPTION_DRAFT` | `execution.adapters.base` | `docs/audits/CROSS_LAYER_GOVERNANCE_EVIDENCE_MATRIX.md#github.pr-description-draft` | `docs/audits/CROSS_LAYER_GOVERNANCE_RECONCILIATION_PROOF.md` | `E2E_EVIDENCE_VERIFIED` |
| `shell` | `REPORT_GENERATION` | `execution.adapters.base` | `docs/audits/CROSS_LAYER_GOVERNANCE_EVIDENCE_MATRIX.md#shell.report-generation` | `docs/audits/CROSS_LAYER_GOVERNANCE_RECONCILIATION_PROOF.md` | `E2E_EVIDENCE_VERIFIED` |
| `shell` | `GOVERNANCE_STATUS_READ` | `execution.adapters.base` | `docs/audits/CROSS_LAYER_GOVERNANCE_EVIDENCE_MATRIX.md#shell.governance-status-read` | `docs/audits/CROSS_LAYER_GOVERNANCE_RECONCILIATION_PROOF.md` | `E2E_EVIDENCE_VERIFIED` |

## Reconciliation Position

```text
Canonical E2E Evidence Hash Authority
  -> Policy Brain binding hash
  -> Gateway binding hash
  -> Simulator/runtime binding hash
  -> Adapter governance reconciliation material
  -> Runtime proof references
  -> Audit evidence references
  -> adapter action contract validation
```

The E2E evidence hash is evidence-only. It proves that all participating
governance authorities belong to one deterministic evidence chain, and blocks
adapter validation when any chain member or audit reference drifts.

## No-Fake-Evidence Statement

This matrix does not assert that a live execution request occurred, that
simulator output executed in runtime, or that a runtime request used simulator
output. It proves only canonical evidence-chain membership for existing
governance authority references. Missing live runtime lineage remains outside
this scoped capability and must be treated as blocked wherever required.
