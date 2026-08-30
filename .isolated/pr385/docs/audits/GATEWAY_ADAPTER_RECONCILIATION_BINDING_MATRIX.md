# PB-E2E-003 - Gateway Adapter Reconciliation Binding Matrix

Date: 2026-06-22

## Canonical Binding Fields

| Field | Canonical source | Required state |
| --- | --- | --- |
| `gateway_binding_id` | deterministic adapter/capability binding id | present and unique |
| `gateway_binding_owner` | `gateway.app.canonical_execution_governance_gate` | exact match |
| `gateway_binding_reference` | `docs/audits/EXECUTION_SURFACE_MAP.md#<adapter>.<capability>` | exact match |
| `gateway_binding_lineage` | `docs/audits/CANONICAL_GATE_AUDIT.md` | exact match |
| `gateway_binding_status` | Gateway Adapter Reconciliation Binding Authority | `GATEWAY_RECONCILED` |
| `gateway_binding_hash` | deterministic SHA-256 over binding material | exact match |

## Authority Boundary

| Boundary | Binding rule | Failure result |
| --- | --- | --- |
| Gateway authority to adapter declaration | adapter/capability must have a known declaration | `GATEWAY_BINDING_ORPHAN` |
| Gateway owner to adapter contract | owner must be `gateway.app.canonical_execution_governance_gate` | `GATEWAY_OWNER_MISMATCH` |
| Gateway inventory reference to adapter contract | reference must match adapter/capability binding | `GATEWAY_REFERENCE_MISMATCH` |
| Gateway lineage to canonical gate audit | lineage must be present and canonical | `GATEWAY_LINEAGE_MISSING` |
| Gateway binding hash to adapter reconciliation | hash must bind current adapter reconciliation material | `GATEWAY_HASH_MISMATCH` |
| Gateway binding freshness | status must be `GATEWAY_RECONCILED` | `GATEWAY_BINDING_STALE` |
| Gateway binding uniqueness | binding id cannot duplicate adapter authority ids | `GATEWAY_BINDING_DUPLICATE` |

## Adapter Binding Inventory

| Adapter | Capability | Gateway binding owner | Gateway reference | Status |
| --- | --- | --- | --- | --- |
| `browser` | `READ_ONLY_NAVIGATION` | `gateway.app.canonical_execution_governance_gate` | `docs/audits/EXECUTION_SURFACE_MAP.md#browser.read-only-navigation` | `GATEWAY_RECONCILED` |
| `filesystem` | `FILE_READ` | `gateway.app.canonical_execution_governance_gate` | `docs/audits/EXECUTION_SURFACE_MAP.md#filesystem.file-read` | `GATEWAY_RECONCILED` |
| `github` | `ISSUE_COMMENT_DRAFT` | `gateway.app.canonical_execution_governance_gate` | `docs/audits/EXECUTION_SURFACE_MAP.md#github.issue-comment-draft` | `GATEWAY_RECONCILED` |
| `github` | `PR_DESCRIPTION_DRAFT` | `gateway.app.canonical_execution_governance_gate` | `docs/audits/EXECUTION_SURFACE_MAP.md#github.pr-description-draft` | `GATEWAY_RECONCILED` |
| `shell` | `REPORT_GENERATION` | `gateway.app.canonical_execution_governance_gate` | `docs/audits/EXECUTION_SURFACE_MAP.md#shell.report-generation` | `GATEWAY_RECONCILED` |
| `shell` | `GOVERNANCE_STATUS_READ` | `gateway.app.canonical_execution_governance_gate` | `docs/audits/EXECUTION_SURFACE_MAP.md#shell.governance-status-read` | `GATEWAY_RECONCILED` |

## Reconciliation Position

```text
Gateway Adapter Reconciliation Binding Authority
  -> adapter reconciliation material
  -> adapter reconciliation hash
  -> adapter action contract validation
  -> canonical execution gate proof validation
```

The adapter reconciliation hash includes the gateway binding hash. A gateway
binding hash mismatch blocks the adapter contract, and any stale gateway binding
prevents the adapter from being treated as gateway-reconciled.

## No-Fake-Evidence Statement

This matrix does not assert that a live gateway `/execute` request authorized a
concrete adapter action. It proves only the canonical adapter governance binding
to the existing repository gateway execution authority path. Missing live
execution lineage remains outside this scoped capability and must be treated as
blocked wherever required.
