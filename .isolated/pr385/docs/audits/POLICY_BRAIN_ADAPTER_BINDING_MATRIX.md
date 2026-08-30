# PB-E2E-002 - Policy Brain Adapter Binding Matrix

Date: 2026-06-22

## Canonical Binding Fields

| Field | Canonical source | Required state |
| --- | --- | --- |
| `policy_binding_id` | deterministic adapter/capability binding id | present and unique |
| `policy_binding_owner` | `runtime.policy_validator` | exact match |
| `policy_binding_reference` | `runtime/policy_validator.py#<adapter>.<capability>` | exact match |
| `policy_binding_lineage` | `docs/governance/AUDIT_LINEAGE_FRAMEWORK.md` | exact match |
| `policy_binding_status` | Policy Brain Binding Authority | `POLICY_BOUND` |
| `policy_binding_hash` | deterministic SHA-256 over binding material | exact match |

## Authority Boundary

| Boundary | Binding rule | Failure result |
| --- | --- | --- |
| Policy Brain to adapter declaration | adapter/capability must have a known declaration | `POLICY_BINDING_ORPHAN` |
| Policy Brain owner to adapter contract | owner must be `runtime.policy_validator` | `POLICY_OWNER_MISMATCH` |
| Policy Brain reference to adapter contract | reference must match adapter/capability binding | `POLICY_REFERENCE_MISMATCH` |
| Policy Brain lineage to audit framework | lineage must be present and canonical | `POLICY_LINEAGE_MISSING` |
| Policy Brain hash to adapter provenance | hash must bind current adapter provenance chain | `POLICY_HASH_MISMATCH` |
| Policy Brain binding freshness | status must be `POLICY_BOUND` | `POLICY_BINDING_STALE` |
| Policy Brain binding uniqueness | binding id cannot duplicate adapter authority ids | `POLICY_BINDING_DUPLICATE` |

## Adapter Binding Inventory

| Adapter | Capability | Policy binding owner | Policy reference | Status |
| --- | --- | --- | --- | --- |
| `browser` | `READ_ONLY_NAVIGATION` | `runtime.policy_validator` | `runtime/policy_validator.py#browser.read-only-navigation` | `POLICY_BOUND` |
| `filesystem` | `FILE_READ` | `runtime.policy_validator` | `runtime/policy_validator.py#filesystem.file-read` | `POLICY_BOUND` |
| `github` | `ISSUE_COMMENT_DRAFT` | `runtime.policy_validator` | `runtime/policy_validator.py#github.issue-comment-draft` | `POLICY_BOUND` |
| `github` | `PR_DESCRIPTION_DRAFT` | `runtime.policy_validator` | `runtime/policy_validator.py#github.pr-description-draft` | `POLICY_BOUND` |
| `shell` | `REPORT_GENERATION` | `runtime.policy_validator` | `runtime/policy_validator.py#shell.report-generation` | `POLICY_BOUND` |
| `shell` | `GOVERNANCE_STATUS_READ` | `runtime.policy_validator` | `runtime/policy_validator.py#shell.governance-status-read` | `POLICY_BOUND` |

## Reconciliation Position

```text
Policy Brain Binding Authority
  -> adapter provenance chain hash
  -> adapter reconciliation hash
  -> adapter action contract validation
  -> canonical execution gate proof validation
```

The adapter reconciliation hash now includes the Policy Brain binding hash. A
binding hash mismatch blocks the adapter contract, and any stale binding also
prevents the adapter from being treated as policy-authorized.

## No-Fake-Evidence Statement

This matrix does not assert that a live policy decision authorized a concrete
runtime execution request. It proves only the canonical adapter governance
binding to the existing repository Policy Brain authority path. Missing live
policy decision lineage remains outside this scoped capability and must be
treated as blocked wherever required.
