# PB-E2E-004 - Simulator Runtime Proof Binding Matrix

Date: 2026-06-22

## Canonical Binding Fields

| Field | Canonical source | Required state |
| --- | --- | --- |
| `simulator_binding_id` | deterministic adapter/capability binding id | present and unique |
| `simulator_binding_owner` | `tests.test_simulation_governance` | exact match |
| `simulator_binding_reference` | `tests/test_simulation_governance.py#<adapter>.<capability>` | exact match |
| `simulator_binding_lineage` | `tests/test_runtime_parity_validator.py` | exact match |
| `simulator_binding_status` | Simulator Runtime Proof Binding Authority | `SIMULATOR_RUNTIME_BOUND` |
| `simulator_binding_hash` | deterministic SHA-256 over binding material | exact match |

## Authority Boundary

| Boundary | Binding rule | Failure result |
| --- | --- | --- |
| Simulator evidence to adapter declaration | adapter/capability must have a known declaration | `SIMULATOR_BINDING_ORPHAN` |
| Simulator evidence owner to adapter contract | owner must be `tests.test_simulation_governance` | `SIMULATOR_OWNER_MISMATCH` |
| Simulator evidence reference to adapter contract | reference must match adapter/capability binding | `SIMULATOR_REFERENCE_MISMATCH` |
| Runtime proof lineage to adapter contract | lineage must be present and canonical | `SIMULATOR_LINEAGE_MISSING` |
| Simulator binding hash to runtime proof path | hash must bind current gateway binding and gate reference | `SIMULATOR_HASH_MISMATCH` |
| Simulator binding freshness | status must be `SIMULATOR_RUNTIME_BOUND` | `SIMULATOR_BINDING_STALE` |
| Simulator binding uniqueness | binding id cannot duplicate adapter authority ids | `SIMULATOR_BINDING_DUPLICATE` |

## Adapter Binding Inventory

| Adapter | Capability | Simulator evidence owner | Simulator reference | Runtime proof lineage | Status |
| --- | --- | --- | --- | --- | --- |
| `browser` | `READ_ONLY_NAVIGATION` | `tests.test_simulation_governance` | `tests/test_simulation_governance.py#browser.read-only-navigation` | `tests/test_runtime_parity_validator.py` | `SIMULATOR_RUNTIME_BOUND` |
| `filesystem` | `FILE_READ` | `tests.test_simulation_governance` | `tests/test_simulation_governance.py#filesystem.file-read` | `tests/test_runtime_parity_validator.py` | `SIMULATOR_RUNTIME_BOUND` |
| `github` | `ISSUE_COMMENT_DRAFT` | `tests.test_simulation_governance` | `tests/test_simulation_governance.py#github.issue-comment-draft` | `tests/test_runtime_parity_validator.py` | `SIMULATOR_RUNTIME_BOUND` |
| `github` | `PR_DESCRIPTION_DRAFT` | `tests.test_simulation_governance` | `tests/test_simulation_governance.py#github.pr-description-draft` | `tests/test_runtime_parity_validator.py` | `SIMULATOR_RUNTIME_BOUND` |
| `shell` | `REPORT_GENERATION` | `tests.test_simulation_governance` | `tests/test_simulation_governance.py#shell.report-generation` | `tests/test_runtime_parity_validator.py` | `SIMULATOR_RUNTIME_BOUND` |
| `shell` | `GOVERNANCE_STATUS_READ` | `tests.test_simulation_governance` | `tests/test_simulation_governance.py#shell.governance-status-read` | `tests/test_runtime_parity_validator.py` | `SIMULATOR_RUNTIME_BOUND` |

## Reconciliation Position

```text
Simulator Runtime Proof Binding Authority
  -> simulator governance evidence reference
  -> runtime parity proof lineage reference
  -> gateway binding hash
  -> adapter action contract validation
  -> canonical execution gate proof validation
```

The simulator binding hash includes the gateway binding hash. A simulator
binding hash mismatch blocks the adapter contract, and any stale simulator
binding prevents the evidence from being treated as runtime-proof-reconciled.

## No-Fake-Evidence Statement

This matrix does not assert that simulator evidence executed in runtime or that
a runtime request used simulator output. It proves only the canonical
evidence-bound reconciliation between simulator governance evidence and runtime
proof evidence references. Missing live runtime lineage remains outside this
scoped capability and must be treated as blocked wherever required.
