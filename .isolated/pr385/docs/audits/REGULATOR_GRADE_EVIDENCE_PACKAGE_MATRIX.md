# PB-E2E-006 - Regulator-Grade Evidence Package Matrix

Date: 2026-06-22

## Canonical Package Fields

| Field | Canonical source | Required state |
| --- | --- | --- |
| `regulator_package_id` | deterministic adapter/capability package id | present and unique |
| `regulator_package_owner` | `execution.adapters.base` | exact match |
| `regulator_package_reference` | `docs/audits/REGULATOR_GRADE_EVIDENCE_PACKAGE_MATRIX.md#<adapter>.<capability>` | exact match |
| `regulator_package_lineage` | `docs/audits/CANONICAL_E2E_EVIDENCE_HASH_AUDIT.md` | exact match |
| `regulator_package_status` | Regulator-Grade Evidence Packaging Authority | `REGULATOR_PACKAGE_VERIFIED` |
| `regulator_package_hash` | deterministic SHA-256 over package material | exact match |

## Package Hash Inputs

| Input | Bound evidence |
| --- | --- |
| Canonical E2E evidence hash | `e2e_evidence_hash` |
| Policy Brain binding reference | `policy_binding_reference` |
| Gateway binding reference | `gateway_binding_reference` |
| Simulator Runtime binding reference | `simulator_binding_reference` |
| Adapter Governance reference | adapter reconciliation material |
| Runtime Proof reference | `tests/test_runtime_parity_validator.py` |
| Audit evidence references | cross-layer evidence matrix and reconciliation proof references |

## Sensitive Data Exclusions

| Prohibited material | Package behavior |
| --- | --- |
| Raw payload markers | Block |
| Secrets | Block |
| Signatures | Block |
| Private keys | Block |
| Raw client IDs | Block |
| Bearer credentials | Block |
| Tokens | Block |

## Authority Boundary

| Boundary | Binding rule | Failure result |
| --- | --- | --- |
| Regulator package to adapter declaration | adapter/capability must have a known declaration | `REGULATOR_PACKAGE_ORPHAN` |
| Regulator package owner to adapter contract | owner must be `execution.adapters.base` | `REGULATOR_PACKAGE_OWNERSHIP_MISMATCH` |
| Regulator package source to adapter contract | source must match adapter/capability package reference | `REGULATOR_PACKAGE_SOURCE_MISMATCH` |
| Regulator package lineage to E2E evidence audit | lineage must be present and canonical | `REGULATOR_PACKAGE_LINEAGE_MISSING` |
| Regulator package hash to evidence chain | hash must bind E2E hash, adapter governance, runtime proof, and audit references | `REGULATOR_PACKAGE_HASH_MISMATCH` |
| Regulator package freshness | status must be `REGULATOR_PACKAGE_VERIFIED` | `REGULATOR_PACKAGE_STALE` |
| Regulator package uniqueness | package id cannot duplicate authority ids | `REGULATOR_PACKAGE_DUPLICATE` |
| Package data hygiene | package fields must not include sensitive markers | `REGULATOR_PACKAGE_SENSITIVE_DATA_PRESENT` |

## Adapter Package Inventory

| Adapter | Capability | Package owner | Package source | Package lineage | Status |
| --- | --- | --- | --- | --- | --- |
| `browser` | `READ_ONLY_NAVIGATION` | `execution.adapters.base` | `docs/audits/REGULATOR_GRADE_EVIDENCE_PACKAGE_MATRIX.md#browser.read-only-navigation` | `docs/audits/CANONICAL_E2E_EVIDENCE_HASH_AUDIT.md` | `REGULATOR_PACKAGE_VERIFIED` |
| `filesystem` | `FILE_READ` | `execution.adapters.base` | `docs/audits/REGULATOR_GRADE_EVIDENCE_PACKAGE_MATRIX.md#filesystem.file-read` | `docs/audits/CANONICAL_E2E_EVIDENCE_HASH_AUDIT.md` | `REGULATOR_PACKAGE_VERIFIED` |
| `github` | `ISSUE_COMMENT_DRAFT` | `execution.adapters.base` | `docs/audits/REGULATOR_GRADE_EVIDENCE_PACKAGE_MATRIX.md#github.issue-comment-draft` | `docs/audits/CANONICAL_E2E_EVIDENCE_HASH_AUDIT.md` | `REGULATOR_PACKAGE_VERIFIED` |
| `github` | `PR_DESCRIPTION_DRAFT` | `execution.adapters.base` | `docs/audits/REGULATOR_GRADE_EVIDENCE_PACKAGE_MATRIX.md#github.pr-description-draft` | `docs/audits/CANONICAL_E2E_EVIDENCE_HASH_AUDIT.md` | `REGULATOR_PACKAGE_VERIFIED` |
| `shell` | `REPORT_GENERATION` | `execution.adapters.base` | `docs/audits/REGULATOR_GRADE_EVIDENCE_PACKAGE_MATRIX.md#shell.report-generation` | `docs/audits/CANONICAL_E2E_EVIDENCE_HASH_AUDIT.md` | `REGULATOR_PACKAGE_VERIFIED` |
| `shell` | `GOVERNANCE_STATUS_READ` | `execution.adapters.base` | `docs/audits/REGULATOR_GRADE_EVIDENCE_PACKAGE_MATRIX.md#shell.governance-status-read` | `docs/audits/CANONICAL_E2E_EVIDENCE_HASH_AUDIT.md` | `REGULATOR_PACKAGE_VERIFIED` |

## Packaging Position

```text
Regulator-Grade Evidence Packaging Authority
  -> canonical E2E evidence hash
  -> policy binding reference
  -> gateway binding reference
  -> simulator/runtime binding reference
  -> adapter governance reconciliation material
  -> runtime proof reference
  -> audit evidence references
  -> non-sensitive regulator package hash
```

The regulator package hash is evidence-only. It proves that the current
governance evidence chain can be represented as one deterministic,
auditor-readable package while excluding sensitive material and avoiding any
live execution lineage claim.

## No-Fake-Evidence Statement

This matrix does not assert that a live execution request occurred, that
simulator output executed in runtime, or that a regulator package was externally
submitted. It proves only deterministic, non-sensitive regulator-grade packaging
for existing governance authority references. Missing live runtime lineage and
external regulator submission remain outside this scoped capability.
