# PB-E2E-001 - Cross-Layer Governance Reconciliation Proof

Date: 2026-06-21

## Scope

This audit reconciles repository evidence across:

- Policy Brain and policy validation evidence
- Adapter Governance Authorities
- Gateway and runtime execution gate evidence
- Governance simulator evidence
- Audit, lineage, and hash/integrity evidence

This document is read-only audit evidence. It does not change runtime behavior,
adapter behavior, simulator behavior, tenant logic, RFC3161 logic, lineage
logic, deployment behavior, connector behavior, or policy semantics.

## Canonical Result

Status: `GAP_BLOCKED`

USBAY has documented and tested evidence for several individual layers, but the
repository does not yet contain a single executable cross-layer evidence record
that cryptographically binds a Policy Brain decision, adapter authority chain,
gateway/runtime gate result, simulator context, audit evidence, and integrity
hash into one end-to-end proof.

Fail-closed interpretation: missing cross-layer linkage is not approval. Any
consumer requiring an end-to-end governance proof must treat unresolved `GAP`
entries as blocked until separately remediated and validated.

## Evidence Inventory

| Layer | Repository evidence | Status |
| --- | --- | --- |
| Adapter governance authorities | `docs/audits/ADAPTER_CONTRACT_AUDIT.md`, `docs/audits/ADAPTER_CAPABILITY_ENFORCEMENT_AUDIT.md`, `docs/audits/ADAPTER_ACTION_SCOPE_AUDIT.md`, `docs/audits/ADAPTER_IDENTITY_ATTESTATION_AUDIT.md`, `docs/audits/ADAPTER_PROVENANCE_CHAIN_AUDIT.md`, `docs/audits/ADAPTER_REGISTRATION_AUTHORITY_AUDIT.md`, `docs/audits/ADAPTER_REVOCATION_AUTHORITY_AUDIT.md`, `docs/audits/ADAPTER_APPROVAL_AUTHORITY_AUDIT.md`, `docs/audits/ADAPTER_GOVERNANCE_CONSISTENCY_AUDIT.md`, `docs/audits/ADAPTER_GOVERNANCE_RECONCILIATION_AUDIT.md` | PRESENT |
| Adapter authority matrix | `docs/audits/ADAPTER_GOVERNANCE_RECONCILIATION_MATRIX.md` | PRESENT |
| Gateway execution inventory | `docs/audits/EXECUTION_SURFACE_MAP.md` | PRESENT |
| Gateway gate audit | `docs/audits/CANONICAL_GATE_AUDIT.md` | PRESENT |
| Execution bypass matrix | `docs/audits/BYPASS_MATRIX_V2.md` | PRESENT |
| Runtime parity and readiness tests | `tests/test_runtime_parity_validator.py`, `tests/test_production_readiness.py`, `tests/test_gateway_app.py` | PRESENT |
| Policy decision and audit export tests | `tests/test_decide_first.py`, `tests/test_gateway_app.py` | PARTIAL |
| Governance simulator tests | `tests/test_simulation_governance.py` | PARTIAL |
| Audit lineage framework | `docs/governance/AUDIT_LINEAGE_FRAMEWORK.md` | PRESENT |
| Architecture-level Policy Brain notes | `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md` | PARTIAL |

## Cross-Layer Reconciliation Chain

Target proof chain:

```text
policy decision
  -> adapter authority chain
  -> gateway canonical execution gate
  -> runtime validation and production readiness
  -> audit/lineage evidence
  -> hash/integrity evidence
```

Observed repository state:

| Link | Evidence | Result |
| --- | --- | --- |
| Policy decision to audit evidence | Decision and export tests assert `decision_id`, `policy_hash`, and `audit_hash` fields in `tests/test_decide_first.py` and `tests/test_gateway_app.py`. | PARTIAL |
| Policy decision to adapter authority chain | No reviewed artifact binds a specific Policy Brain decision ID to a specific adapter reconciliation record. | GAP |
| Adapter authority chain | PB-ADAPTER-001 through PB-ADAPTER-010 audit docs and tests define contract, capability, action scope, identity, provenance, registration, approval, revocation, consistency, and reconciliation authorities. | PRESENT |
| Adapter chain to gateway gate | Adapter tests validate required canonical gate proof, but no reviewed end-to-end artifact binds one adapter reconciliation hash to one gateway `/execute` request. | GAP |
| Gateway gate to routing owner | `docs/audits/EXECUTION_SURFACE_MAP.md` and `docs/audits/CANONICAL_GATE_AUDIT.md` identify `gateway.app.canonical_execution_governance_gate` and `security.compute_router.route_execution`. | PRESENT |
| Runtime parity and readiness | `tests/test_runtime_parity_validator.py`, `tests/test_production_readiness.py`, and `tests/test_gateway_app.py` cover blocked runtime parity, blocked readiness, corrupted lineage, revoked runtime, stale attestation, replay, duplicate ownership, and duplicate reason-code blockers. | PRESENT |
| Runtime context reference in one proof record | No reviewed artifact records the runtime context reference in the same proof object as the adapter authority chain and Policy Brain decision. | GAP |
| Simulator evidence to runtime proof | `tests/test_simulation_governance.py` covers simulation policy and audit behavior, but no reviewed cross-layer proof binds simulator evidence to a gateway/runtime execution decision. | GAP |
| Audit lineage | `docs/governance/AUDIT_LINEAGE_FRAMEWORK.md` defines decision, evidence, validation, review, export, and certification lineage requirements. | PRESENT |
| End-to-end evidence hash | Adapter identity/provenance/reconciliation hashes exist; decision and audit hashes exist in tests. No reviewed single hash binds all cross-layer evidence into one canonical end-to-end record. | GAP |

## GAP Register

| Gap | Description | Fail-closed treatment |
| --- | --- | --- |
| `GAP_POLICY_BRAIN_LINKAGE` | No canonical artifact links a Policy Brain decision to adapter authority reconciliation evidence. | Block end-to-end proof acceptance |
| `GAP_GATEWAY_LINKAGE` | No canonical artifact links a concrete gateway `/execute` request to a concrete adapter reconciliation record. | Block end-to-end proof acceptance |
| `GAP_RUNTIME_CONTEXT_REFERENCE` | Runtime parity/readiness evidence is tested, but not bound into one cross-layer proof object. | Block end-to-end proof acceptance |
| `GAP_SIMULATOR_CONTEXT_LINKAGE` | Simulator evidence exists in tests, but is not bound to runtime execution evidence. | Block simulator-to-runtime proof acceptance |
| `GAP_END_TO_END_EVIDENCE_HASH` | No single canonical hash binds policy, adapter, gateway, runtime, audit, and integrity evidence. | Block cryptographic E2E proof claims |
| `GAP_AUDIT_DOC_REGISTRY` | Audit documents exist, but there is no reviewed canonical audit index for cross-layer proof freshness. | Treat stale/orphan audit freshness as unproven |
| `GAP_AUTHORITY_BOUNDARY_DOCUMENTATION` | Adapter authorities are documented; cross-boundary ownership between Policy Brain, adapter, gateway, runtime, and simulator remains partly undocumented. | Block authority-boundary certification |

## Stale Or Orphan Audit Review

The following audit docs are referenced as current evidence for this proof:

- `docs/audits/ADAPTER_GOVERNANCE_RECONCILIATION_AUDIT.md`
- `docs/audits/ADAPTER_GOVERNANCE_RECONCILIATION_MATRIX.md`
- `docs/audits/EXECUTION_SURFACE_MAP.md`
- `docs/audits/CANONICAL_GATE_AUDIT.md`
- `docs/audits/BYPASS_MATRIX_V2.md`
- `docs/audits/EXECUTION_TEST_GAPS.md`
- `docs/governance/AUDIT_LINEAGE_FRAMEWORK.md`

No fake evidence identifiers are introduced by this audit. Where a concrete
artifact binding was not found, the result is recorded as `GAP`.

## Fail-Closed Impact

- This proof does not enable execution.
- This proof does not approve adapters.
- This proof does not approve simulator output.
- This proof does not certify production readiness.
- This proof records unresolved cross-layer evidence as blocked.

Any downstream process that requires a complete cross-layer proof must deny or
defer approval while `GAP_BLOCKED` remains the canonical result.

## Validation Evidence

Required validation for this audit:

```text
python3.11 -m py_compile tests/test_gateway_app.py tests/test_execution_adapters.py tests/test_runtime_parity_validator.py tests/test_production_readiness.py
pytest -q tests/test_gateway_app.py
pytest -q tests/test_execution_adapters.py
pytest -q tests/test_runtime_parity_validator.py
pytest -q tests/test_production_readiness.py -k "consolidation_production_readiness or production_readiness_evidence_package_blocks"
git diff --check
git diff --cached --check
```
