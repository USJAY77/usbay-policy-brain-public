# PB-E2E-001 - Cross-Layer Governance Evidence Matrix

Date: 2026-06-21

## Purpose

This matrix records what USBAY can currently prove across Policy Brain,
Adapter Governance, Gateway/Runtime Governance, Simulator Governance, and
Audit/Integrity evidence. Missing evidence is explicitly marked `GAP`.

## Evidence Matrix

| Evidence layer | Canonical or reviewed artifact | Linkage to next layer | Integrity evidence | Result |
| --- | --- | --- | --- | --- |
| Policy Brain decision | `tests/test_decide_first.py`, `tests/test_gateway_app.py`, `runtime/policy_validator.py` referenced by `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md` | Decision/audit fields exist in tests; no reviewed binding to adapter reconciliation record | `policy_hash`, `decision_id`, `audit_hash` tested in policy decision paths | PARTIAL |
| Adapter contract authority | `docs/audits/ADAPTER_CONTRACT_AUDIT.md` | Feeds adapter capability/action validation | Contract schema and owner validation documented | PRESENT |
| Adapter capability authority | `docs/audits/ADAPTER_CAPABILITY_ENFORCEMENT_AUDIT.md`, `docs/audits/ADAPTER_CAPABILITY_MAP.md` | Feeds action scope and gate proof requirements | Capability/action ownership documented | PRESENT |
| Adapter action scope authority | `docs/audits/ADAPTER_ACTION_SCOPE_AUDIT.md` | Restricts actions before adapter evaluation | Action scope hash documented in tests/audit | PRESENT |
| Adapter identity authority | `docs/audits/ADAPTER_IDENTITY_ATTESTATION_AUDIT.md` | Binds adapter identity before evaluation | `adapter_identity_hash` and attestation reference documented | PRESENT |
| Adapter provenance authority | `docs/audits/ADAPTER_PROVENANCE_CHAIN_AUDIT.md`, `docs/audits/ADAPTER_PROVENANCE_MAP.md` | Binds origin, owner, source, and attestation lineage | `provenance_chain_hash` documented | PRESENT |
| Adapter registration authority | `docs/audits/ADAPTER_REGISTRATION_AUTHORITY_AUDIT.md`, `docs/audits/ADAPTER_REGISTRATION_STATE_MAP.md` | Requires active registration before evaluation | Registration state/reference documented | PRESENT |
| Adapter approval authority | `docs/audits/ADAPTER_APPROVAL_AUTHORITY_AUDIT.md`, `docs/audits/ADAPTER_APPROVAL_FLOW_MAP.md` | Requires approval before evaluation | Approval state/reference documented | PRESENT |
| Adapter revocation authority | `docs/audits/ADAPTER_REVOCATION_AUTHORITY_AUDIT.md`, `docs/audits/ADAPTER_REVOCATION_FLOW_MAP.md` | Blocks revoked or malformed revocation states | Revocation reference documented | PRESENT |
| Adapter consistency authority | `docs/audits/ADAPTER_GOVERNANCE_CONSISTENCY_AUDIT.md`, `docs/audits/ADAPTER_GOVERNANCE_CONSISTENCY_MATRIX.md` | Requires cross-authority consistency before reconciliation | Consistency status and reason codes documented | PRESENT |
| Adapter reconciliation authority | `docs/audits/ADAPTER_GOVERNANCE_RECONCILIATION_AUDIT.md`, `docs/audits/ADAPTER_GOVERNANCE_RECONCILIATION_MATRIX.md` | Requires reconciled adapter governance before evaluation continues | `reconciliation_hash` documented | PRESENT |
| Gateway execution gate | `docs/audits/EXECUTION_SURFACE_MAP.md`, `docs/audits/CANONICAL_GATE_AUDIT.md`, `tests/test_gateway_app.py` | Routes only through `gateway.app.canonical_execution_governance_gate` and `security.compute_router.route_execution` | Static inventory and route proof tests documented | PRESENT |
| Runtime parity | `tests/test_runtime_parity_validator.py`, `governance/runtime_parity.py`, `governance/runtime_parity_validator.py` | Feeds canonical execution gate readiness | Runtime manifest/provenance corruption tests documented | PRESENT |
| Production readiness | `tests/test_production_readiness.py`, `governance/production_readiness.py` | Feeds canonical execution gate readiness | Readiness evidence package blockers tested | PRESENT |
| Execution bypass review | `docs/audits/BYPASS_MATRIX_V2.md`, `docs/audits/EXECUTION_TEST_GAPS.md` | Documents expected and actual block behavior for known bypass attempts | Test coverage matrix documented | PRESENT |
| Governance simulator | `tests/test_simulation_governance.py` | Simulator decisions are tested; no reviewed binding to runtime execution proof | Simulation policy hash/audit behavior appears in tests | PARTIAL |
| Audit lineage | `docs/governance/AUDIT_LINEAGE_FRAMEWORK.md` | Defines required lineage from decision through export/certification assessment | Hash requirements and missing-link detection documented | PRESENT |
| Cross-layer E2E proof hash | No reviewed canonical artifact found | Missing single record binding policy, adapter, gateway, runtime, simulator, audit, and integrity evidence | No single end-to-end hash found | GAP |

## Required Cross-Layer Fields

| Field | Current evidence | Status |
| --- | --- | --- |
| `policy_decision_id` | Decision tests cover `decision_id`; no cross-layer proof field found | GAP |
| `policy_hash` | Policy decision and gateway tests cover policy hash behavior | PRESENT |
| `adapter_reconciliation_id` | Adapter reconciliation docs define the field | PRESENT |
| `adapter_reconciliation_hash` | Adapter reconciliation docs define the hash | PRESENT |
| `gateway_gate_authority` | `gateway.app.canonical_execution_governance_gate` in execution inventory | PRESENT |
| `routing_owner` | `security.compute_router.route_execution` in execution inventory | PRESENT |
| `runtime_validation_status` | Runtime parity validator tests cover valid and blocked states | PRESENT |
| `production_readiness_status` | Production readiness tests cover ready and blocked states | PRESENT |
| `simulator_context_reference` | No reviewed cross-layer proof reference found | GAP |
| `audit_lineage_reference` | Lineage framework exists; one cross-layer binding record not found | GAP |
| `e2e_evidence_hash` | No reviewed single cross-layer hash found | GAP |

## Boundary Matrix

| Boundary | Evidence | Result |
| --- | --- | --- |
| Policy Brain to Adapter Governance | No concrete policy decision to adapter authority binding found | GAP |
| Adapter Governance to Gateway Gate | Adapter gate proof requirements exist; no concrete adapter reconciliation hash to `/execute` request binding found | GAP |
| Gateway Gate to Runtime Parity | Canonical gate and tests cover runtime validation blockers | PRESENT |
| Runtime Parity to Production Readiness | Readiness and runtime parity tests cover blocking behavior | PRESENT |
| Simulator to Runtime | Simulator tests exist; no simulator-to-runtime proof binding found | GAP |
| Audit/Lineage to Cross-Layer Proof | Lineage framework exists; single cross-layer proof artifact does not | GAP |

## No-Fake-Evidence Statement

This matrix does not create synthetic evidence IDs, hashes, approvals,
attestations, runtime contexts, simulator contexts, or policy decisions. Missing
artifacts are marked `GAP` and must be treated as blocked for end-to-end proof
acceptance.

## Fail-Closed Summary

Canonical evidence status: `GAP_BLOCKED`

The individual adapter and execution-gate controls remain documented as
fail-closed. The cross-layer proof is not complete until the `GAP` entries are
resolved by real repository evidence and validation.
