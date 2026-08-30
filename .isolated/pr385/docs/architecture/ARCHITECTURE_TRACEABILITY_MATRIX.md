# USBAY Architecture Traceability Matrix

Matrix date: 2026-06-01

Evidence rule: repository evidence only. The requested Notion pages were not available in the active tool context, so Notion claims remain unverified until exported.

## Traceability Matrix

| Notion Source | Repository File | Code Evidence | Test Evidence | Status |
|---|---|---|---|---|
| USBAY Universal Execution Architecture | `docs/runtime-deployment-governance.md` | Documents `gateway.app:app` deployment entrypoint and fail-closed startup rules. | Deployment and gateway tests require runtime startup alignment. | PARTIAL: repository evidence verified; Notion source unavailable |
| USBAY Universal Execution Architecture | `gateway/app.py` | `validate_execution_decision()` and `/execute` validate signed decisions, replay state, actor binding, nonce binding, policy/Hydra verification, and mark-used semantics. | `tests/test_gateway_app.py`, `tests/test_gateway_hydra.py` | PARTIAL: repository evidence verified; Notion source unavailable |
| USBAY Universal Execution Architecture | `runtime/enforcement_gateway.py` | Declares fail-closed governance enforcement gateway guarantees. | Runtime/enforcement validation tests in repository. | PARTIAL: repository evidence verified; Notion source unavailable |
| Hydra Defense Stack | `security/hydra_consensus.py` | Defines expected nodes, required votes, consensus evidence, and fail-closed reasons for quorum, stale node, policy mismatch, replay divergence, and disagreement. | `tests/test_hydra_consensus.py`, `tests/test_hydra_stack.py`, `tests/test_gateway_hydra.py` | PARTIAL: repository evidence verified; Notion source unavailable |
| Hydra Defense Stack | `security/hydra_nodes.py` | Collects in-process, subprocess, and remote node decisions; converts node errors, missing nodes, and invalid signatures into deny decisions. | `tests/test_hydra_node_service.py`, `tests/test_hydra_live_client.py` | PARTIAL: repository evidence verified; Notion source unavailable |
| Policy Brain | `runtime/policy_validator.py` | Validates policy files, policy hash, signature, public key, approvals, evidence snapshot, and runtime attestation artifacts. | `tests/test_policy_verification_workflow.py`, policy validation tests in repository. | PARTIAL: repository evidence verified; Notion source unavailable |
| Policy Brain | `docs/governance-policy-parity.md` | Documents simulation/runtime parity and fail-closed rollout behavior. | `tests/test_governance_policy_parity.py` | PARTIAL: repository evidence verified; Notion source unavailable |
| Policy Brain | `governance/policy_registry.json` | Provides repository policy registry evidence surface. | Policy registry startup and workflow tests in repository. | PARTIAL: repository evidence verified; Notion source unavailable |
| Enforcement Gateway | `gateway/app.py` | Exposes runtime status, governance evidence, execution validation, and execute route behavior. | `tests/test_gateway_app.py` | PARTIAL: repository evidence verified; Notion source unavailable |
| Enforcement Gateway | `docs/runtime-deployment-governance.md` | Defines production command constraints and fail-closed deployment startup behavior. | Deployment provenance/live-pilot tests in repository. | PARTIAL: repository evidence verified; Notion source unavailable |
| Audit & Evidence Layer | `audit/hash_chain.py` | Appends audit events with `hash_prev` and `hash_current`; verifies chain continuity and immutable ledger validity. | `tests/test_audit_hash_chain.py`, `tests/test_audit_integrity.py` | PARTIAL: repository evidence verified; Notion source unavailable |
| Audit & Evidence Layer | `audit/immutable_ledger.py` | Provides immutable evidence event ledger support. | `tests/test_immutable_evidence_ledger.py` | PARTIAL: repository evidence verified; Notion source unavailable |
| Audit & Evidence Layer | `docs/governance-evidence-chain.md` | Documents deterministic append-only evidence lifecycle, replay detection, and future anchoring path. | `tests/test_governance_evidence_chain.py`, `tests/test_governance_evidence_record_chain.py` | PARTIAL: repository evidence verified; Notion source unavailable |
| Audit & Evidence Layer | `docs/governance-worm-immutable-storage.md` | Documents local-only WORM readiness, fail-closed conditions, and future external WORM integration boundary. | `tests/test_worm_evidence_archive.py`, `tests/test_governance_worm_evidence_manifest.py` | PARTIAL: repository evidence verified; Notion source unavailable |
| Audit & Evidence Layer | `docs/pilot/USBAY_ENTERPRISE_AUDIT_OVERVIEW.md` | Documents pilot evidence-pack, offline verification, signer continuity, and fail-closed evidence behavior. | `tests/test_offline_evidence_verifier.py` | PARTIAL: repository evidence verified; Notion source unavailable |

## Gaps

- Notion source documents are not exported or hashed.
- No claim-level Notion-to-code traceability can be certified until source text is available.
- No local evidence proves Notion page versions, authorship, timestamps, or approval state.
- Production certification must remain blocked until architecture source parity is proven.

## Required Remediation

1. Export each Notion architecture page to Markdown.
2. Record Notion page title, version, export date, source URL or ID, and content hash.
3. Replace source-unavailable architecture files with exact exported content plus repository reconciliation notes.
4. Update this matrix with claim-level mappings from Notion text to repository files, code evidence, and tests.
5. Keep any unmapped architecture claim blocked until implementation and test evidence exists.

## Certification Decision

Decision: BLOCKED.

Reason: Notion source evidence unavailable.
