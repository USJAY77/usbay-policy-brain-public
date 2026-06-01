# Claim-Level Traceability Matrix

Purpose: map architecture claims to authoritative GitHub source evidence, repository implementation evidence, test evidence, audit evidence, and current certification status.

Source audit: `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md`

Source-of-truth decision: `docs/architecture/SOURCE_OF_TRUTH_POLICY.md` records GitHub as the authoritative architecture source and records the inspected Notion architecture pages as title-only, non-authoritative placeholders.

Evidence rule: repository evidence only. Do not fabricate Notion source claims, source URLs, source hashes, WORM provider evidence, audit evidence, or certification claims.

Certification status: BLOCKED because BLOCKER-001 remains OPEN, BLOCKER-002 remains PARTIAL after reconciliation, and BLOCKER-003 remains OPEN.

## Status Definitions

- VERIFIED: authoritative GitHub source text, repository implementation evidence, test evidence, and audit evidence exist for the repository-side claim.
- PARTIAL: repository evidence exists, but source, audit, production, or certification evidence is incomplete.
- BLOCKED: required source evidence, implementation evidence, test evidence, audit evidence, external provider evidence, or certification evidence is missing for the claim.

## Mapping Rules

- Exact source claim text must come from authoritative GitHub repository documentation or implementation evidence.
- If evidence does not exist, use `Information not provided`.
- Human approval is not evidence.
- Local WORM readiness is not external WORM provider evidence.
- Missing evidence must fail closed.

## Matrix

| claim_id | authoritative GitHub source path | exact source claim text | implementation evidence | test evidence | audit evidence | status | missing evidence |
|---|---|---|---|---|---|---|---|
| ARCH-UEA-001 | `docs/runtime-deployment-governance.md` | "The runtime entrypoint is `gateway.app:app`. The deployment must bind to `0.0.0.0` and the platform-provided `PORT` environment variable only." | `docs/runtime-deployment-governance.md` defines the runtime deployment command and fail-closed startup rules. | `tests/test_deployment_provenance.py`; `tests/test_live_pilot_v1.py`; `tests/test_gateway_app.py` | `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md` verifies the deployment governance entrypoint and fail-closed startup requirements. | VERIFIED | Information not provided |
| ARCH-UEA-002 | `docs/architecture/USBAY_UNIVERSAL_EXECUTION_ARCHITECTURE.md` | "Execution validation checks decision ID, signatures, actor binding, algorithm version, replay state, nonce binding, decision time, Hydra/policy verification, execution routing, and mark-used semantics before allowing execution." | `gateway/app.py` contains execution validation and `/execute` routing. | `tests/test_gateway_app.py`; `tests/test_gateway_hydra.py` | `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md` records execution validation as verified current state. | VERIFIED | Information not provided |
| ARCH-HYDRA-001 | `docs/architecture/HYDRA_DEFENSE_STACK.md` | "`security/hydra_consensus.py` defines three expected nodes and two required votes." | `security/hydra_consensus.py` defines consensus validation, quorum, stale-node, policy hash, nonce, replay, and disagreement failure paths. | `tests/test_hydra_consensus.py`; `tests/test_hydra_stack.py`; `tests/test_gateway_hydra.py` | `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md` verifies Hydra consensus behavior and fail-closed outcomes. | VERIFIED | Production node identity, key custody, rotation, revocation, and remote transport evidence remain outside this claim and are not provided here. |
| ARCH-HYDRA-002 | `docs/architecture/HYDRA_DEFENSE_STACK.md` | "`security/hydra_nodes.py` collects node decisions from in-process, subprocess, and remote node clients." | `security/hydra_nodes.py` collects node decisions and converts unavailable nodes, missing nodes, invalid signatures, and node failures into deny decisions. | `tests/test_hydra_node_service.py`; `tests/test_hydra_live_client.py` | `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md` records node failure handling and remote-node governance gaps. | PARTIAL | Production remote endpoint identity, transport security, and node enrollment evidence are not provided. |
| ARCH-POLICY-001 | `docs/architecture/POLICY_BRAIN.md` | "`runtime/policy_validator.py` validates policy JSON, SHA256 digest, signature, and public key artifacts." | `runtime/policy_validator.py` validates required policy artifacts, approvals, evidence ruleset snapshot, runtime attestation, and audit ledger head. | `tests/test_policy_verification_workflow.py`; `tests/test_governance_policy_pack.py`; `tests/test_governance_policy_parity.py` | `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md` verifies policy validation fail-closed behavior. | VERIFIED | Information not provided |
| ARCH-POLICY-002 | `docs/governance-policy-parity.md` | "USBAY policy simulation is only rollout-safe when it can be proven to match the runtime enforcement outcome." | `governance/policy_parity.py` and `docs/governance-policy-parity.md` define parity validation and fail-closed rollout behavior. | `tests/test_governance_policy_parity.py` | `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md` records policy parity as a verified repository control. | VERIFIED | Information not provided |
| ARCH-GATEWAY-001 | `docs/architecture/ENFORCEMENT_GATEWAY.md` | "Invalid or unverifiable policy blocks governance action." | `runtime/enforcement_gateway.py` declares fail-closed guarantees for policy validation, device trust, audit append, and backend truth. | `tests/test_governance_architecture_boundaries.py`; `tests/test_gateway_app.py` | `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md` verifies enforcement gateway fail-closed guarantees. | VERIFIED | Information not provided |
| ARCH-GATEWAY-002 | `docs/architecture/ENFORCEMENT_GATEWAY.md` | "`gateway/app.py` exposes runtime health, governance evidence, execution validation, and execute routes." | `gateway/app.py` exposes runtime status, governance evidence, execution validation, and execute-route behavior; deny/fail-closed responses are returned for validation failures. | `tests/test_gateway_app.py`; `tests/test_gateway_hydra.py` | `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md` verifies gateway runtime behavior and execution validation. | VERIFIED | Information not provided |
| ARCH-AUDIT-001 | `docs/architecture/AUDIT_EVIDENCE_LAYER.md` | "`audit/hash_chain.py` appends audit events with previous/current hash continuity and verifies the chain." | `audit/hash_chain.py` appends audit events with `hash_prev` and `hash_current`, verifies chain continuity, and checks associated immutable ledger validity when present. | `tests/test_audit_hash_chain.py`; `tests/test_audit_integrity.py`; `tests/test_immutable_evidence_ledger.py` | `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md` verifies audit hash-chain behavior. | VERIFIED | Information not provided |
| ARCH-AUDIT-002 | `docs/governance-evidence-chain.md` | "USBAY evidence chains provide deterministic append-only continuity for governance proof bundles, local timestamp anchors, RFC3161 preflight requests, and WORM evidence manifests." | `docs/governance-evidence-chain.md` documents deterministic append-only evidence lifecycle, replay detection, chronology continuity limits, and future anchoring path. | `tests/test_governance_evidence_chain.py`; `tests/test_governance_evidence_record_chain.py`; `tests/test_governance_evidence_merkle_checkpoint.py` | `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md` verifies local evidence-chain continuity and notes external chronology limits. | VERIFIED | External time, independent witness consensus, and immutable storage durability evidence are not provided. |
| ARCH-WORM-001 | `docs/governance-worm-immutable-storage.md` | "This module does not write to real WORM storage, call cloud APIs, or export raw governance payloads." | `docs/governance-worm-immutable-storage.md` documents local-only WORM readiness; `governance/worm_immutable_storage.py` emits `LOCAL_ONLY` plans. | `tests/test_worm_evidence_archive.py`; `tests/test_governance_worm_evidence_manifest.py`; `tests/test_governance_worm_immutable_storage.py` | `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md` records external WORM as a gap; `docs/architecture/WORM_PILOT_PLAN.md` documents pilot-only next steps. | BLOCKED | External WORM provider/control evidence, retention class proof, legal hold model proof, immutable write proof, export verification evidence, provider audit receipt, and provider failure-mode audit are not provided. |
| ARCH-SOURCE-001 | `docs/architecture/SOURCE_OF_TRUTH_POLICY.md` | "GitHub is the authority for: Architecture source of truth." | `docs/architecture/SOURCE_OF_TRUTH_POLICY.md`, `docs/architecture/source/ARCHITECTURE_SOURCE_MANIFEST.md`, and `docs/architecture/ARCHITECTURE_CERTIFICATION_BLOCKERS.md` record GitHub authority and title-only Notion placeholder status. | Documentation review only; no runtime test applicable. | `docs/architecture/ARCHITECTURE_CERTIFICATION_BLOCKERS.md` records BLOCKER-001 reclassification and source-of-truth decision. | PARTIAL | Certification record closure for BLOCKER-001 is not provided; source authority evidence exists, but blocker lifecycle closure remains open. |

## Coverage Summary

Total claims: 12.

Verified claims: 9.

Partial claims: 2.

Blocked claims: 1.

Documentation-only source authority claim: 1. This claim is included in the partial claim count.

## Reconciliation Outcome

The matrix now uses GitHub repository documentation as the authoritative source for architecture claims.

BLOCKER-002 remains PARTIAL.

Reason: most repository-side claims now have authoritative GitHub source text, implementation evidence, test evidence, and audit evidence. BLOCKER-002 cannot close while `ARCH-HYDRA-002` remains partially mapped for production remote-node identity/transport evidence, `ARCH-WORM-001` remains blocked by BLOCKER-003 external WORM evidence, and `ARCH-SOURCE-001` remains partial pending certification lifecycle closure for BLOCKER-001.
