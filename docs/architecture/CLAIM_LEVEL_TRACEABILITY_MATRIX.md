# Claim-Level Traceability Matrix

Purpose: map architecture claims to repository implementation evidence, test evidence, and missing certification evidence after PR #133.

Source audit: `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md`

Evidence rule: repository evidence only. Do not fabricate Notion source claims, source URLs, source hashes, WORM provider evidence, or certification claims.

Certification status: BLOCKED because Notion source exports and external WORM provider evidence are not present.

## Status Definitions

- VERIFIED: repository implementation evidence and test evidence exist for the repository-side claim.
- PARTIAL: repository evidence exists, but required source, audit, or production evidence is incomplete.
- BLOCKED: required source evidence, implementation evidence, test evidence, or certification evidence is missing for the certification claim.

## Mapping Rules

- Exact source claim text must come from exported Notion Markdown. If the source text is unavailable, use `Information not provided`.
- Source document path must point to the expected source export path under `docs/architecture/source/`.
- Human approval is not evidence.
- Local WORM readiness is not external WORM provider evidence.
- Missing evidence must fail closed.

## Matrix

| claim_id | exact source claim text | source document path | repository implementation evidence | test evidence | status | missing evidence |
|---|---|---|---|---|---|---|
| ARCH-UEA-001 | Information not provided | `docs/architecture/source/USBAY_UNIVERSAL_EXECUTION_ARCHITECTURE.md` | `docs/runtime-deployment-governance.md` documents `gateway.app:app` as runtime deployment entrypoint and requires platform `PORT`, `0.0.0.0`, no hardcoded/default port fallback, no duplicate startup paths, and fail-closed startup behavior. | `tests/test_deployment_provenance.py`; `tests/test_live_pilot_v1.py`; `tests/test_gateway_app.py` | PARTIAL | Exported Notion source text, source URL/page ID, version identifier, content hash, source approval evidence. |
| ARCH-UEA-002 | Information not provided | `docs/architecture/source/USBAY_UNIVERSAL_EXECUTION_ARCHITECTURE.md` | `gateway/app.py` contains `validate_execution_decision()` and `/execute`; execution validation checks decision ID, submitted decision signatures, actor binding, algorithm version, replay state, decision time, nonce binding, Hydra/policy verification, execution routing, and mark-used behavior. | `tests/test_gateway_app.py`; `tests/test_gateway_hydra.py` | PARTIAL | Exported Notion source text, source metadata, claim-to-code approval evidence, audit artifact proving source parity. |
| ARCH-HYDRA-001 | Information not provided | `docs/architecture/source/HYDRA_DEFENSE_STACK.md` | `security/hydra_consensus.py` defines expected nodes, required votes, consensus evidence, and fail-closed outcomes for missing provenance, invalid nodes, request/policy mismatch, quorum failure, stale attestation, policy hash mismatch, nonce/replay divergence, and node disagreement. | `tests/test_hydra_consensus.py`; `tests/test_hydra_stack.py`; `tests/test_gateway_hydra.py` | PARTIAL | Exported Notion source text, source URL/version/hash, production node identity evidence, key custody evidence, rotation/revocation evidence. |
| ARCH-HYDRA-002 | Information not provided | `docs/architecture/source/HYDRA_DEFENSE_STACK.md` | `security/hydra_nodes.py` collects in-process, subprocess, and remote node decisions; node errors, missing nodes, invalid signatures, unavailable nodes, and node failures become deny decisions. | `tests/test_hydra_node_service.py`; `tests/test_hydra_live_client.py` | PARTIAL | Exported Notion source text, remote endpoint identity evidence, transport security evidence, production node enrollment evidence. |
| ARCH-POLICY-001 | Information not provided | `docs/architecture/source/POLICY_BRAIN.md` | `runtime/policy_validator.py` validates policy JSON, SHA256 digest, signature, public key, approvals, evidence ruleset snapshot, runtime attestation, audit ledger head, and required artifacts; missing or invalid artifacts fail closed. | `tests/test_policy_verification_workflow.py`; `tests/test_governance_policy_pack.py`; `tests/test_governance_policy_parity.py` | PARTIAL | Exported Notion source text, source URL/version/hash, source approval evidence. |
| ARCH-POLICY-002 | Information not provided | `docs/architecture/source/POLICY_BRAIN.md` | `docs/governance-policy-parity.md` documents policy simulation/runtime parity; `governance/policy_parity.py` evidence exists in repository and parity must fail closed on mismatch. | `tests/test_governance_policy_parity.py` | PARTIAL | Exported Notion source text, claim-level source parity evidence, certification audit record. |
| ARCH-GATEWAY-001 | Information not provided | `docs/architecture/source/ENFORCEMENT_GATEWAY.md` | `runtime/enforcement_gateway.py` declares fail-closed guarantees: invalid/unverifiable policy blocks actions, device actions require registration/authentication/attestation, allow/deny decisions append to audit before returning, and client state is not trusted. | `tests/test_governance_architecture_boundaries.py`; `tests/test_gateway_app.py` | PARTIAL | Exported Notion source text, source URL/version/hash, source-to-implementation review evidence. |
| ARCH-GATEWAY-002 | Information not provided | `docs/architecture/source/ENFORCEMENT_GATEWAY.md` | `gateway/app.py` exposes runtime status, governance evidence, execution validation, and execute-route behavior; deny/fail-closed responses are returned for validation failures. | `tests/test_gateway_app.py`; `tests/test_gateway_hydra.py` | PARTIAL | Exported Notion source text, source metadata, architecture parity audit evidence. |
| ARCH-AUDIT-001 | Information not provided | `docs/architecture/source/AUDIT_EVIDENCE_LAYER.md` | `audit/hash_chain.py` appends audit events with `hash_prev` and `hash_current`, verifies chain continuity, and checks associated immutable ledger validity when present. | `tests/test_audit_hash_chain.py`; `tests/test_audit_integrity.py`; `tests/test_immutable_evidence_ledger.py` | PARTIAL | Exported Notion source text, source URL/version/hash, regulator export evidence if certification claim is made. |
| ARCH-AUDIT-002 | Information not provided | `docs/architecture/source/AUDIT_EVIDENCE_LAYER.md` | `docs/governance-evidence-chain.md` documents deterministic append-only evidence lifecycle, replay detection, chronology continuity limits, and future anchoring path. | `tests/test_governance_evidence_chain.py`; `tests/test_governance_evidence_record_chain.py`; `tests/test_governance_evidence_merkle_checkpoint.py` | PARTIAL | Exported Notion source text, source metadata, external anchor evidence if immutable external chronology is claimed. |
| ARCH-WORM-001 | Information not provided | `docs/architecture/source/AUDIT_EVIDENCE_LAYER.md` | `docs/governance-worm-immutable-storage.md` documents local-only WORM readiness manifests, hash-only diagnostics, fail-closed manifest verification, and explicitly states that the layer does not write to real WORM storage or call cloud APIs. | `tests/test_worm_evidence_archive.py`; `tests/test_governance_worm_evidence_manifest.py` | BLOCKED | External WORM provider/control evidence, retention class, legal hold model, immutable write proof, export verification evidence, failure-mode audit. |
| ARCH-SOURCE-001 | Information not provided | `docs/architecture/source/ARCHITECTURE_SOURCE_MANIFEST.md` | Source manifest records expected paths and explicitly marks source URL, version identifier, and content hash as `Information not provided`; no Notion exports are present. | Documentation review only; no runtime test applicable. | BLOCKED | Real exported Notion Markdown with source URL/page ID, export timestamp, version identifier, content hash, export actor, repository commit SHA. |

## Summary

Repository implementation evidence is present for the core execution, Hydra, policy, gateway, audit, and local WORM readiness surfaces.

Certification remains blocked because repository evidence does not replace missing Notion source exports and does not provide external WORM provider evidence.

