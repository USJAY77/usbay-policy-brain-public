# Claim-Level Traceability Matrix

Purpose: map each architecture claim to repository implementation evidence and test evidence.

Source audit: `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md`

Certification status: BLOCKED until Notion source claims are exported and mapped.

## Mapping Rules

- Do not certify a claim from Notion unless the exact source text is exported.
- Do not certify a repository behavior unless code evidence and test evidence are identified.
- Do not treat human approval as a substitute for audit evidence.
- If a claim is not mapped to implementation and tests, keep it OPEN.
- Missing evidence must fail closed.

## Matrix

| Claim ID | Source Document | Source Claim | Repository File | Code Evidence | Test Evidence | Audit Evidence Required | Status |
|---|---|---|---|---|---|---|---|
| ARCH-UEA-001 | USBAY Universal Execution Architecture | Information not provided. | `docs/runtime-deployment-governance.md` | Runtime entrypoint is documented as `gateway.app:app`; deployment must use platform `PORT` and fail closed on startup drift. | Deployment provenance/live-pilot tests in repository. | Exported Notion claim, source hash, deployment validation result, commit SHA. | OPEN |
| ARCH-UEA-002 | USBAY Universal Execution Architecture | Information not provided. | `gateway/app.py` | `validate_execution_decision()` and `/execute` validate signed decisions, replay state, actor binding, nonce binding, policy/Hydra verification, and mark-used semantics. | `tests/test_gateway_app.py`, `tests/test_gateway_hydra.py` | Exported Notion claim, execution decision evidence, replay evidence, audit hash. | OPEN |
| ARCH-HYDRA-001 | Hydra Defense Stack | Information not provided. | `security/hydra_consensus.py` | Hydra defines expected nodes, required votes, consensus evidence, and fail-closed quorum/replay/policy mismatch behavior. | `tests/test_hydra_consensus.py`, `tests/test_hydra_stack.py`, `tests/test_gateway_hydra.py` | Exported Notion claim, node identity evidence, quorum evidence, consensus evidence hash. | OPEN |
| ARCH-HYDRA-002 | Hydra Defense Stack | Information not provided. | `security/hydra_nodes.py` | Node collection converts unavailable nodes, missing nodes, invalid signatures, and failures into deny decisions. | `tests/test_hydra_node_service.py`, `tests/test_hydra_live_client.py` | Exported Notion claim, node enrollment evidence, signature verification evidence, failure audit. | OPEN |
| ARCH-POLICY-001 | Policy Brain | Information not provided. | `runtime/policy_validator.py` | Policy validator checks policy file, SHA256 digest, signature, public key, approvals, evidence snapshot, and runtime attestation evidence. | `tests/test_policy_verification_workflow.py` | Exported Notion claim, policy hash, signature proof, approval evidence, validation output. | OPEN |
| ARCH-POLICY-002 | Policy Brain | Information not provided. | `docs/governance-policy-parity.md` | Policy parity requires simulation/runtime decision equivalence before rollout and fails closed on mismatch. | `tests/test_governance_policy_parity.py` | Exported Notion claim, parity proof, runtime decision evidence, policy pack hash. | OPEN |
| ARCH-GATEWAY-001 | Enforcement Gateway | Information not provided. | `runtime/enforcement_gateway.py` | Enforcement gateway declares fail-closed guarantees for policy validation, device trust, audit append, and backend truth. | Runtime/enforcement validation tests in repository. | Exported Notion claim, audit append evidence, device trust evidence, policy validation evidence. | OPEN |
| ARCH-GATEWAY-002 | Enforcement Gateway | Information not provided. | `gateway/app.py` | Gateway exposes runtime health, governance evidence, execution validation, and execution routing behavior. | `tests/test_gateway_app.py` | Exported Notion claim, health evidence, governance evidence response, execution denial/allow audit. | OPEN |
| ARCH-AUDIT-001 | Audit & Evidence Layer | Information not provided. | `audit/hash_chain.py` | Audit events include previous/current hash continuity and immutable ledger validation. | `tests/test_audit_hash_chain.py`, `tests/test_audit_integrity.py` | Exported Notion claim, audit chain verification output, ledger validation evidence. | OPEN |
| ARCH-AUDIT-002 | Audit & Evidence Layer | Information not provided. | `docs/governance-evidence-chain.md` | Evidence chain docs define deterministic append-only continuity and replay detection. | `tests/test_governance_evidence_chain.py`, `tests/test_governance_evidence_record_chain.py` | Exported Notion claim, chain hash, replay detection result, evidence export hash. | OPEN |
| ARCH-WORM-001 | Audit & Evidence Layer | Information not provided. | `docs/governance-worm-immutable-storage.md` | WORM readiness is documented as local-only, hash-only, and not external WORM storage. | `tests/test_worm_evidence_archive.py`, `tests/test_governance_worm_evidence_manifest.py` | Exported Notion claim, WORM readiness manifest, retention/export evidence, external WORM approval if claimed. | OPEN |

## Status Definitions

- OPEN: source claim or required evidence is missing.
- PARTIAL: source and code evidence exist, but test or audit evidence is incomplete.
- CLOSED: source claim, repository implementation, test evidence, and audit evidence are all present.
- BLOCKED: claim conflicts with repository evidence or lacks required evidence.

## Certification Rule

No architecture claim is certifiable until its status is CLOSED.

