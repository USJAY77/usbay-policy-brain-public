# USBAY Architecture Audit #002: Core Architecture

Audit date: 2026-06-01

Audit scope: USBAY Universal Execution Architecture, Hydra Defense Stack, Policy Brain, Enforcement Gateway, and Audit & Evidence Layer.

Evidence standard: repository and documentation evidence only. Architecture details not present in the repository or available documentation are listed as assumptions or open questions. Human approval does not replace audit evidence.

## 1. Source Documents

Requested Notion architecture sources:

- USBAY Universal Execution Architecture: not available in the local repository context.
- Hydra Defense Stack: not available in the local repository context.
- Policy Brain: not available in the local repository context.
- Enforcement Gateway: not available in the local repository context.
- Audit & Evidence Layer: not available in the local repository context.

Repository documentation reviewed:

- `docs/pilot/USBAY_ENTERPRISE_ARCHITECTURE.md`
- `docs/pilot/USBAY_ENTERPRISE_AUDIT_OVERVIEW.md`
- `docs/governance-architecture-boundaries.md`
- `docs/runtime-deployment-governance.md`
- `docs/governance-evidence-chain.md`
- `docs/governance-worm-immutable-storage.md`
- `docs/governance-policy-parity.md`

Repository implementation evidence reviewed:

- `gateway/app.py`
- `runtime/enforcement_gateway.py`
- `runtime/policy_validator.py`
- `security/hydra_consensus.py`
- `security/hydra_nodes.py`
- `audit/hash_chain.py`
- `audit/immutable_ledger.py`

Validation and boundary evidence reviewed:

- `tests/test_governance_architecture_boundaries.py`
- `tests/test_gateway_hydra.py`
- `tests/test_hydra_consensus.py`
- `tests/test_hydra_stack.py`
- `tests/test_audit_hash_chain.py`
- `tests/test_immutable_evidence_ledger.py`
- `tests/test_worm_evidence_archive.py`

## 2. Verified Current State

The enterprise architecture documentation identifies the runtime path as Policy Brain plus Enforcement Gateway, with runtime dashboard and evidence-pack surfaces for review. The same document states that the pilot package is visual documentation only and does not certify production deployment, approve execution, or override USBAY governance.

The deployment governance documentation identifies `gateway.app:app` as the runtime deployment entrypoint. Deployment startup must use the platform-provided `PORT`, bind to `0.0.0.0`, and fail closed on missing `PORT`, hardcoded/default port fallback, duplicate startup paths, or dashboard orchestration outside the production command.

The policy validation implementation in `runtime/policy_validator.py` requires policy JSON, SHA256, signature, and public key artifacts. It is documented to fail closed on missing artifacts, parse issues, digest mismatch, or signature failure.

The enforcement gateway implementation in `runtime/enforcement_gateway.py` declares fail-closed guarantees: invalid or unverifiable policy blocks governance action, device actions require registration/authentication/attestation, every allow/deny decision is appended to governance audit before returning, and client-provided badge/session state is not trusted for enforcement.

The execution path in `gateway/app.py` validates decision ID, decision signatures, actor hash, algorithm version, replay state, nonce binding, decision time, Hydra/policy verification, execution routing, and mark-used semantics before allowing execution. Errors return deny/fail-closed responses rather than optimistic allow.

The Hydra consensus implementation defines three expected nodes and two required votes. It fails closed on missing provenance context, release-lineage mismatch, fewer than three decisions, invalid node decisions, request hash mismatch, policy version mismatch, unavailable quorum, stale node/attestation timestamps, missing required state fields, policy hash mismatch, nonce/replay divergence, and node disagreement.

Hydra node collection treats node failures, unavailable nodes, invalid signatures, and missing expected nodes as signed deny decisions. Default node clients include in-process, subprocess, and remote node clients.

The audit hash-chain layer appends events with `hash_prev` and `hash_current` and verifies previous/current hash continuity. It also appends evidence events into an immutable ledger path and fails verification if the immutable ledger is invalid.

The evidence-chain documentation defines local deterministic append-only continuity using previous chain hash, current manifest hash, proof bundle hash, timestamp anchor hash, RFC3161 preflight digest, WORM manifest hash, chain position, UTC timestamp, module versions, and retention policy label.

The WORM immutable storage documentation describes local-only readiness manifests. It explicitly does not write to real WORM storage, call cloud APIs, or export raw governance payloads. Future external WORM integrations require separate governance.

The governance architecture boundaries documentation separates structural validation from cryptographic verification and requires fail-closed behavior for malformed, missing, unsigned, stale, or ambiguous governance data.

The policy parity documentation states that simulation is rollout-safe only when deterministic simulation results match runtime decision evidence. Human review may authorize recovery work, but the validator does not auto-repair or downgrade failure.

## 3. Assumptions

- The named Notion pages may contain higher-level architecture intent, but their contents were not available in this local environment. No architecture details from those pages are treated as verified.
- "USBAY Universal Execution Architecture" is assumed to correspond to the repository execution path in `gateway/app.py`, `runtime/enforcement_gateway.py`, `runtime/policy_validator.py`, and related security/audit modules.
- "Hydra Defense Stack" is assumed to correspond to `security/hydra_consensus.py`, `security/hydra_nodes.py`, and Hydra tests.
- "Policy Brain" is assumed to correspond to policy validation, policy registry, policy parity, and runtime policy-state functions.
- "Audit & Evidence Layer" is assumed to correspond to `audit/*`, `governance/evidence_*`, WORM readiness docs, evidence-chain docs, and offline verifier/evidence-pack docs.
- Production certification is not assumed. Repository documentation explicitly distinguishes pilot/demo review artifacts from production certification.

## 4. Risks

- Notion-to-repository drift: architecture pages may describe controls that are not implemented or tested in the repository.
- Pilot-to-production confusion: enterprise architecture docs say the pilot package is not production certification, but downstream reviewers may misread evidence-pack visibility as deployment approval.
- Hydra remote-node dependency: the default Hydra stack includes a remote node URL. Unreachable or spoofed remote endpoints must remain deny/fail-closed and must be audited.
- Development secrets: Hydra defaults include local development keys/secrets. Production use requires governed secret provisioning and rotation evidence.
- Audit durability gap: repository evidence supports local hash-chain and immutable-ledger readiness, while external WORM storage is explicitly future integration.
- Human approval substitution: human review may direct recovery work, but cannot replace missing policy, signature, quorum, replay, or audit evidence.
- Runtime evidence sensitivity: diagnostics must remain hash-only and avoid raw payloads, private keys, approval contents, secrets, nonces, and private signing material.
- Dependency drift: governance boundary docs identify dependency isolation as a control; changes coupling governance modules into runtime/audit/security layers could weaken auditability or fail-closed semantics.

## 5. Gaps

- Notion source availability gap: the requested architecture pages were not available for direct audit in this environment.
- Architecture traceability gap: no local evidence maps each Notion architecture claim to repository file, test, control ID, and audit artifact.
- External WORM gap: WORM immutable storage is documented as local-only readiness, not regulator-grade external WORM persistence.
- Hydra production identity gap: local/default Hydra node keys and secrets must be replaced by governed production identities, rotation policy, and revocation evidence before unrestricted deployment.
- Remote verifier evidence gap: the audit found remote-node behavior in code, but no reviewed evidence proving production remote-node endpoint identity, transport security, or enrollment governance.
- Production certification gap: docs explicitly say pilot packages do not certify production deployment.
- Audit index gap: no `docs/audits` index was found to register audit #002.
- Notion import gap: if Euria/Notion is the authoritative architecture source, export/version/hash evidence is required before this audit can certify parity.

## 6. Attack Paths

- Prompted or manual approval bypass: an operator treats founder/human approval as sufficient despite missing signed policy, quorum, replay, or audit evidence.
- Stale Hydra node replay: an attacker reuses old node decisions. Current Hydra logic checks node and attestation freshness and nonce/replay binding; audit must verify test coverage for all stale/replay variants.
- Policy hash drift: runtime decision evidence references a different policy hash than expected. Hydra and parity controls should deny on policy mismatch.
- Remote node spoofing: an attacker returns a forged remote Hydra decision. Node decision signature verification should convert invalid signatures to deny decisions; production must also govern node identity and transport.
- Audit chain tampering: an older audit entry is edited. Hash-chain verification should fail when previous/current hash continuity breaks.
- Evidence-pack tampering: gate history or chain summary changes after export. Offline verifier documentation says tampering must return `VERIFY_FAIL`.
- WORM readiness replay: an archived evidence unit is replayed as new. Evidence-chain docs state duplicate entry hashes and duplicate WORM manifest hashes are rejected.
- Deployment startup bypass: alternate runtime commands, hardcoded ports, or dashboard orchestration could bypass production gateway expectations. Runtime deployment docs require fail-closed startup validation.
- Diagnostic data leakage: raw payloads, approvals, secrets, or nonces leak through logs/evidence exports. Governance docs require hash-only/redacted diagnostics.

## 7. Control Effectiveness

Effective controls verified by repository evidence:

- Fail-closed policy validation exists for policy JSON, SHA256, signatures, and public key artifacts.
- Execution validation checks decision signatures, actor binding, algorithm version, replay state, nonce binding, and decision expiry before execution.
- Hydra consensus denies on missing quorum, mismatched request/policy state, stale attestation, nonce/replay divergence, node disagreement, and missing provenance context.
- Node collection converts node failure, missing nodes, invalid signatures, and unavailable nodes into deny decisions.
- Audit hash chain verifies `hash_prev`/`hash_current` continuity and validates associated immutable ledger state.
- Documentation explicitly separates pilot evidence review from production certification.
- WORM readiness documentation preserves hash-only and local-only boundaries.

Partially effective or not yet production-proven controls:

- WORM evidence preservation is readiness-only and local-only; external regulator-grade WORM storage is not verified.
- Hydra production node identity, transport security, key rotation, and revocation evidence were not verified in this audit.
- Notion architecture parity to repository implementation was not verified because source pages were unavailable.
- Full production certification cannot be inferred from pilot review docs.

Ineffective if used alone:

- Human approval without signed policy/audit/quorum evidence.
- Visual dashboard status without backend evidence.
- Pilot evidence pack without offline verification.
- Local development Hydra defaults in unrestricted production.

## 8. Audit Requirements

- Export the five named Notion architecture pages with stable document versions, timestamps, and hashes.
- Create a traceability matrix from each architecture claim to repository file, test, evidence artifact, and owner.
- Preserve fail-closed evidence for every allow/deny path, including actor, device or node identity, decision, timestamp, policy version/hash, signature status, replay state, and audit hash.
- Verify Hydra node identity, role, signature, attestation timestamp, policy hash, nonce hash, replay registry hash, and consensus evidence hash for each consensus decision.
- Verify execution decisions include signed decision evidence and mark-used/replay protection evidence.
- Verify every evidence export can be checked offline and returns explicit pass/fail status.
- Verify audit/evidence diagnostics are hash-only and contain no private keys, secrets, raw nonces, raw approval contents, or raw regulator exports.
- Verify WORM retention/export controls before claiming regulator-grade evidence preservation.
- Record all audit failures as blocked, not approved with conditions.

## 9. Recommended Actions

1. Export the Notion architecture pages into versioned repository documentation or an evidence pack before certification.
2. Create a `docs/audits/README.md` or audit index only under a separate documentation task if audit indexing is required by project governance.
3. Build an architecture traceability matrix covering Policy Brain, Enforcement Gateway, Hydra Defense Stack, and Audit/Evidence Layer.
4. Add or identify tests proving Notion architecture parity against repository implementation.
5. Replace Hydra development defaults with governed production secret/identity configuration before unrestricted deployment.
6. Document Hydra remote-node enrollment, transport security, key rotation, revocation, and failure semantics.
7. Promote WORM storage from local-only readiness to governed external WORM integration only through a separate reviewed capability branch.
8. Keep dashboard/demo states explicitly labeled as non-certification surfaces.
9. Require audit evidence for human approvals; do not accept human approval as a substitute for missing evidence.
10. Preserve fail-closed behavior for missing policy, missing quorum, stale attestation, replay detection, audit-chain failure, evidence export failure, and deployment startup drift.

## 10. Open Questions

- What are the exact contents, versions, and hashes of the five requested Notion architecture pages?
- Is Notion or the repository the authoritative source for architecture truth?
- Which control IDs map the Universal Execution Architecture to runtime modules and tests?
- What is the production Hydra node identity model, including key custody, rotation, revocation, and remote endpoint verification?
- What external WORM provider, retention class, legal hold model, and export verification process are approved?
- What evidence proves Policy Brain decisions and Enforcement Gateway decisions are parity-checked before rollout?
- Which audit artifacts must be retained for regulator export, and what redaction profile applies?
- What is the required audit index format for `docs/audits`, if any?
- What human approval workflow exists, and how is it bound to signed audit evidence rather than treated as a substitute for evidence?
- What deployment gate converts this architecture audit from review evidence into production readiness evidence?
