# Architecture Certification Blockers

Purpose: track blockers identified by Euria Architecture Review and define evidence required to move each blocker from OPEN to CLOSED.

Source audit: `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md`

Certification status: BLOCKED.

## Blocker Register

| Blocker ID | Blocker | Verified Control | Required Control | Evidence Required To Close | Status |
|---|---|---|---|---|---|
| BLOCKER-001 | Notion source availability gap | Repository evidence exists for runtime, Hydra, policy, gateway, and audit layers. | Export all five Notion architecture pages with version and hash evidence. | Markdown export, source URL/ID, source version, export date, export actor, content hash, repository commit SHA. | OPEN |
| BLOCKER-002 | Architecture traceability gap | Repository-level traceability matrix exists. | Claim-level Notion-to-code-to-test-to-audit mapping. | `CLAIM_LEVEL_TRACEABILITY_MATRIX.md` populated with exact source claims, repository files, code evidence, test evidence, and audit evidence. | OPEN |
| BLOCKER-003 | External WORM gap | Local-only WORM readiness is documented and tested. | Regulator-grade WORM persistence policy and implementation evidence. | Approved WORM provider/control, retention policy, legal hold model, immutable write proof, export verification, failure-mode audit. | OPEN |
| BLOCKER-004 | Hydra production identity gap | Hydra fail-closed consensus and node failure behavior are implemented. | Governed production node identity, key custody, rotation, and revocation. | Node enrollment records, key custody policy, rotation evidence, revocation evidence, identity verification tests, consensus audit evidence. | OPEN |
| BLOCKER-005 | Remote verifier evidence gap | Remote Hydra node client exists and invalid/unavailable nodes are denied. | Production remote endpoint identity and transport governance. | Endpoint identity proof, transport security policy, node enrollment binding, spoofing/downgrade tests, audit evidence. | OPEN |
| BLOCKER-006 | Production certification gap | Pilot docs state pilot package is not production certification. | Explicit production certification gate with evidence requirements. | Certification checklist, test execution report, release evidence, human approval evidence bound to audit evidence, fail-closed deployment gate. | OPEN |
| BLOCKER-007 | Audit index gap | Audit #002 exists under `docs/audits`. | Governed audit index format if required by project policy. | Audit index file, audit ID, title, date, scope, status, source hash, reviewer, and approval evidence. | OPEN |
| BLOCKER-008 | Notion import/parity gap | Repository architecture reconciliation files mark Notion unavailable. | Source-of-truth parity between Notion and repository docs. | Exported Notion hashes, repository doc hashes, parity review record, claim-level mapping, drift decision. | OPEN |
| BLOCKER-009 | Human approval substitution risk | Audit #002 states human approval must not replace audit evidence. | Approval workflow bound to signed policy/audit/quorum evidence. | Written approval policy, approval records, actor/device/decision/timestamp/policy version, audit hash, tests proving missing evidence blocks. | OPEN |
| BLOCKER-010 | Diagnostic data leakage risk | Docs require hash-only/redacted diagnostics. | Verified diagnostics redaction across architecture evidence exports. | Redaction profile, log scan evidence, tests for no secrets/raw payloads/raw approvals/raw nonces/private keys. | OPEN |

## Closure Rules

A blocker moves to CLOSED only when:

- Required evidence is present.
- Evidence is stored in the repository or governed evidence pack.
- Evidence has source/version/hash metadata.
- Test evidence exists where the blocker relates to runtime behavior.
- Audit evidence exists where the blocker relates to governance decisions.
- Fail-closed behavior is preserved.

Human approval alone cannot close any blocker.

## Certification Decision

Decision: BLOCKED.

Reason: Architecture certification blockers remain OPEN.
