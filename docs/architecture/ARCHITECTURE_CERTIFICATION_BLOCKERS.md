# Architecture Certification Blockers

Purpose: track architecture certification blockers after PR #133 and define evidence required to move each blocker to CLOSED.

Source audit: `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md`

Post-PR #133 certification status: BLOCKED.

Evidence rule: repository evidence only. Do not fabricate Notion exports, source URLs, hashes, external WORM provider evidence, or certification claims.

## Current Blocker Register

| Blocker ID | Blocker | Current State | Repository Evidence Present | Missing Evidence | Evidence Required To Close |
|---|---|---|---|---|---|
| BLOCKER-001 | Notion source availability gap | BLOCKED | Placeholder source records and source manifest exist under `docs/architecture/source/`. Repository architecture reconciliation docs exist. | Real exported Notion Markdown, source URL or stable page ID, source version or last edited timestamp, real export timestamp, content hash, export actor, repository commit SHA containing the export. | Export all five required Notion pages to Markdown with URL/version/hash metadata and update `docs/architecture/source/ARCHITECTURE_SOURCE_MANIFEST.md`. |
| BLOCKER-002 | Claim-level traceability gap | PARTIAL | `docs/architecture/CLAIM_LEVEL_TRACEABILITY_MATRIX.md` maps repository implementation evidence and test evidence for core architecture surfaces. | Exact Notion source claim text, source URL/version/hash metadata, claim-level source approval evidence, audit evidence proving source parity. | Add exported Notion claim text to each matrix row, verify source hashes, and map each claim to repository implementation evidence, test evidence, and audit evidence. |
| BLOCKER-003 | External WORM evidence gap | BLOCKED | `docs/governance-worm-immutable-storage.md` documents local-only WORM readiness; WORM-related tests exist for local readiness and manifests. | External WORM provider/control evidence, retention class, legal hold model, immutable write proof, export verification evidence, failure-mode audit, approved provider policy. | Add governed external WORM evidence and validation results. Local WORM readiness alone is insufficient. |

## Repository Evidence Closed By PR #133

PR #133 improved repository-side architecture evidence and traceability documentation. It established repository lineage evidence for:

- Universal execution implementation surfaces.
- Hydra consensus and node failure behavior.
- Policy validation and parity documentation.
- Enforcement Gateway runtime behavior.
- Audit/evidence chain and local WORM readiness documentation.

This repository lineage evidence does not close Blocker #001 or Blocker #003.

## Closure Rules

A blocker may move to CLOSED only when:

- Required evidence is present.
- Evidence is stored in the repository or governed evidence pack.
- Evidence has source, version, and hash metadata where applicable.
- Test evidence exists where the blocker relates to runtime behavior.
- Audit evidence exists where the blocker relates to governance decisions or certification.
- Fail-closed behavior is preserved.

Human approval alone cannot close any blocker.

## Current Certification Decision

Decision: BLOCKED.

Reason: BLOCKER-001 and BLOCKER-003 remain BLOCKED; BLOCKER-002 remains PARTIAL.
