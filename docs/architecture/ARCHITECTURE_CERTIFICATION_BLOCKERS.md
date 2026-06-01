# Architecture Certification Blockers

Purpose: track architecture certification blockers after PR #133 and define evidence required to move each blocker to CLOSED.

Source audit: `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md`

Post-PR #133 certification status: BLOCKED.

Evidence rule: repository evidence only. Do not fabricate Notion exports, source URLs, hashes, external WORM provider evidence, or certification claims.

Source-of-truth decision recorded: 2026-06-02.

Decision evidence: all five referenced Notion architecture pages were inspected and found to contain title-only content. The GitHub repository is the authoritative architecture source. The inspected Notion architecture pages are non-authoritative placeholders/navigation pages.

## Current Blocker Register

| Blocker ID | Blocker | Current State | Repository Evidence Present | Missing Evidence | Evidence Required To Close |
|---|---|---|---|---|---|
| BLOCKER-001 | Notion architecture content gap | BLOCKED | All five referenced Notion architecture pages were inspected and found to contain title-only placeholder content. Placeholder source records and source manifest exist under `docs/architecture/source/`. Repository architecture reconciliation docs exist. GitHub is recorded as the authoritative architecture source. | Substantive architecture content is absent from the inspected Notion pages. No Notion architecture claims, diagrams, controls, requirements, source URL evidence, version metadata, export timestamp, content hash, export actor, or source-to-claim evidence exists for those pages. | Keep BLOCKER-001 open until certification records accept GitHub as the authoritative architecture source and claim-level repository evidence is complete, or until substantive Notion pages are created and exported with URL/version/hash metadata. |
| BLOCKER-002 | Claim-level traceability gap | PARTIAL | `docs/architecture/CLAIM_LEVEL_TRACEABILITY_MATRIX.md` has been reconciled to the GitHub source-of-truth decision and maps authoritative GitHub source text, implementation evidence, test evidence, and audit evidence for core architecture surfaces. | Remaining partial/blocked claim evidence: production remote-node identity and transport evidence for Hydra remote behavior, external WORM provider evidence for ARCH-WORM-001, and certification lifecycle closure evidence for source authority. | Close or explicitly scope remaining partial/blocked matrix rows with evidence. BLOCKER-002 cannot close while any required claim remains PARTIAL or BLOCKED. |
| BLOCKER-003 | External WORM evidence gap | BLOCKED | `docs/governance-worm-immutable-storage.md` documents local-only WORM readiness; WORM-related tests exist for local readiness and manifests. External WORM pilot preparation docs exist under `docs/architecture/WORM_PILOT_PLAN.md`, `docs/architecture/WORM_PROVIDER_COMPARISON.md`, `docs/architecture/WORM_EVIDENCE_REQUIREMENTS.md`, and `docs/architecture/WORM_PILOT_DECISION_MATRIX.md`. | External WORM provider/control evidence, retention class, legal hold model, immutable write proof, export verification evidence, failure-mode audit, approved provider policy. | Run a governed external WORM pilot, collect provider evidence, verify fail-closed behavior, and update certification evidence. Local WORM readiness and pilot planning alone are insufficient. |

## Repository Evidence Closed By PR #133

PR #133 improved repository-side architecture evidence and traceability documentation. It established repository lineage evidence for:

- Universal execution implementation surfaces.
- Hydra consensus and node failure behavior.
- Policy validation and parity documentation.
- Enforcement Gateway runtime behavior.
- Audit/evidence chain and local WORM readiness documentation.

This repository lineage evidence does not close Blocker #001 or Blocker #003.

## Blocker #003 Pilot Package

External WORM pilot preparation is documented in:

- `docs/architecture/WORM_PILOT_PLAN.md`
- `docs/architecture/WORM_PROVIDER_COMPARISON.md`
- `docs/architecture/WORM_EVIDENCE_REQUIREMENTS.md`
- `docs/architecture/WORM_PILOT_DECISION_MATRIX.md`

Pilot package status:

Decision: PILOT.

Certification impact:

Decision: BLOCKED.

Reason: pilot planning does not provide external WORM provider evidence, retention enforcement evidence, legal hold evidence, immutable write proof, audit receipt, export verification evidence, or provider failure-mode evidence.

Human approval does not replace missing provider evidence.

## Blocker #001 Reclassification

Prior classification: Notion source availability/export gap.

Current classification: Notion architecture content gap.

Root cause:

The five inspected Notion architecture pages contain title-only placeholder content. The blocker is not caused by an export failure. The blocker is caused by the absence of substantive architecture content in Notion.

Governance decision:

- GitHub repository documentation and implementation evidence are the authoritative architecture source.
- Notion architecture pages are non-authoritative placeholders/navigation pages unless future substantive content is added and reconciled.
- No certification claim may rely on title-only Notion pages.
- BLOCKER-001 remains BLOCKED until the certification evidence path is completed.

Certification impact:

Decision: BLOCKED.

Human approval does not replace missing architecture content, claim evidence, source metadata, or traceability evidence.

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
