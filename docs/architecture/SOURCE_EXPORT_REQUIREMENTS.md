# Source Export Requirements

Purpose: define the evidence required to reconcile Euria/Notion architecture sources with repository implementation evidence.

Source audit: `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md`

Certification status: BLOCKED until source exports are complete.

## Required Source Documents

- USBAY Universal Execution Architecture
- Hydra Defense Stack
- Policy Brain
- Enforcement Gateway
- Audit & Evidence Layer

## Verified Controls

- Repository evidence exists for gateway runtime deployment, execution validation, policy validation, Hydra consensus, audit hash chains, evidence chains, policy parity, and local-only WORM readiness.
- Repository documentation explicitly separates pilot/demo review artifacts from production certification.
- Repository documentation requires fail-closed behavior for malformed, missing, unsigned, stale, or ambiguous governance data.

## Required Controls

The architecture source export process must produce evidence for:

- Source title.
- Source owner.
- Source system.
- Source URL or stable page ID.
- Export date.
- Export actor.
- Content hash.
- Source version or revision timestamp.
- Approval status.
- Approval evidence.
- Exported Markdown path.
- Repository commit SHA containing the export.

## Export Rules

- Export each Notion architecture page to Markdown.
- Do not summarize the page as a substitute for export.
- Do not rewrite architecture claims during export.
- Preserve headings, decision language, control claims, and diagrams where possible.
- If a diagram cannot be exported, record `Information not provided.` for diagram contents and list the missing artifact.
- Hash the exported Markdown content.
- Store exported Markdown under `docs/architecture/`.
- Map every architecture claim to repository evidence or mark it blocked.

## Source Export Evidence Record

Each exported source must include this metadata block:

```text
Source title:
Source URL or ID:
Source owner:
Source system:
Export date:
Export actor:
Source version:
Content hash:
Approval evidence:
Repository path:
Repository commit SHA:
Certification status:
```

## Blocker Closure Criteria

The Notion source availability blocker moves from OPEN to CLOSED only when all five source documents are exported, hashed, versioned, stored under `docs/architecture/`, and mapped in `CLAIM_LEVEL_TRACEABILITY_MATRIX.md`.

If any source cannot be exported:

Decision: BLOCKED.

Reason: Source evidence unavailable.

