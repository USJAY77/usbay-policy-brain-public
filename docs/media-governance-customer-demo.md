# USBAY Media Governance Customer Demo

This customer-demo prototype shows how USBAY can sit above AI media workflows as a governance layer. It is intentionally non-production scaffolding.

## What USBAY Proves Today

- Media release requires provenance, approval, timestamp, rights/consent, release token, distribution authorization, revocation clearance, jurisdiction clearance, drift review, watchtower health, human escalation clearance, recovery clearance, and red-team clearance.
- Audit exports are reference-only and scope-bound.
- Adversarial governance events override prior PASS states.
- Missing or malformed governance evidence fails closed.
- Remaining production gaps are represented as non-production scaffolds for immutable evidence, lifecycle orchestration, dashboard/export readiness, and cryptographic authority.

## What Fails Closed

- Missing approval
- Missing timestamp
- Provenance mismatch
- Missing rights or consent
- Missing or mis-scoped release token
- Missing distribution authority
- Revoked, frozen, disputed, or takedown-required release state
- Jurisdiction conflict or regional restriction
- Audit export lineage gap or payload detection
- Model drift or policy lineage break
- Critical watchtower health
- Missing human escalation
- Missing recovery review
- Forged approval, lineage corruption, replay, fake escalation, recovery bypass, export tamper, distribution spoofing, or governance bypass simulation
- Unsigned evidence bundle, missing chain hash, mutable evidence marker, or missing timestamp reference
- Unknown lifecycle stage, stage order violation, missing orchestration gate, or attempted runtime override
- Unscoped dashboard/export output, missing export purpose, or sensitive payload export marker
- Missing signature reference, unknown signing authority, stale key reference, or unbound signature scope

## Evidence Available

- `artifacts/media-governance-demo-manifest.json`
- `artifacts/media-audit-export-manifest.json`
- `artifacts/media-jurisdiction-export-manifest.json`
- `artifacts/media-drift-governance-manifest.json`
- `artifacts/media-governance-watchtower-manifest.json`
- `artifacts/media-human-escalation-manifest.json`
- `artifacts/media-recovery-governance-manifest.json`
- `artifacts/media-redteam-governance-manifest.json`
- `artifacts/media-immutable-evidence-manifest.json`
- `artifacts/media-lifecycle-orchestration-manifest.json`
- `artifacts/media-dashboard-export-manifest.json`
- `artifacts/media-crypto-authority-manifest.json`
- `artifacts/media-governance-demo-evidence-bundle.json`

## Not Production-Ready

This demo does not provide production certification, real distributor integration, real regulator integration, real platform publishing, real signing authority, real release authority, real legal review authority, real identity verification, or real timestamp authority. Human policy owners must define production policy, signing, approval, legal, and operational controls before live use.

## Demo Boundary

The demo does not store media payload bodies, person-identifying data, auth material, legal document bodies, platform bearer material, protected creative works, real platform integrations, or production secrets.
