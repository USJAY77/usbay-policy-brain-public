# Governance Drift Detection Automation

## Mode

Report-only by default. Do not edit files, push commits, merge PRs, or write directly to `main`.

## Prompt

Inspect USBAY governance runtime and evidence controls for drift from the trusted baseline. Check policy hashes, release manifests, runtime provenance authority, governance health diagnostics, attestation freshness, and readiness flags.

## Required Report Fields

- `risk`: governance drift can cause runtime decisions to appear valid while relying on stale or mismatched authority.
- `mechanism`: compare tracked governance configuration, startup validation outputs, runtime health markers, and test evidence against the expected baseline.
- `gap`: list missing, stale, ambiguous, or inconsistent governance evidence.
- `audit_evidence`: include command outputs, changed paths, and marker names such as `GOVERNANCE_CONTINUITY_VALID=true` when available.
- `human_impact`: explain whether operators should block release, request review, or investigate provenance.
- `merge_gate`: confirm human review is required before merge.

## Safety Rules

- Never auto-repair drift.
- Never log raw payloads or secrets.
- Treat unavailable validation as fail-closed.
- Any proposed fix must use an isolated branch and PR.
