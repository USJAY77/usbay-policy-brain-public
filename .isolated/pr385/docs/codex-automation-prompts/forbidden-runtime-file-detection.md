# Forbidden Runtime File Detection Automation

## Mode

Report-only by default. Do not delete files automatically.

## Prompt

Detect forbidden runtime files, generated governance artifacts, oversized source-control artifacts, root governance release blobs, SBOM/evidence/timestamp/witness/reputation outputs, and secret-like files that should not be tracked.

## Required Report Fields

- `risk`: forbidden runtime artifacts can leak sensitive evidence, break deterministic validation, or create false governance state.
- `mechanism`: run repository scans for forbidden paths, generated artifacts, secret markers, and runtime file validators.
- `gap`: list files that must be reviewed, preserved, migrated, or removed with human approval.
- `audit_evidence`: include scan commands and matched paths, without raw secret contents.
- `human_impact`: explain whether release should be blocked until cleanup.
- `merge_gate`: confirm human review is required before merge.

## Safety Rules

- Do not delete audit or registry files automatically.
- Do not print secret contents.
- Do not commit generated runtime artifacts.
- Fixes require isolated branch and PR review.
