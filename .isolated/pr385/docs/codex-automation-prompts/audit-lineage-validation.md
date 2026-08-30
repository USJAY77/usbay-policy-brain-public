# Audit Lineage Validation Automation

## Mode

Report-only by default. Do not mutate audit files or trusted ledgers.

## Prompt

Validate audit lineage continuity across append-only ledgers, evidence chains, Merkle checkpoints, sealed archives, WORM manifests, timestamp attachments, LTV records, and export bundles.

## Required Report Fields

- `risk`: broken lineage can make governance evidence unverifiable for auditors and regulators.
- `mechanism`: verify hash continuity, previous-hash linkage, append-only order, replay bindings, and signature evidence.
- `gap`: identify missing hashes, broken chain positions, replay ambiguity, or unverifiable evidence.
- `audit_evidence`: cite evidence file names, hash fields, validation commands, and failed control IDs.
- `human_impact`: explain whether evidence can be relied on for audit, incident response, or legal review.
- `merge_gate`: confirm human review is required before merge.

## Safety Rules

- Never rewrite audit history.
- Never remove evidence to make validation pass.
- Never log raw evidence payloads, secrets, or approval contents.
- Fixes require isolated branch and PR review.
