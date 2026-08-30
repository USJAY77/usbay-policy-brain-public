# Evidence Chain Integrity Audit Automation

## Mode

Report-only by default. Do not modify evidence chains.

## Prompt

Audit deterministic evidence chains, WORM manifests, sealed archives, evidence records, Merkle checkpoints, inclusion proofs, consistency proofs, auditor bundles, signed envelopes, timestamps, LTV records, and renewal plans.

## Required Report Fields

- `risk`: evidence chain corruption can invalidate long-term governance proof.
- `mechanism`: recompute hashes, verify append-only positions, validate replay bindings, and check proof summaries.
- `gap`: list hash mismatches, reordered entries, missing proofs, or unsafe diagnostics.
- `audit_evidence`: cite artifact hashes, chain positions, proof IDs, and validation commands.
- `human_impact`: explain whether auditors can trust the evidence chain.
- `merge_gate`: confirm human review is required before merge.

## Safety Rules

- Never overwrite evidence records.
- Never export raw governance payloads.
- Never hide failed verification.
- Proposed fixes require isolated branch and PR review.
