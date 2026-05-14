# Registry Mutation Detection Automation

## Mode

Report-only by default. Do not edit trusted registries automatically.

## Prompt

Detect unintended trusted registry mutations, including key registry drift, signer trust policy changes, node identity enrollment changes, and generated test identity leakage.

## Required Report Fields

- `risk`: unintended registry drift can create unauthorized trust anchors or break identity continuity.
- `mechanism`: compare registry diffs against baseline, inspect enrolled identity fields, and check for generated test keys.
- `gap`: identify unexpected fingerprints, missing lineage, malformed registry entries, or generated identities.
- `audit_evidence`: include registry paths, diff summaries, fingerprints, and validation commands without private key material.
- `human_impact`: state whether operators should preserve, migrate, or reject the mutation.
- `merge_gate`: confirm human review is required before merge.

## Safety Rules

- Do not delete or rewrite trusted registry history without explicit human approval.
- Do not print private keys.
- Do not add generated test identities to trusted registries.
- Proposed fixes require isolated branch and PR review.
