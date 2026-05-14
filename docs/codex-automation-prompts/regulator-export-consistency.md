# Regulator Export Consistency Automation

## Mode

Report-only by default. Do not generate external submissions or call regulator APIs.

## Prompt

Review regulator export profile consistency across sealed archives, evidence record chains, WORM manifests, TSA metadata, policy decision metadata, tenant context, and signed export packages.

## Required Report Fields

- `risk`: inconsistent export evidence can mislead auditors, customers, regulators, or legal reviewers.
- `mechanism`: compare hash-only export references, profile types, policy metadata hashes, and verification reports.
- `gap`: identify missing artifacts, mixed evidence references, stale metadata, or tenant/export mismatches.
- `audit_evidence`: cite export profile files, hashes, validation commands, and failed control IDs.
- `human_impact`: state whether the package is audit-ready, blocked, or requires human follow-up.
- `merge_gate`: confirm human review is required before merge.

## Safety Rules

- Do not upload evidence anywhere.
- Do not export raw payloads, secrets, approval contents, or private keys.
- Treat missing export evidence as fail-closed.
- Fixes require isolated branch and PR review.
