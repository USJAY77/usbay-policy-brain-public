## PURPOSE

Implement a cryptographically chained audit trail for USBAY computer-use decisions.

## RISK

Without tamper-evident decision provenance, historical decision modification, removal, or insertion could go undetected.

## POLICY LINK

- AGENTS.md fail-closed governance
- AGENTS.md audit-first engineering
- AGENTS.md rollback and forensics
- runtime/computer_use/decision_engine.py

## REQUIRED APPROVALS

- USBAY-AUDIT review required before merge.
- USBAY-GLOBAL23 review required before merge.
- No deployment, browser execution, desktop execution, or external API call is authorized.

## GOVERNANCE CHECKS

- Decision audit record includes required fields.
- First record uses `previous_hash = GENESIS`.
- Every subsequent record references the previous record hash.
- Chain verification returns `VALID` or `CHAIN_BROKEN`.
- Modified records break verification.
- Removed records break verification.
- Inserted records break verification.
- Broken chain maps to `FAIL_CLOSED`.

## AUDIT

PB-159 evidence is recorded under `governance/evidence/pb159/` with test results, chain rule, genesis rule, audit output fields, and remaining gaps.

## IMPACT

This is a local provenance layer only. It does not deploy, execute browser actions, execute desktop actions, call external APIs, or activate providers.

## Decision

VERIFIED

## Status

READY_FOR_REVIEW
