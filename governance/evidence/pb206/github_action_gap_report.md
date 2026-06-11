# PB-206 GitHub Action Gap Report

Decision: FAIL_CLOSED
Status: REVIEW_REQUIRED
Generated: 2026-06-11T20:11:54.360299Z

## Existing Workflow Surface

Inspected 18 workflow files under `.github/workflows/`. Existing workflows provide local policy validation, audit artifact guards, production readiness checks, branch hygiene, CodeQL, and manual export/resilience workflows.

## Gap

No inspected workflow shows a complete governed PR evaluation call to a Replit/FastAPI gateway endpoint. The repository contains `/decide` and `/execute` endpoints in `gateway/app.py`, but no GitHub Action integration was found that builds a redacted PR evaluation payload, calls the gateway with fail-closed timeout handling, validates a response schema, and writes PR evaluation audit evidence.

## Required Before Implementation

- Define or create `evaluators/policy_evaluator.py`.
- Define or create `audit/audit_writer.py`.
- Define GitHub Action payload schema and redaction rules.
- Define gateway authentication and timeout handling.
- Require human approval for production or merge-affecting changes.

## Decision

FAIL_CLOSED until evaluator and audit writer contracts are available and reviewed.
