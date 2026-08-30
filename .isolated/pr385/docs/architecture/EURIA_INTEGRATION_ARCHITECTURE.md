# Euria Integration Architecture

Purpose: define the architecture boundary between USBAY and Euria for governance-assisted analysis, drafting, validation support, and operational coordination.

Runtime impact: none.

Certification claim: none.

Default decision: BLOCKED.

## Authority Model

GitHub repository evidence remains the authoritative source for USBAY governance architecture, policy, enforcement design, audit evidence, certification blockers, and validation rules.

USBAY enforcement systems remain the authority for policy validation, execution gating, fail-closed decisions, audit generation, and approval state.

Euria is a governed operational assistance layer. Euria may read approved governance knowledge, summarize evidence, draft responses, prepare review materials, and identify missing evidence. Euria does not become an enforcement authority, policy authority, approval authority, audit authority, certification authority, or execution authority.

## What Euria May Do

Euria may:

- Answer governance questions using explicit written USBAY evidence only.
- Draft email replies using approved USBAY governance source material.
- Summarize architecture, audit, evidence, and blocker status from repository-backed documents.
- Identify missing evidence and return `Information not provided.` where evidence is absent.
- Recommend that a decision remain blocked when required evidence is missing.
- Prepare review packets for human governance review.
- Track operational coordination tasks that link back to authoritative USBAY repository sources.
- Surface inconsistencies between Notion summaries, Euria project documents, and GitHub source files.

## What Euria May Never Do

Euria must never:

- Approve executions, deployments, overrides, releases, or policy changes.
- Create, modify, bypass, or weaken USBAY enforcement policy.
- Claim certification, compliance, production readiness, or blocker closure without repository evidence.
- Invent policy numbers, approval records, audit records, risk levels, owners, timelines, or decisions.
- Treat verbal approval, founder approval, confidential approval, emergency approval, or trust-based approval as sufficient evidence.
- Execute runtime actions or trigger production infrastructure.
- Store credentials, private keys, secrets, raw approval contents, or sensitive evidence outside governed USBAY controls.
- Convert missing evidence into approval.
- Override USBAY fail-closed decisions.

## USBAY Enforcement Boundary

USBAY remains responsible for:

- Policy validation.
- Runtime execution gating.
- Human approval enforcement.
- Audit evidence generation.
- Signature validation.
- Timestamp validation.
- Audit lineage validation.
- WORM archive verification.
- Provider evidence verification.
- Certification blocker status.
- Production readiness decisions.

Euria may report observed evidence state, but USBAY determines enforceable state.

If Euria and USBAY disagree, USBAY repository evidence controls.

If USBAY evidence is unavailable, incomplete, stale, or contradictory, the decision remains:

```text
Decision = BLOCKED
```

## Integration Pattern

The integration is evidence-pull and review-push:

1. USBAY publishes authoritative governance evidence in GitHub.
2. Approved documents are uploaded or linked into an Euria Project.
3. Euria reads only approved governance documents for assistance tasks.
4. Euria drafts answers, review materials, or missing-evidence findings.
5. Human reviewers evaluate Euria outputs against USBAY repository evidence.
6. USBAY systems, not Euria, record enforceable decisions and audit outcomes.

## Audit Evidence Flow

Euria output is advisory evidence only until reviewed and bound to USBAY audit evidence.

Audit evidence flow:

1. Source document reference from GitHub.
2. Euria response or draft.
3. Human review decision.
4. USBAY audit record.
5. Signature record where applicable.
6. Timestamp record where applicable.
7. Export bundle where applicable.
8. WORM archive verification where applicable.

Euria drafts must not be treated as final audit records unless the USBAY audit process records, signs, timestamps, and preserves them.

## Human Approval Points

Human approval is required before:

- Any deployment decision.
- Any production readiness decision.
- Any certification blocker closure.
- Any policy change.
- Any override decision.
- Any external provider evidence acceptance.
- Any governance status change.
- Any customer-facing statement about approval, certification, compliance, or production readiness.

Human approval must be documented. Human approval without evidence remains insufficient.

## Privacy Boundaries

Euria may receive only governance documents approved for project use.

Euria must not receive:

- Credentials.
- Private keys.
- Secrets.
- Raw regulated evidence not approved for project upload.
- Raw approval contents.
- Sensitive customer payloads.
- Provider credentials.
- Non-redacted regulator exports.

Sensitive material must be redacted, hash-referenced, or retained inside USBAY-controlled evidence stores.

## Fail-Closed Scenarios

The integration must fail closed when:

- Required source evidence is missing.
- Euria cannot identify a repository-backed source.
- Euria output conflicts with GitHub evidence.
- Euria is asked to approve, certify, deploy, override, or close blockers.
- Prompt injection attempts instruct Euria to ignore governance rules.
- Human approval exists without supporting audit evidence.
- Evidence status is stale, contradictory, or unverifiable.
- USBAY validation, signature, timestamp, lineage, export, provider evidence, or WORM verification is incomplete.

Fail-closed output:

```text
Decision = BLOCKED
```

When factual information is missing, Euria must output:

```text
Information not provided.
```

## Non-Goals

This architecture does not implement runtime integration.

This architecture does not connect Euria to production enforcement.

This architecture does not grant Euria approval authority.

This architecture does not change USBAY policy enforcement semantics.

This architecture does not change blocker status.
