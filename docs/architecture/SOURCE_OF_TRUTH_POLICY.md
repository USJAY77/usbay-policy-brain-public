# USBAY Architecture Source-of-Truth Policy

Purpose: establish a verifiable architecture source-of-truth process for USBAY architecture certification.

Runtime impact: none.

Certification status: BLOCKED until all required certification evidence exists.

Source-of-truth decision recorded: 2026-06-02.

Decision evidence: all five referenced Notion architecture pages were inspected and found to contain title-only content. No architecture claims, controls, diagrams, implementation requirements, or certification evidence were present in those pages.

## 1. Authority Model

### GitHub Source Authority

GitHub is the authority for:

- Architecture source of truth.
- Runtime implementation.
- Policy validation code.
- Enforcement gateway behavior.
- Hydra consensus implementation.
- Audit and evidence implementation.
- Tests.
- CI and validation evidence.
- Architecture documentation with substantive content.
- Versioned architecture reconciliation records.
- Certification blocker records.

GitHub evidence must include repository path, commit SHA, code evidence, test evidence, and audit evidence where applicable.

### Notion Placeholder Status

The inspected Notion architecture pages are non-authoritative placeholders/navigation pages.

They are not the authority for:

- Architecture intent.
- Architecture narrative.
- Architecture diagrams.
- Design rationale.
- Runtime implementation.
- Governance controls.
- Certification claims.
- Audit evidence.

Because the inspected Notion pages contain title-only content, there are no Notion architecture claims to export, hash, reconcile, or certify.

If future Notion pages are populated with substantive architecture content, those pages must be treated as proposed documentation until reconciled against GitHub repository evidence. Notion documentation must not supersede GitHub repository evidence without a governed source-of-truth decision and audit record.

### Euria Validation Authority

Euria is the independent validation authority for:

- Knowledge-base ingestion.
- Evidence-only response behavior.
- Prompt-injection resistance.
- Regression test execution.
- Certification report generation.

Euria validation does not replace source exports, repository tests, or audit evidence.

### Codex Audit Authority

Codex audit dossiers are evidence synthesis artifacts. They may identify risks, gaps, attack paths, and blockers, but they must not fabricate source details or close blockers without evidence.

## 2. Conflict Resolution Workflow

If Notion and GitHub conflict:

1. Mark the claim `OPEN`.
2. Record the conflicting Notion source claim, or record `Information not provided` when the Notion page contains no substantive claim.
3. Record the conflicting GitHub repository evidence.
4. Determine whether the conflict is documentation drift or implementation drift.
5. Create a remediation issue or branch scoped to one governance capability.
6. Require human review.
7. Require updated source export, repository evidence, tests, and audit record.
8. Move the claim to `VERIFIED` only after evidence is complete.
9. Move the claim to `CLOSED` only after certification evidence is recorded.

Conflict outcome until resolved:

Decision: BLOCKED.

Human approval must not replace missing evidence.

## 3. Export Requirements

If a Notion architecture page contains substantive architecture content, it must be exported to Markdown and stored under:

```text
docs/architecture/source/
```

Each export must include:

- Source title.
- Source URL or stable page ID.
- Source owner if available.
- Export timestamp.
- Version identifier or last edited timestamp.
- Export actor.
- Repository path.
- Repository commit SHA.
- SHA256 content hash.

If any export requirement is missing:

Decision: BLOCKED.

Current Notion status:

- The five inspected Notion architecture pages are title-only placeholders.
- No substantive architecture export exists because no substantive Notion architecture content was present.
- BLOCKER-001 remains open because the expected architecture content is absent from Notion, not because an available source failed to export.

## 4. Evidence Requirements

Every architecture claim requires:

- Source evidence from the authoritative GitHub repository architecture source.
- Repository implementation evidence from GitHub.
- Test evidence.
- Audit evidence if the claim affects governance decisions, approvals, deployment, enforcement, audit, evidence, or certification.
- Closure evidence in the blocker lifecycle.

If a Notion claim exists in the future, it must be mapped to GitHub repository evidence before it can support certification.

Missing evidence outcome:

Decision: BLOCKED.

## 5. Certification Blocker Lifecycle

### OPEN

Status meaning:

- Required evidence is missing, incomplete, unavailable, conflicting, or unverified.

Allowed certification outcome:

Decision: BLOCKED.

### VERIFIED

Status meaning:

- Required evidence has been collected and reviewed.
- Source authority evidence exists.
- Repository evidence exists.
- Test evidence exists where applicable.
- Audit evidence exists where applicable.
- No unresolved conflict remains.

Allowed certification outcome:

Decision: BLOCKED until formally closed.

### CLOSED

Status meaning:

- Evidence is complete.
- Evidence is versioned and hash-verifiable.
- Required tests passed.
- Audit record exists.
- Human approval, if required, is bound to audit evidence.
- Certification report records closure.

Allowed certification outcome:

CERTIFIED for the specific blocker only.

## 6. Certification Evidence Requirements By Blocker

| Blocker Type | Required Evidence To Move OPEN to VERIFIED | Required Evidence To Move VERIFIED to CLOSED |
|---|---|---|
| Notion source availability/content | Inspection evidence showing whether Notion contains substantive architecture content; if content exists, Markdown export, source URL or page ID, export timestamp, version identifier, and content hash. | Source manifest updated, hash verified when export content exists, repository commit SHA recorded, certification report updated. |
| Architecture traceability | Claim-level matrix mapping source claim to repository file, code evidence, test evidence, and audit evidence. | All required claims marked CLOSED with test and audit evidence. |
| External WORM evidence | WORM provider/control evidence, retention policy, legal hold model, immutable write proof, export verification. | External WORM validation passed, failure semantics audited, certification report updated. |
| Hydra production identity | Node enrollment, role mapping, key custody, rotation, revocation, remote identity, transport policy. | Hydra tests passed, consensus evidence exported, failure-mode audit recorded. |
| Remote verifier evidence | Endpoint identity proof, transport security policy, node enrollment binding, spoofing/downgrade tests. | Remote verification evidence passed and audit record stored. |
| Production certification | Production certification gate, test execution report, release evidence, deployment approval evidence. | Certification report records all blockers closed and no failed checks. |
| Audit index | Audit index format, audit ID, title, date, scope, source hash, reviewer, status. | Index committed and cross-linked to certification report. |
| Notion import/parity | Exported Notion hashes, repository document hashes, parity review record, drift decision. | Parity validated and claim-level matrix updated. |
| Human approval substitution | Written approval policy and signed audit-bound approval evidence. | Tests prove missing evidence blocks even with human approval. |
| Diagnostic leakage | Redaction profile, log scan evidence, secret/raw payload/approval/nonce detection tests. | Redaction tests pass and audit evidence is stored. |

## 7. Blocker #001 Closure Rule

Certification Blocker #001 is the Notion source availability/content blocker.

Reclassified root cause:

The five inspected Notion architecture pages contain title-only placeholder content. BLOCKER-001 is therefore caused by absence of substantive architecture content in Notion, not by export failure.

It may move from `OPEN` to `VERIFIED` only when one of the following evidence paths is complete:

1. Notion remains non-authoritative and GitHub architecture source authority is accepted through a certification record, with repository architecture claims mapped to implementation and test evidence.
2. Substantive Notion architecture pages are created and exported to Markdown with:
   - Source URL or stable page ID.
   - Export timestamp.
   - Version identifier.
   - Content hash.
   - Repository path.

It may move from `VERIFIED` to `CLOSED` only when:

- `ARCHITECTURE_SOURCE_MANIFEST.md` is updated.
- All applicable source hashes verify.
- Repository commit SHA is recorded.
- Claim-level traceability references the authoritative GitHub sources, or exported Notion sources if substantive Notion content is later created.
- Certification report records closure.

Current status:

CLOSED.

Reason:

Inspected Notion architecture pages contain title-only placeholder content and provide no substantive architecture claims. GitHub is the authoritative architecture source, and the claim-level matrix references authoritative GitHub source paths.

Closure boundary:

This closes only BLOCKER-001. It does not close claim-level traceability gaps, external WORM evidence gaps, production certification, or regulator-grade immutable storage evidence.
