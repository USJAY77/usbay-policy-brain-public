# USBAY Architecture Source-of-Truth Policy

Purpose: establish a verifiable architecture source-of-truth process for USBAY architecture certification.

Runtime impact: none.

Certification status: BLOCKED until required evidence exists.

## 1. Authority Model

### GitHub Source Authority

GitHub is the authority for:

- Runtime implementation.
- Policy validation code.
- Enforcement gateway behavior.
- Hydra consensus implementation.
- Audit and evidence implementation.
- Tests.
- CI and validation evidence.
- Versioned architecture reconciliation records.
- Certification blocker records.

GitHub evidence must include repository path, commit SHA, code evidence, test evidence, and audit evidence where applicable.

### Notion Documentation Authority

Notion is the authority for:

- Architecture intent.
- Architecture narrative.
- Architecture diagrams.
- Design rationale.
- Source architecture page ownership.
- Architecture document revision history when exported.

Notion documentation does not prove runtime implementation. Notion claims must be mapped to GitHub repository evidence before certification.

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
2. Record the conflicting Notion source claim.
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

Each Notion architecture source must be exported to Markdown and stored under:

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

## 4. Evidence Requirements

Every architecture claim requires:

- Source evidence from Notion export.
- Repository implementation evidence from GitHub.
- Test evidence.
- Audit evidence if the claim affects governance decisions, approvals, deployment, enforcement, audit, evidence, or certification.
- Closure evidence in the blocker lifecycle.

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
- Source export exists.
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
| Notion source availability | Markdown export, source URL or page ID, export timestamp, version identifier, content hash. | Source manifest updated, hash verified, repository commit SHA recorded, certification report updated. |
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

Certification Blocker #001 is the Notion source availability blocker.

It may move from `OPEN` to `VERIFIED` only when all five architecture sources are exported to Markdown with:

- Source URL or stable page ID.
- Export timestamp.
- Version identifier.
- Content hash.
- Repository path.

It may move from `VERIFIED` to `CLOSED` only when:

- `ARCHITECTURE_SOURCE_MANIFEST.md` is updated.
- All source hashes verify.
- Repository commit SHA is recorded.
- Claim-level traceability references the exported sources.
- Certification report records closure.

Current status:

OPEN.

Reason:

Information not provided.
