# USBAY Governance Synchronization Layer

Purpose: define the architecture required to synchronize Notion Architecture Sources, GitHub Repository Evidence, Codex Audit Generation, and Euria Independent Validation.

Status: design only.

Runtime impact: none.

## 1. Source-of-Truth Declaration

USBAY architecture governance requires explicit source-of-truth separation:

| Domain | Source of Truth | Evidence Requirement |
|---|---|---|
| Architecture intent | Notion architecture source pages | Exported Markdown, source URL or page ID, version identifier, export timestamp, content hash |
| Runtime implementation | GitHub repository | Repository path, commit SHA, code evidence, test evidence |
| Audit generation | Codex audit dossier | Audit file path, audit timestamp, source references, findings, blocker mapping |
| Independent validation | Euria Project | Uploaded knowledge base version, model version if available, test execution report, certification decision |

No source may silently override another source.

If source evidence is missing:

Decision: BLOCKED.

## 2. Export Workflow

1. Identify approved Notion architecture source pages.
2. Export each source page to Markdown.
3. Store exported Markdown under `docs/architecture/source/`.
4. Record source URL or page ID.
5. Record export timestamp.
6. Record source version or last edited timestamp.
7. Compute SHA256 content hash of the exported Markdown.
8. Commit exports to the repository.
9. Update `ARCHITECTURE_SOURCE_MANIFEST.md`.
10. Update claim-level traceability.
11. Generate or update Codex audit dossier.
12. Upload synchronized package to Euria for independent validation.

Export is not complete until the exported Markdown, metadata, hash, and repository commit SHA are all present.

## 3. Metadata Model

Each synchronized source document must include:

```text
source_title:
source_type:
source_system:
source_url_or_id:
source_owner:
source_version:
source_last_edited_at:
exported_at:
exported_by:
repository_path:
repository_commit_sha:
content_sha256:
approval_status:
approval_evidence:
certification_status:
```

Each traceability claim must include:

```text
claim_id:
source_document:
source_section:
source_claim:
repository_file:
code_evidence:
test_evidence:
audit_evidence:
status:
blocker_id:
closure_evidence:
```

## 4. Hash Verification Model

Hash verification must be deterministic:

1. Normalize exported Markdown as UTF-8.
2. Compute SHA256 over exact exported file bytes.
3. Store the hash in `ARCHITECTURE_SOURCE_MANIFEST.md`.
4. Recompute hash during audit generation.
5. Block certification on mismatch.

Hash mismatch outcome:

Decision: BLOCKED.

Reasons that must block:

- Missing source file.
- Missing content hash.
- Hash mismatch.
- Source URL missing.
- Source version missing.
- Export timestamp missing.
- Repository commit SHA missing.

## 5. Traceability Lifecycle

Traceability states:

- `OPEN`: source claim or required evidence is missing.
- `PARTIAL`: source and some repository evidence exist, but test or audit evidence is incomplete.
- `CLOSED`: source claim, repository implementation, test evidence, and audit evidence are all present.
- `BLOCKED`: claim conflicts with repository evidence or lacks required governance evidence.

Lifecycle:

1. Export source document.
2. Extract architecture claims.
3. Assign stable claim IDs.
4. Map claim to repository file.
5. Map claim to code evidence.
6. Map claim to test evidence.
7. Map claim to audit evidence.
8. Mark unmapped claims `OPEN`.
9. Mark conflicting claims `BLOCKED`.
10. Mark complete claims `CLOSED`.

No claim is certifiable until status is `CLOSED`.

## 6. Audit Lifecycle

Audit generation lifecycle:

1. Read source manifest.
2. Verify source file hashes.
3. Read traceability matrix.
4. Confirm each claim has source, code, test, and audit evidence.
5. Identify gaps, risks, blockers, and attack paths.
6. Generate audit dossier under `docs/audits/`.
7. Record certification blockers.
8. Preserve fail-closed recommendations.

Audit output must separate:

- Verified facts.
- Assumptions.
- Risks.
- Gaps.
- Attack paths.
- Required controls.
- Open questions.

Human approval must not replace audit evidence.

## 7. Certification Lifecycle

Certification lifecycle:

1. Confirm source exports are complete.
2. Confirm source hashes match manifest.
3. Confirm claim-level traceability is complete.
4. Confirm repository tests pass.
5. Confirm audit blockers are closed.
6. Upload synchronized knowledge base to Euria.
7. Execute Euria regression tests.
8. Record Euria certification report.
9. Approve certification only if every required control is evidenced.

Allowed certification outcomes:

- `CERTIFIED`
- `BLOCKED`

Certification must be `BLOCKED` if:

- Any source export is missing.
- Any content hash is missing or mismatched.
- Any claim remains `OPEN`.
- Any blocker remains `OPEN`.
- Any required test evidence is missing.
- Any Euria regression test fails.
- Any human approval lacks audit evidence.

## 8. Synchronization Responsibilities

| Actor/System | Responsibility | Must Not Do |
|---|---|---|
| Notion | Maintain architecture intent | Replace repository implementation evidence |
| GitHub | Preserve implementation, tests, and audit docs | Treat undocumented source claims as implemented |
| Codex | Generate evidence-based audit dossiers | Fabricate missing source details |
| Euria | Independently validate fail-closed behavior | Accept claims without uploaded evidence |
| Human reviewer | Approve or reject certification package | Replace missing audit evidence with verbal approval |

## 9. Required Artifacts

- `docs/architecture/source/ARCHITECTURE_SOURCE_MANIFEST.md`
- `docs/architecture/CLAIM_LEVEL_TRACEABILITY_MATRIX.md`
- `docs/architecture/ARCHITECTURE_CERTIFICATION_BLOCKERS.md`
- `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md`
- Euria upload package.
- Euria regression execution report.
- Certification report.

## 10. Fail-Closed Rule

If source, implementation, test, audit, or validation evidence is incomplete:

Decision: BLOCKED.

If a requested fact is not provided:

Information not provided.

No certification may proceed from assumptions.
