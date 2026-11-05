## PURPOSE
Run a synthetic fresh-child isolation preflight on an ephemeral Ubuntu CI runner before any future Governed Mail application validation. This proposal does not run or transfer the unpublished Replit mail implementation. Add bounded diagnostics for the first observed setup/child failure without altering the sandbox policy or rerunning the old unchanged candidate.

## RISK
Local/Replit isolation probes failed and later Replit candidate/evidence disappeared within bounded recovery searches. An incomplete control or test inventory must not be reported as success. CI capability success must not become execution authority or a production claim. The initial artifact recorded only a generic setup failure; exposing raw stdout/stderr would risk leaking host data, while omitting the stage prevents diagnosis.

## POLICY LINK
Baseline AGENTS.md; existing fail-closed evidence and authorization boundaries; PB-023/PB-026 generated metadata contracts. PB-375 is a new administrative validation work identifier, not an adopted policy or operational grant.

## REQUIRED APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE CHECKS
- Owner authorized publication of this prepared preflight candidate as a Draft PR and one CI validation cycle; no automatic rerun.
- All five technical files must match the saved review package hashes. Only generated governance metadata is added.
- Exact PR-head checkout, contents:read only, no persisted credentials, no sudo, no dependency installation or privileged fallback.
- Synthetic canaries only; no application tests, provider access, release issuance, real mailbox data or execution authority.
- No merge, deployment, activation, trust/permission broadening or alteration of the active Replit app. Two independent exact-head reviews remain required before merge.
- Owner authorized this diagnostics-only publication and exactly one new-head CI cycle. Preserve workflow bytes, kernel restriction AST and application-execution-disabled flags. No automatic rerun.

## AUDIT
Review base 53e4c0efea5d5f67c91f70ba6b2b488b067d1530 tree 33666efe14a83dfa867499c888bbafc1d0ac7250. Historical controller intake was verified byte-for-byte against SHA256 16890c0ad83f6d124e6a9d63f7350aa7d615f1bfa2d4bfc0965508725bf0746c. Sixteen local result-contract unit tests passed under Python3.12.14; Python/probe AST and YAML structure checks passed. The reused kernel_restrictions function AST is unchanged. Native CI is pending; old 475-case and historical 497-case reports are not new proof. First published head4441e83595d5968fc8795cf74a9c4a3beccd8512: preflight run42088455208 attempt1 failed with child_exit1 and no controls, while its sixteen contract tests passed. Archive and inner report checksums verified; artifact13444091930 retained. Separate governance run42088455138 passed 2839 tests and194 subtests. Local follow-up: twenty unique contract/diagnostic tests PASS, four new. No new CI outcome claimed at publication.

## IMPACT
Produce a bounded downloadable isolation report/checksum with thirty-day retention. Unsupported setup or incomplete controls fails CI. The report permanently sets application_tests_run, application_execution_enabled and production_ready to false.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL
## MECHANISM
A path-filtered PR workflow pins checkout/upload actions to immutable commits and verifies the exact head. Standard-library unit tests precede namespace/chroot/capability/Landlock/seccomp setup and ten exact fresh-child controls. Reports and SHA256SUMS are uploaded even on failure; missing artifacts also fail the job. Record fixed setup-stage identifiers, allowlisted exception types, integer errno and exact error-category matches. Never persist raw child stdout/stderr. Unknown, malformed or oversized child output remains UNKNOWN. No fallback or success criterion is relaxed.

## GAP
First-head CI isolation FAILED before controls; exact setup phase remains UNKNOWN in that preserved artifact. This follow-up has not yet run in CI. CI isolation is NOT_PROVEN. The inherited historical syscall filter is not an exhaustive sandbox proof. The original Python command grammar is not applied by this capability probe. The future suite-completeness helper is not wired into the Replit controller. No mail test selection, dependency equivalence, startup acceptance, issued release manifest, provider integration or production readiness is established.

## VALIDATION
Reuse local evidence for the unchanged five-file candidate. One first-head CI cycle is authorized. Inspect the synthetic report, checksum, exact source identity and exit code. Repository default PR checks may also run; their labels do not establish production readiness.

## ROLLBACK
Keep the proposal unmerged if native validation fails. Any future removal must preserve failure evidence; do not reset replay state or erase historical records.

## SOURCE
https://github.com/USJAY77/usbay-policy-brain-public/commit/53e4c0efea5d5f67c91f70ba6b2b488b067d1530

## CHANGED FILES
- .github/workflows/mail-readiness-isolation.yml
- validation/mail_readiness/README.md
- validation/mail_readiness/isolation_preflight.py
- validation/mail_readiness/result_contract.py
- validation/mail_readiness/test_result_contract.py
- governance/evidence/pb375_mail_isolation_preflight/metadata.json
- governance/evidence/pb375_mail_isolation_preflight/generated_pr_body.md

## VALIDATION RESULTS
Initial CI: 16 result-contract tests PASS; isolation setup FAILED; verified report uploaded. Local diagnostics-only follow-up: 20 unique tests PASS including four new redaction/classification tests; kernel function AST unchanged. New-head CI pending. Historical preparation labels remain snapshots, not current authority or proof.

## ROLLBACK PLAN
Do not merge a failed candidate. Prepare any later source reversal only within separately authorized scope, preserving the audit trail and reports.

## COMMIT OR SOURCE REFERENCE
Base 53e4c0efea5d5f67c91f70ba6b2b488b067d1530; original controller SHA256 16890c0ad83f6d124e6a9d63f7350aa7d615f1bfa2d4bfc0965508725bf0746c; private review package Library file libfile_7a67f7b5423c8191a980efdb64289777 version1. No library access is required for CI. Diagnostics parent4441e83595d5968fc8795cf74a9c4a3beccd8512; prior failure run42088455208; archive SHA256 76e35516c9e1d2364a26dc73aaa9508e53769a7266655e964ebadf8f937edf83.
