## PURPOSE
Test bounded runner-owner UID/GID binding within the already explicitly authorized fixed sudo/unshare synthetic preflight. Preserve the user/network/mount/PID namespace layers, kernel restrictions, application-disabled flags and read-only workflow permissions.

## RISK
The prior bootstrap failed with Permission denied before controls. Static review identifies a possible mismatch when sudo changes the effective host owner used by map-root-user. The exact denied operation remains UNKNOWN. UID/GID mapping must be deterministic, one-ID-only and reject host-root/wildcard identities.

## POLICY LINK
Baseline AGENTS.md; existing fail-closed evidence and authorization boundaries; PB-023/PB-026 generated metadata contracts. PB-375 is a new administrative validation work identifier, not an adopted policy or operational grant.

## REQUIRED APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE CHECKS
- Owner directed a bounded UID/GID repair batch on PR427 with at most three new-head CI cycles after evidence-backed corrections. This is cycle1. No unchanged-run retry.
- Keep the fixed sudo/unshare prefix and workflow bytes unchanged; no further privilege widening, sudo command, kernel-policy relaxation or fallback.
- Map only the original nonroot controller UID/GID to inner0, count1; deny invalid/root/string IDs, require supported mapping syntax and verify child source ownership.
- No mail/application tests, provider or release issuance, production changes, merge, deployment or activation. Stop at success, budget exhaustion or a new authority boundary.
- Every outcome must bind exact source and preserve the verified report/checksum. Independent exact-head review is still required before merge.

## AUDIT
Review base 53e4c0efea5d5f67c91f70ba6b2b488b067d1530 tree 33666efe14a83dfa867499c888bbafc1d0ac7250. Historical controller intake was verified byte-for-byte against SHA256 16890c0ad83f6d124e6a9d63f7350aa7d615f1bfa2d4bfc0965508725bf0746c. Sixteen local result-contract unit tests passed under Python3.12.14; Python/probe AST and YAML structure checks passed. The reused kernel_restrictions function AST is unchanged. Native CI is pending; old 475-case and historical 497-case reports are not new proof. First published head4441e83595d5968fc8795cf74a9c4a3beccd8512: preflight run42088455208 attempt1 failed with child_exit1 and no controls, while its sixteen contract tests passed. Archive and inner report checksums verified; artifact13444091930 retained. Separate governance run42088455138 passed 2839 tests and194 subtests. Local follow-up: twenty unique contract/diagnostic tests PASS, four new. No new CI outcome claimed at publication. Diagnostics head4ce82a3406a6d56f3844b5ad79b7e4621bc45dd2: run42089788419 attempt1 passed20 unit tests and failed isolation setup with child_exit1 and no controls. Saved archive SHA256 d038584b68d72afcf9dae71b9327e9c263e286137b72d7ad79e62ef1df16ae96 and inner report checksum verified. Governance run42089788566 passed2839 tests and194 subtests. Prepared bootstrap proposal passes24 pure local tests; no local privileged execution occurred. Explicit bootstrap heade66b5f10bd026b5d4b0f1f1212982472d6fbd70c: run42091415750 attempt1 passed24 pure tests but failed preflight with child_exit2, Permission denied and no controls. Artifact13445861318 SHA256 c8832e29020299e91a4bfd68a7d1392d264f3b2e22d9220737905b355233be4c verified with inner checksum. Governance run42091415672 passed2839 tests and194 subtests. Current prepared owner/version proposal:34 pure local tests PASS; privileged execution not performed locally.

## IMPACT
Reduce the mapping to the original nonroot runner owner while retaining the existing sandbox. Test only synthetic controls; no result grants product execution authority or production readiness.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL
## MECHANISM
The parent records its actual numeric effective UID/GID before sudo. Privileged unshare explicitly maps exactly those single host IDs to inner0, denies supplementary groups and selects inner UID/GID0. The child checks source-directory ownership before mounting. Recognized util-linux2.x >=2.39 is required; malformed/old/unknown versions fail before launch. Default unprivileged mode, fixed sudo prefix, workflow bytes and kernel function remain unchanged.

## GAP
Owner-binding effectiveness remains NOT_PROVEN until exact-head native evidence. Previous permission-denial cause is not asserted as proven. Synthetic controls remain bounded, not exhaustive. Full command-grammar review, mail-suite integration, transitive dependency equivalence, startup/release/provider authority and production readiness remain open.

## VALIDATION
34 unique local pure tests PASS, including ten new owner/version tests. Kernel and sudo-prefix ASTs and workflow bytes unchanged. Bounded repair cycle1 of maximum3. Inspect native control outcomes and verified artifacts; make another cycle only after a diagnosed source correction within the same authority.

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
Historical explicit-bootstrap CI:24 pure tests PASS; preflight FAILED before controls. Current owner-mapping candidate:34 local tests PASS; native CI pending at publication. No mail tests or privileged local execution performed.

## ROLLBACK PLAN
Do not merge a failed candidate. Prepare any later source reversal only within separately authorized scope, preserving the audit trail and reports.

## COMMIT OR SOURCE REFERENCE
Base 53e4c0efea5d5f67c91f70ba6b2b488b067d1530; original controller SHA256 16890c0ad83f6d124e6a9d63f7350aa7d615f1bfa2d4bfc0965508725bf0746c; private review package Library file libfile_7a67f7b5423c8191a980efdb64289777 version1. No library access is required for CI. Diagnostics parent4441e83595d5968fc8795cf74a9c4a3beccd8512; prior failure run42088455208; archive SHA256 76e35516c9e1d2364a26dc73aaa9508e53769a7266655e964ebadf8f937edf83. Explicit-bootstrap parent4ce82a3406a6d56f3844b5ad79b7e4621bc45dd2; saved review package libfile_7a67f7b5423c8191a980efdb64289777 version3. GitHub platform reference: https://docs.github.com/en/actions/reference/runners/github-hosted-runners . Owner-mapping parente66b5f10bd026b5d4b0f1f1212982472d6fbd70c; saved review package libfile_7a67f7b5423c8191a980efdb64289777 version4; unshare primary reference https://man7.org/linux/man-pages/man1/unshare.1.html .
