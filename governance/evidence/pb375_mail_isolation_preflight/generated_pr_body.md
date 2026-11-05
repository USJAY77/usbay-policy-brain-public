## PURPOSE
Validate synthetic fresh-child isolation on a disposable GitHub-hosted Ubuntu runner using the explicitly owner-authorized fixed sudo/unshare namespace bootstrap. The parent controller remains unprivileged. No application or mail test runs.

## RISK
Previous unprivileged launcher failed before controls with Operation not permitted/write failed; the exact denied operation remains UNKNOWN. Privileged namespace setup adds CI OS privilege use and therefore requires explicit owner scope. A green synthetic preflight is not a production or general sandbox guarantee.

## POLICY LINK
Baseline AGENTS.md; existing fail-closed evidence and authorization boundaries; PB-023/PB-026 generated metadata contracts. PB-375 is a new administrative validation work identifier, not an adopted policy or operational grant.

## REQUIRED APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE CHECKS
- Owner explicitly authorized publication of the prepared proposal on PR427 and exactly one CI cycle with the fixed sudo/unshare startup, excluding merge/deployment/activation.
- Additional privilege applies only to the fixed noninteractive namespace launcher on the ephemeral runner. No arbitrary sudo command, fallback or automatic retry.
- Exact-head checkout, contents:read, no persisted credentials or dependency installation. No sysctl/AppArmor/seccomp relaxation.
- The historical kernel restriction function remains AST-identical. Capabilities are dropped and controls must succeed before any synthetic success claim.
- No provider/mail/application execution, release issuance, product policy change, operational grant or change to active Replit. Two independent exact-head reviews remain necessary before merge.

## AUDIT
Review base 53e4c0efea5d5f67c91f70ba6b2b488b067d1530 tree 33666efe14a83dfa867499c888bbafc1d0ac7250. Historical controller intake was verified byte-for-byte against SHA256 16890c0ad83f6d124e6a9d63f7350aa7d615f1bfa2d4bfc0965508725bf0746c. Sixteen local result-contract unit tests passed under Python3.12.14; Python/probe AST and YAML structure checks passed. The reused kernel_restrictions function AST is unchanged. Native CI is pending; old 475-case and historical 497-case reports are not new proof. First published head4441e83595d5968fc8795cf74a9c4a3beccd8512: preflight run42088455208 attempt1 failed with child_exit1 and no controls, while its sixteen contract tests passed. Archive and inner report checksums verified; artifact13444091930 retained. Separate governance run42088455138 passed 2839 tests and194 subtests. Local follow-up: twenty unique contract/diagnostic tests PASS, four new. No new CI outcome claimed at publication. Diagnostics head4ce82a3406a6d56f3844b5ad79b7e4621bc45dd2: run42089788419 attempt1 passed20 unit tests and failed isolation setup with child_exit1 and no controls. Saved archive SHA256 d038584b68d72afcf9dae71b9327e9c263e286137b72d7ad79e62ef1df16ae96 and inner report checksum verified. Governance run42089788566 passed2839 tests and194 subtests. Prepared bootstrap proposal passes24 pure local tests; no local privileged execution occurred.

## IMPACT
Test one explicitly selected privileged namespace bootstrap while preserving the application-disabled flags and every existing isolation requirement. Publish a verified bounded report/checksum; do not infer authority or deployment readiness from it.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL
## MECHANISM
An explicit CLI flag selects the fixed argv prefix /usr/bin/sudo --non-interactive -- /usr/bin/unshare for namespace creation. The default path remains unprivileged and never falls back automatically. Existing chroot/read-only mounts, capability dropping and unchanged Landlock/seccomp precede the ten fresh-child controls. The chosen mode is recorded.

## GAP
Privileged bootstrap effectiveness is NOT_PROVEN until this exact-head CI run. The precise original denied operation remains UNKNOWN. The synthetic control set is not an exhaustive sandbox proof; inherited in-flight connections, command grammar, complete mail-suite integration, transitive dependencies, release/provider authority and production readiness remain outside this proposal.

## VALIDATION
Local proposal:24 unique pure standard-library tests PASS, including four fixed-launcher-argument tests. Python/YAML validation and unchanged kernel-function AST PASS. One new-head CI cycle authorized. Download and verify its source-bound report/checksum whether successful or failed. No automatic retry.

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
Previous diagnostic native preflight:20 unit tests PASS; namespace setup FAILED, no controls/application tests. Proposed bootstrap:24 local tests PASS; new native result PENDING at publication. Historical review-package labels remain preparation snapshots; publication authority is recorded separately here.

## ROLLBACK PLAN
Do not merge a failed candidate. Prepare any later source reversal only within separately authorized scope, preserving the audit trail and reports.

## COMMIT OR SOURCE REFERENCE
Base 53e4c0efea5d5f67c91f70ba6b2b488b067d1530; original controller SHA256 16890c0ad83f6d124e6a9d63f7350aa7d615f1bfa2d4bfc0965508725bf0746c; private review package Library file libfile_7a67f7b5423c8191a980efdb64289777 version1. No library access is required for CI. Diagnostics parent4441e83595d5968fc8795cf74a9c4a3beccd8512; prior failure run42088455208; archive SHA256 76e35516c9e1d2364a26dc73aaa9508e53769a7266655e964ebadf8f937edf83. Explicit-bootstrap parent4ce82a3406a6d56f3844b5ad79b7e4621bc45dd2; saved review package libfile_7a67f7b5423c8191a980efdb64289777 version3. GitHub platform reference: https://docs.github.com/en/actions/reference/runners/github-hosted-runners .
