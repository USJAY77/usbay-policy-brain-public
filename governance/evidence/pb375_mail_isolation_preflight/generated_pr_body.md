## PURPOSE
Repair exact runner-owner UID/GID mapping and supplementary-group ordering for synthetic isolation only, using separately authorized temporary mapping permissions on a disposable CI runner. This is repair cycle1 of maximum2.

## RISK
Native run42094437881 proves newuidmap rejected the requested range before controls. Static util-linux2.39.3 review identifies --setgroups=deny before force_gid setgroups as a second ordering conflict. Temporary OS policy writes and privileged bootstrap require strict source, owner, scope, update and restoration checks.

## POLICY LINK
Baseline AGENTS.md; existing fail-closed evidence and authorization boundaries; PB-023/PB-026 generated metadata contracts. PB-375 is a new administrative validation work identifier, not an adopted policy or operational grant.

## REQUIRED APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE CHECKS
- Owner authorized this bounded implementation/publication batch and at most two new-head synthetic CI rounds. A second round requires an evidence-backed in-scope correction; no unchanged retry.
- Permit only temporary root:<original nonroot runner UID>:1 and root:<original nonroot runner GID>:1 entries on one disposable hosted CI runner. Preserve existing entries, permissions and metadata; reject unsafe/ambiguous/concurrently changed policy.
- Fixed bootstrap checks sudo caller, repository owner, exact head and committed source bytes. Clear supplementary groups before unshare; retain deny and verify exact maps/IDs/groups before controls.
- No sudoers changes, packages, kernel relaxation, broad/root-host mappings, persistent/shared runner use, arbitrary privileged command or fallback.
- No mail/application tests, provider/release issuance, product authority, merge, deployment or activation. Stop at success, budget exhaustion or a different permission boundary.
- Exact-head independent human review remains required before any merge. Synthetic success never establishes production readiness.

## AUDIT
Review base 53e4c0efea5d5f67c91f70ba6b2b488b067d1530 tree 33666efe14a83dfa867499c888bbafc1d0ac7250. Historical controller intake was verified byte-for-byte against SHA256 16890c0ad83f6d124e6a9d63f7350aa7d615f1bfa2d4bfc0965508725bf0746c. Sixteen local result-contract unit tests passed under Python3.12.14; Python/probe AST and YAML structure checks passed. The reused kernel_restrictions function AST is unchanged. Native CI is pending; old 475-case and historical 497-case reports are not new proof. First published head4441e83595d5968fc8795cf74a9c4a3beccd8512: preflight run42088455208 attempt1 failed with child_exit1 and no controls, while its sixteen contract tests passed. Archive and inner report checksums verified; artifact13444091930 retained. Separate governance run42088455138 passed 2839 tests and194 subtests. Local follow-up: twenty unique contract/diagnostic tests PASS, four new. No new CI outcome claimed at publication. Diagnostics head4ce82a3406a6d56f3844b5ad79b7e4621bc45dd2: run42089788419 attempt1 passed20 unit tests and failed isolation setup with child_exit1 and no controls. Saved archive SHA256 d038584b68d72afcf9dae71b9327e9c263e286137b72d7ad79e62ef1df16ae96 and inner report checksum verified. Governance run42089788566 passed2839 tests and194 subtests. Prepared bootstrap proposal passes24 pure local tests; no local privileged execution occurred. Explicit bootstrap heade66b5f10bd026b5d4b0f1f1212982472d6fbd70c: run42091415750 attempt1 passed24 pure tests but failed preflight with child_exit2, Permission denied and no controls. Artifact13445861318 SHA256 c8832e29020299e91a4bfd68a7d1392d264f3b2e22d9220737905b355233be4c verified with inner checksum. Governance run42091415672 passed2839 tests and194 subtests. Current prepared owner/version proposal:34 pure local tests PASS; privileged execution not performed locally. Owner-mapping cycle1 head1cc00d1c5a21898f5070d24598d2b5dc4868a73f, run42093576550 attempt1, failed before controls with child_exit1 and no prior categorized launcher error. Verified artifact13447015748 SHA256 e894b7b53088a26b7b331f0ebec066f094217a9ef9e7c32ce8ed9e526ae33367 and inner checksum. util-linuxv2.39.3 source shows range mappings invoke external ID-map helpers; native cause remains UNKNOWN until this diagnostic cycle. Thirty-eight local pure tests PASS. Owner-mapping cycle2 head663ca06be84c1ff2694bc2f2f600cf9e6ce56f94: native run42094437881 failed with UID_MAP_HELPER_ERROR / ID_RANGE_NOT_ALLOWED before controls. Archive SHA2564c9130cacab9ff1ecb19d9dcb9d7b1b066c9415c78b05c52732e45e63c482768 and inner checksum verified. Thirty-eight native pure tests and separate2839 governance tests plus194 subtests passed. The previous three-cycle batch stopped after two; no third retry. New repair candidate:60 local pure tests passed; kernel function AST unchanged. No local privileged execution. New-head native repair result pending.

## IMPACT
Close the runner setup defect without weakening product governance. Mapping permissions are CI OS setup only, not USBAY execution authority. Keep the PR Draft and unmerged pending actual validation and review.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL
## MECHANISM
Fixed bootstrap with caller/source binding; locked, bounded subordinate-ID extension and exact restoration; groups cleared before unshare; no force-setgid CLI option; child setresgid then proves exact maps, IDs and denied setgroups. Fresh child independently proves IDs/groups/denied syscall. All original ten controls, existing kernel restrictions and policy restoration are mandatory.

## GAP
Native isolation for this candidate is UNKNOWN. The original failure is preserved. Bootstrap is scoped to a disposable hosted runner, not a hardened multi-tenant service; a malicious concurrent root/owner process is outside this in-job source/lock boundary. Full command grammar, mail-suite integration, release/provider authority and EGAP-HYDRA-REMOTE-TRANSPORT-AUTH remain open.

## VALIDATION
60 unique local pure tests PASS; AST checks PASS; kernel function AST unchanged. No local sudo/namespace/host policy operation. Native CI pending, repair cycle1 of maximum2.

## ROLLBACK
Restore only exact known mapping writes in finally; refuse to overwrite unexpected concurrent state. On failure, prevent synthetic success and preserve evidence. Runner disposal remains required. Do not merge a failed candidate.

## SOURCE
https://github.com/USJAY77/usbay-policy-brain-public/commit/53e4c0efea5d5f67c91f70ba6b2b488b067d1530

## CHANGED FILES
- validation/mail_readiness/README.md
- validation/mail_readiness/isolation_preflight.py
- validation/mail_readiness/result_contract.py
- validation/mail_readiness/test_result_contract.py
- validation/mail_readiness/runner_bootstrap.py
- validation/mail_readiness/test_runner_bootstrap.py
- .github/workflows/mail-readiness-isolation.yml
- governance/evidence/pb375_mail_isolation_preflight/metadata.json
- governance/evidence/pb375_mail_isolation_preflight/generated_pr_body.md

## VALIDATION RESULTS
60 unique local pure tests PASS; AST checks PASS; kernel function AST unchanged. No local sudo/namespace/host policy operation. Native CI pending, repair cycle1 of maximum2.

## ROLLBACK PLAN
Restore only exact known mapping writes in finally; refuse to overwrite unexpected concurrent state. On failure, prevent synthetic success and preserve evidence. Runner disposal remains required. Do not merge a failed candidate.

## COMMIT OR SOURCE REFERENCE
Base 53e4c0efea5d5f67c91f70ba6b2b488b067d1530; original controller SHA256 16890c0ad83f6d124e6a9d63f7350aa7d615f1bfa2d4bfc0965508725bf0746c; private review package Library file libfile_7a67f7b5423c8191a980efdb64289777 version1. No library access is required for CI. Diagnostics parent4441e83595d5968fc8795cf74a9c4a3beccd8512; prior failure run42088455208; archive SHA256 76e35516c9e1d2364a26dc73aaa9508e53769a7266655e964ebadf8f937edf83. Explicit-bootstrap parent4ce82a3406a6d56f3844b5ad79b7e4621bc45dd2; saved review package libfile_7a67f7b5423c8191a980efdb64289777 version3. GitHub platform reference: https://docs.github.com/en/actions/reference/runners/github-hosted-runners . Owner-mapping parente66b5f10bd026b5d4b0f1f1212982472d6fbd70c; saved review package libfile_7a67f7b5423c8191a980efdb64289777 version4; unshare primary reference https://man7.org/linux/man-pages/man1/unshare.1.html . Cycle2 parent1cc00d1c5a21898f5070d24598d2b5dc4868a73f; util-linux primary source https://github.com/util-linux/util-linux/blob/v2.39.3/sys-utils/unshare.c . Repair parent663ca06be84c1ff2694bc2f2f600cf9e6ce56f94; primary group-order sources https://github.com/util-linux/util-linux/blob/v2.39.3/sys-utils/unshare.c and https://github.com/shadow-maint/shadow/blob/4.13/src/newgidmap.c .
