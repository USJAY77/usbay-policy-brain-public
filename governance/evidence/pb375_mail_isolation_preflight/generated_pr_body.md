## PURPOSE
Correct the observed setgroups/gid_map ordering defect using a bounded exact-parent GID mapping guard. Owner separately authorized this publication and exactly one additional synthetic CI round. No merge, deployment or activation.

## RISK
Kernel proc_setgroups_write rejects deny after gid_map exists. The prior unshare sequence applied deny too late. The new root-owned guard must prove exact original owner binding, its actual parent target, a separate user namespace, an exact prior UID map and an empty GID map before denying groups and mapping one GID. No arbitrary PID, resource, command or broader range is permitted.

## POLICY LINK
Baseline AGENTS.md; existing fail-closed evidence and authorization boundaries; PB-023/PB-026 generated metadata contracts. PB-375 is a new administrative validation work identifier, not an adopted policy or operational grant.

## REQUIRED APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE CHECKS
- Owner explicitly authorized publication of the prepared exact-parent pre-map group-denial helper and one additional synthetic CI round. This extension is separate from the consumed two-round batch. No unchanged retry or second additional round.
- The root-owned ephemeral helper may access only its verified actual parent proc-directory FD and fixed uid_map/gid_map/setgroups resources. It may deny setgroups then publish exactly inner0 to original nonroot runner GID, count1, after exact UID-map verification.
- Keep source/caller/head checks, temporary subordinate-ID policy restoration, namespace layers, child identity checks, all ten synthetic controls and unchanged kernel restrictions. Missing denial or identity proof fails closed.
- No arbitrary target PID, host-root mapping, sudoers change, packages, kernel-policy relaxation, persistent/shared runner use, fallback or authority broadening.
- No mail/application tests, provider/release/product authority, merge, deployment or activation. Stop after the one authorized native round or a different permission requirement.
- Independent exact-head review remains required before any merge. Synthetic PASS does not establish Governed Mail production readiness.

## AUDIT
Review base 53e4c0efea5d5f67c91f70ba6b2b488b067d1530 tree 33666efe14a83dfa867499c888bbafc1d0ac7250. Historical controller intake was verified byte-for-byte against SHA256 16890c0ad83f6d124e6a9d63f7350aa7d615f1bfa2d4bfc0965508725bf0746c. Sixteen local result-contract unit tests passed under Python3.12.14; Python/probe AST and YAML structure checks passed. The reused kernel_restrictions function AST is unchanged. Native CI is pending; old 475-case and historical 497-case reports are not new proof. First published head4441e83595d5968fc8795cf74a9c4a3beccd8512: preflight run42088455208 attempt1 failed with child_exit1 and no controls, while its sixteen contract tests passed. Archive and inner report checksums verified; artifact13444091930 retained. Separate governance run42088455138 passed 2839 tests and194 subtests. Local follow-up: twenty unique contract/diagnostic tests PASS, four new. No new CI outcome claimed at publication. Diagnostics head4ce82a3406a6d56f3844b5ad79b7e4621bc45dd2: run42089788419 attempt1 passed20 unit tests and failed isolation setup with child_exit1 and no controls. Saved archive SHA256 d038584b68d72afcf9dae71b9327e9c263e286137b72d7ad79e62ef1df16ae96 and inner report checksum verified. Governance run42089788566 passed2839 tests and194 subtests. Prepared bootstrap proposal passes24 pure local tests; no local privileged execution occurred. Explicit bootstrap heade66b5f10bd026b5d4b0f1f1212982472d6fbd70c: run42091415750 attempt1 passed24 pure tests but failed preflight with child_exit2, Permission denied and no controls. Artifact13445861318 SHA256 c8832e29020299e91a4bfd68a7d1392d264f3b2e22d9220737905b355233be4c verified with inner checksum. Governance run42091415672 passed2839 tests and194 subtests. Current prepared owner/version proposal:34 pure local tests PASS; privileged execution not performed locally. Owner-mapping cycle1 head1cc00d1c5a21898f5070d24598d2b5dc4868a73f, run42093576550 attempt1, failed before controls with child_exit1 and no prior categorized launcher error. Verified artifact13447015748 SHA256 e894b7b53088a26b7b331f0ebec066f094217a9ef9e7c32ce8ed9e526ae33367 and inner checksum. util-linuxv2.39.3 source shows range mappings invoke external ID-map helpers; native cause remains UNKNOWN until this diagnostic cycle. Thirty-eight local pure tests PASS. Owner-mapping cycle2 head663ca06be84c1ff2694bc2f2f600cf9e6ce56f94: native run42094437881 failed with UID_MAP_HELPER_ERROR / ID_RANGE_NOT_ALLOWED before controls. Archive SHA2564c9130cacab9ff1ecb19d9dcb9d7b1b066c9415c78b05c52732e45e63c482768 and inner checksum verified. Thirty-eight native pure tests and separate2839 governance tests plus194 subtests passed. The previous three-cycle batch stopped after two; no third retry. New repair candidate:60 local pure tests passed; kernel function AST unchanged. No local privileged execution. New-head native repair result pending. Repair cycle1 head8fab31e63e620c512f0e62295fcc183beec8c14f run42098239522 attempt1 failed before controls with generic NAMESPACE_LAUNCH / RuntimeError and no categorized launcher error. Artifact13449685076 archive SHA2565eb300ea9449eedadf9cdb4192d3c9b91aa2705af761849a03a56561d40af1af and inner checksum verified. Pure native contract step passed; exact count not yet extracted. Round2 local65 tests passed, including five new bounded diagnostic cases. Mapping/policy/source functions, controller and workflow unchanged. Repair round2 head4c1ea59f106fd3c111579c32389f994dbe6f9082 run42098894624:65 native pure tests passed; isolation failed with OPERATION_NOT_PERMITTED / SETGROUPS_PATH / WRITE_FAILED; launcher_exit1; mapping_policy_restored true. Artifact13448830947 SHA2565b6c9a7fd4d8141e9f908326385c53002dea0c1237d816b11ba81455f02bae7d and inner checksum verified. Separate governance run42098895059 passed2839 tests plus194 subtests. Kernelv6.8 proc_setgroups_write corroborates the forbidden post-gid-map denial. Current candidate79 pure local tests passed; five new exact-parent/argument cases; no local privileged execution. Native additional run pending.

## IMPACT
Repair bootstrap ordering while retaining mandatory permanent group denial and exact owner scope. This OS setup permission grants no USBAY product authority. Keep the PR Draft and unmerged.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL
## MECHANISM
Root-owned mode700 temporary helper directory under /run with exact head/UID/GID binding. A fixed newgidmap guard accepts only its actual parent PID and one exact GID, pins that proc directory, verifies separate user namespace and prior exact UID map, rejects any existing GID map, writes and verifies deny before publishing gid_map, then verifies final state. Remove the later unshare deny write, not the denial requirement. Pre-mount and fresh-child identity/denial checks remain mandatory; root policy changes are restored.

## GAP
Native helper/PID/namespace/proc-FD integration remains UNKNOWN until this exact-head run. Pure tests simulate kernel ordering but do not prove native isolation. This is scoped to a disposable hosted runner, not a hardened multi-tenant bootstrap service. Existing full command grammar, mail-suite integration, release/provider and EGAP-HYDRA-REMOTE-TRANSPORT-AUTH gaps remain open.

## VALIDATION
79 unique local pure tests PASS; Python AST checks PASS; kernel function AST unchanged. No local sudo, namespace, /proc or /etc writes. Exactly one additional native CI round pending.

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
- validation/mail_readiness/gidmap_guard.py
- validation/mail_readiness/test_gidmap_guard.py
- governance/evidence/pb375_mail_isolation_preflight/metadata.json
- governance/evidence/pb375_mail_isolation_preflight/generated_pr_body.md

## VALIDATION RESULTS
79 unique local pure tests PASS; Python AST checks PASS; kernel function AST unchanged. No local sudo, namespace, /proc or /etc writes. Exactly one additional native CI round pending.

## ROLLBACK PLAN
Restore only exact known mapping writes in finally; refuse to overwrite unexpected concurrent state. On failure, prevent synthetic success and preserve evidence. Runner disposal remains required. Do not merge a failed candidate.

## COMMIT OR SOURCE REFERENCE
Base 53e4c0efea5d5f67c91f70ba6b2b488b067d1530; original controller SHA256 16890c0ad83f6d124e6a9d63f7350aa7d615f1bfa2d4bfc0965508725bf0746c; private review package Library file libfile_7a67f7b5423c8191a980efdb64289777 version1. No library access is required for CI. Diagnostics parent4441e83595d5968fc8795cf74a9c4a3beccd8512; prior failure run42088455208; archive SHA256 76e35516c9e1d2364a26dc73aaa9508e53769a7266655e964ebadf8f937edf83. Explicit-bootstrap parent4ce82a3406a6d56f3844b5ad79b7e4621bc45dd2; saved review package libfile_7a67f7b5423c8191a980efdb64289777 version3. GitHub platform reference: https://docs.github.com/en/actions/reference/runners/github-hosted-runners . Owner-mapping parente66b5f10bd026b5d4b0f1f1212982472d6fbd70c; saved review package libfile_7a67f7b5423c8191a980efdb64289777 version4; unshare primary reference https://man7.org/linux/man-pages/man1/unshare.1.html . Cycle2 parent1cc00d1c5a21898f5070d24598d2b5dc4868a73f; util-linux primary source https://github.com/util-linux/util-linux/blob/v2.39.3/sys-utils/unshare.c . Repair parent663ca06be84c1ff2694bc2f2f600cf9e6ce56f94; primary group-order sources https://github.com/util-linux/util-linux/blob/v2.39.3/sys-utils/unshare.c and https://github.com/shadow-maint/shadow/blob/4.13/src/newgidmap.c . Exact-parent correction parent4c1ea59f106fd3c111579c32389f994dbe6f9082; primary kernel contract https://github.com/torvalds/linux/blob/v6.8/kernel/user_namespace.c .
