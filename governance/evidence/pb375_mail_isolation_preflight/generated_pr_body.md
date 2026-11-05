## PURPOSE
Repair the synthetic fresh-child execution boundary using actual ELF/runtime binding, one fixed trusted Python/loader startup and mandatory additive child execve/execveat denial before controls. This is cycle1 of a separately authorized maximum3-round batch.

## RISK
Prior exact-head native run reached FRESH_CHILD_CONTROLS but child startup failed with EACCES. Missing ELF-loader EXECUTE access is a static hypothesis, not a native-confirmed denied-object diagnosis. Unrestricted loader permission can bypass an executable allowlist. The fixed startup must never expose that permission to an ungoverned payload.

## POLICY LINK
Baseline AGENTS.md; existing fail-closed evidence and authorization boundaries; PB-023/PB-026 generated metadata contracts. PB-375 is a new administrative validation work identifier, not an adopted policy or operational grant.

## REQUIRED APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE CHECKS
- Owner explicitly authorized this synthetic-harness kernel execution-policy repair, implementation/publication on PR427 and at most three targeted new-head CI rounds after evidence-backed corrections. Cycle1; no unchanged retry.
- Allow only the actual verified ELF Python and its sole verified loader for one fixed source-bound trusted child startup. No guessed loader, shell, Git delegation or caller-selected code/arguments.
- Fresh child must install and verify an additive no_new_privs/seccomp gate denying execve, execveat and alternate ABI execution before controls. Failure aborts; no fallback.
- Preserve exact original owner mapping, parent-target guard, source/head/caller checks, namespace layers, read-only source/runtime, capability drop, existing non-exec kernel restrictions and temporary mapping-policy restoration.
- All original ten controls plus three explicit exec/loader negative controls, exact fresh identity, runtime binding and gate evidence are mandatory. A malformed or missing result fails closed.
- No further permission widening, packages, policy/root product grants, mail/application tests, provider/release issuance, merge, deployment or activation. Stop at success, a different permission requirement or three-round exhaustion.
- Independent exact-head human review remains required before any merge. Synthetic PASS does not prove full sandbox containment or Governed Mail production readiness.

## AUDIT
Review base 53e4c0efea5d5f67c91f70ba6b2b488b067d1530 tree 33666efe14a83dfa867499c888bbafc1d0ac7250. Historical controller intake was verified byte-for-byte against SHA256 16890c0ad83f6d124e6a9d63f7350aa7d615f1bfa2d4bfc0965508725bf0746c. Sixteen local result-contract unit tests passed under Python3.12.14; Python/probe AST and YAML structure checks passed. The reused kernel_restrictions function AST is unchanged. Native CI is pending; old 475-case and historical 497-case reports are not new proof. First published head4441e83595d5968fc8795cf74a9c4a3beccd8512: preflight run42088455208 attempt1 failed with child_exit1 and no controls, while its sixteen contract tests passed. Archive and inner report checksums verified; artifact13444091930 retained. Separate governance run42088455138 passed 2839 tests and194 subtests. Local follow-up: twenty unique contract/diagnostic tests PASS, four new. No new CI outcome claimed at publication. Diagnostics head4ce82a3406a6d56f3844b5ad79b7e4621bc45dd2: run42089788419 attempt1 passed20 unit tests and failed isolation setup with child_exit1 and no controls. Saved archive SHA256 d038584b68d72afcf9dae71b9327e9c263e286137b72d7ad79e62ef1df16ae96 and inner report checksum verified. Governance run42089788566 passed2839 tests and194 subtests. Prepared bootstrap proposal passes24 pure local tests; no local privileged execution occurred. Explicit bootstrap heade66b5f10bd026b5d4b0f1f1212982472d6fbd70c: run42091415750 attempt1 passed24 pure tests but failed preflight with child_exit2, Permission denied and no controls. Artifact13445861318 SHA256 c8832e29020299e91a4bfd68a7d1392d264f3b2e22d9220737905b355233be4c verified with inner checksum. Governance run42091415672 passed2839 tests and194 subtests. Current prepared owner/version proposal:34 pure local tests PASS; privileged execution not performed locally. Owner-mapping cycle1 head1cc00d1c5a21898f5070d24598d2b5dc4868a73f, run42093576550 attempt1, failed before controls with child_exit1 and no prior categorized launcher error. Verified artifact13447015748 SHA256 e894b7b53088a26b7b331f0ebec066f094217a9ef9e7c32ce8ed9e526ae33367 and inner checksum. util-linuxv2.39.3 source shows range mappings invoke external ID-map helpers; native cause remains UNKNOWN until this diagnostic cycle. Thirty-eight local pure tests PASS. Owner-mapping cycle2 head663ca06be84c1ff2694bc2f2f600cf9e6ce56f94: native run42094437881 failed with UID_MAP_HELPER_ERROR / ID_RANGE_NOT_ALLOWED before controls. Archive SHA2564c9130cacab9ff1ecb19d9dcb9d7b1b066c9415c78b05c52732e45e63c482768 and inner checksum verified. Thirty-eight native pure tests and separate2839 governance tests plus194 subtests passed. The previous three-cycle batch stopped after two; no third retry. New repair candidate:60 local pure tests passed; kernel function AST unchanged. No local privileged execution. New-head native repair result pending. Repair cycle1 head8fab31e63e620c512f0e62295fcc183beec8c14f run42098239522 attempt1 failed before controls with generic NAMESPACE_LAUNCH / RuntimeError and no categorized launcher error. Artifact13449685076 archive SHA2565eb300ea9449eedadf9cdb4192d3c9b91aa2705af761849a03a56561d40af1af and inner checksum verified. Pure native contract step passed; exact count not yet extracted. Round2 local65 tests passed, including five new bounded diagnostic cases. Mapping/policy/source functions, controller and workflow unchanged. Repair round2 head4c1ea59f106fd3c111579c32389f994dbe6f9082 run42098894624:65 native pure tests passed; isolation failed with OPERATION_NOT_PERMITTED / SETGROUPS_PATH / WRITE_FAILED; launcher_exit1; mapping_policy_restored true. Artifact13448830947 SHA2565b6c9a7fd4d8141e9f908326385c53002dea0c1237d816b11ba81455f02bae7d and inner checksum verified. Separate governance run42098895059 passed2839 tests plus194 subtests. Kernelv6.8 proc_setgroups_write corroborates the forbidden post-gid-map denial. Current candidate79 pure local tests passed; five new exact-parent/argument cases; no local privileged execution. Native additional run pending. Prior head5ea2f4fbf84592bfafbd2de42deea5ffe78e687a run42100566003 attempt1:79 native pure tests passed; failure at FRESH_CHILD_CONTROLS with PermissionError errno13, restored mapping policy. Artifact13448553656 SHA256d6e8b66659bf470d702ed4ce879689f6cc9549e45cefe9ad63d1ed3885241460 and inner checksum verified. Governance run42100566421 passed2839 tests plus194 subtests. Current candidate106 pure local tests passed; local ELF metadata inspection passed without child/filter execution. Existing non-exec kernel filter AST is unchanged; only exact execution-target/parameter differs. New native CI pending.

## IMPACT
Replace an unusable synthetic startup boundary with an explicit fixed-startup/no-exec phase design. Validate the failure and bypass cases on exact source; grant no application/provider/production authority.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL
## MECHANISM
Strict bounded ELF64/x86-64 PT_INTERP parsing and host-root runtime identity/hash validation; namespace recomputation and equality; preserved known runtime aliases; exact Python/loader Landlock grants for fixed trusted startup; inherited additive no-exec filter in the fresh child. Original ten controls plus execve/execveat/direct-loader-with-shell denial, identity, gate, runtime and restoration evidence are required.

## GAP
Native fixed-startup/loader/no-exec composition remains UNKNOWN. The loader hypothesis is not yet native-confirmed. This is a trusted fixed-probe harness, not a general arbitrary-code or multi-tenant service. In-process native code, dynamic loading, full suite command grammar, mail integration, release/provider authority and EGAP-HYDRA-REMOTE-TRANSPORT-AUTH remain open.

## VALIDATION
106 unique local pure tests PASS. Local ELF metadata read PASS; no local seccomp installation, child execution or privileged setup. Python AST checks PASS. Existing non-exec kernel function AST unchanged. Native cycle1 of maximum3 pending.

## ROLLBACK
Restore only exact known mapping writes in finally; refuse to overwrite unexpected concurrent state. On failure, prevent synthetic success and preserve evidence. Runner disposal remains required. Do not merge a failed candidate.

## SOURCE
https://github.com/USJAY77/usbay-policy-brain-public/commit/53e4c0efea5d5f67c91f70ba6b2b488b067d1530

## CHANGED FILES
- validation/mail_readiness/README.md
- validation/mail_readiness/isolation_preflight.py
- validation/mail_readiness/result_contract.py
- validation/mail_readiness/runner_bootstrap.py
- validation/mail_readiness/execution_boundary.py
- validation/mail_readiness/test_execution_boundary.py
- governance/evidence/pb375_mail_isolation_preflight/metadata.json
- governance/evidence/pb375_mail_isolation_preflight/generated_pr_body.md

## VALIDATION RESULTS
106 unique local pure tests PASS. Local ELF metadata read PASS; no local seccomp installation, child execution or privileged setup. Python AST checks PASS. Existing non-exec kernel function AST unchanged. Native cycle1 of maximum3 pending.

## ROLLBACK PLAN
Restore only exact known mapping writes in finally; refuse to overwrite unexpected concurrent state. On failure, prevent synthetic success and preserve evidence. Runner disposal remains required. Do not merge a failed candidate.

## COMMIT OR SOURCE REFERENCE
Base 53e4c0efea5d5f67c91f70ba6b2b488b067d1530; original controller SHA256 16890c0ad83f6d124e6a9d63f7350aa7d615f1bfa2d4bfc0965508725bf0746c; private review package Library file libfile_7a67f7b5423c8191a980efdb64289777 version1. No library access is required for CI. Diagnostics parent4441e83595d5968fc8795cf74a9c4a3beccd8512; prior failure run42088455208; archive SHA256 76e35516c9e1d2364a26dc73aaa9508e53769a7266655e964ebadf8f937edf83. Explicit-bootstrap parent4ce82a3406a6d56f3844b5ad79b7e4621bc45dd2; saved review package libfile_7a67f7b5423c8191a980efdb64289777 version3. GitHub platform reference: https://docs.github.com/en/actions/reference/runners/github-hosted-runners . Owner-mapping parente66b5f10bd026b5d4b0f1f1212982472d6fbd70c; saved review package libfile_7a67f7b5423c8191a980efdb64289777 version4; unshare primary reference https://man7.org/linux/man-pages/man1/unshare.1.html . Cycle2 parent1cc00d1c5a21898f5070d24598d2b5dc4868a73f; util-linux primary source https://github.com/util-linux/util-linux/blob/v2.39.3/sys-utils/unshare.c . Repair parent663ca06be84c1ff2694bc2f2f600cf9e6ce56f94; primary group-order sources https://github.com/util-linux/util-linux/blob/v2.39.3/sys-utils/unshare.c and https://github.com/shadow-maint/shadow/blob/4.13/src/newgidmap.c . Exact-parent correction parent4c1ea59f106fd3c111579c32389f994dbe6f9082; primary kernel contract https://github.com/torvalds/linux/blob/v6.8/kernel/user_namespace.c . Execution-boundary parent5ea2f4fbf84592bfafbd2de42deea5ffe78e687a. Kernel primary sources https://github.com/torvalds/linux/blob/v6.8/fs/binfmt_elf.c and https://github.com/torvalds/linux/blob/v6.8/security/landlock/fs.c .
