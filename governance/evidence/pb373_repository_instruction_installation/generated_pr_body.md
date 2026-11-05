## PURPOSE
Install the already reviewed engineering guidance into the repository instruction locations for Codex, Cursor and Copilot. This is a separate installation proposal following source-only PR424 and administrative work item https://github.com/USJAY77/usbay-policy-brain-public/issues/423. Add bounded failure diagnostics to two existing CI-adoption assertions after the first candidate CI failure; expected outcomes and verification remain unchanged.

## RISK
Unlike the prior source-only proposal, these paths intentionally apply engineering guidance when supported agents open this branch. Guidance must not grant operational authority or silently replace baseline constraints. Live GitHub adoption verification can fail closed without its reason appearing in existing assertion output; diagnostics expose only reason and HTTP status.

## POLICY LINK
Baseline AGENTS.md; PB-023/PB-026 generated metadata contracts; .github/pull_request_template.md; reviewed shared source and inert adapters merged by PR424 at 227c5144c63c715a09acf0be41ef8fe8a918a071.

## REQUIRED APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE CHECKS
- Owner authorized instruction installation in reachable non-production environments. Owner separately authorized publication as a Draft PR. Merge, deployment, product activation and permission widening remain outside scope.
- Preserve the baseline AGENTS.md as an exact prefix. Active instruction files must equal the reviewed staged adapter bytes. Do not change shared source, application code, dependencies, workflows, secrets, trust or permissions.
- These are intentional instruction loader paths, not inert proposals. Keep REVIEW_REQUIRED / AWAITING_APPROVAL and obtain two independent exact-head reviews before merge.
- A local installed file or model response does not prove account-wide settings, future-session loading, runtime enforcement or production readiness.
- Owner authorized this bounded test-diagnostic addition and one new CI cycle. Do not alter assertion conditions, fixtures, policy, adoption verifier, credentials, workflows or authority. Do not automatically rerun CI after this cycle.

## AUDIT
Initial candidate de101b9f2e5d0e038208fe5f22d897d998c3d727: auto-fix job127256802439/run42030905408 reported 2816 passed, 2 failed, 194 subtests passed, 4378 deselected. The two live PR410 CI-adoption assertions returned FAIL_CLOSED; the underlying reason was absent from output. Original failure evidence is preserved. Diagnostics are not a remediation or approval. Baseline 227c5144c63c715a09acf0be41ef8fe8a918a071.

## IMPACT
Consistent engineering guidance for repository agents without application/runtime changes, operational grants or product activation.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL

## MECHANISM
Install exact reviewed adapter bytes into three instruction paths, retaining baseline AGENTS content and the unchanged canonical source hash. On failure, two existing assertions additionally expose only reason/http_status; all assertion conditions remain identical.

## GAP
Future-session inclusion, actual Cursor/Copilot use and account settings remain UNKNOWN. This proposal is scoped to Draft PR publication; it does not establish merged installation or platform loading. Exact initial CI failure reason remains UNKNOWN until observed in the authorized diagnostic cycle. No approval-adoption repair is claimed.

## VALIDATION
Static adapter provenance, PB-023/PB-026 metadata validators and AST comparison of all test conditions and code except the two diagnostic messages. One new CI cycle is owner-authorized; its outcome must be read back. No local application or test execution.

## ROLLBACK
Any later reversal must preserve prior instructions and evidence; no reset or history rewrite is performed.

## SOURCE
https://github.com/USJAY77/usbay-policy-brain-public/commit/227c5144c63c715a09acf0be41ef8fe8a918a071

## CHANGED FILES
- AGENTS.md
- .cursor/rules/usbay-discipline.mdc
- .github/copilot-instructions.md
- governance/evidence/pb373_repository_instruction_installation/metadata.json
- governance/evidence/pb373_repository_instruction_installation/generated_pr_body.md
- tests/test_governance_actions_policy_approvals.py

## VALIDATION RESULTS
Initial CI failed two live-adoption assertions; 2816 tests and 194 subtests passed. The proposal changes only two assertion messages at lines51/132; ASTs are otherwise identical. Static metadata validation passed. New-head CI outcome pending.

## ROLLBACK PLAN
Prepare a minimal source reversal of only these additions if separately authorized; preserve baseline instructions and audit history.

## COMMIT OR SOURCE REFERENCE
Base: 227c5144c63c715a09acf0be41ef8fe8a918a071; failed candidate/diagnostic parent: de101b9f2e5d0e038208fe5f22d897d998c3d727; original failure job: https://github.com/USJAY77/usbay-policy-brain-public/actions/runs/42030905408/job/127256802439
