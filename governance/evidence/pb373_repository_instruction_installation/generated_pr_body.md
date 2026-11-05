## PURPOSE
Install the already reviewed engineering guidance into the repository instruction locations for Codex, Cursor and Copilot. This is a separate installation proposal following source-only PR424 and administrative work item https://github.com/USJAY77/usbay-policy-brain-public/issues/423. Add bounded failure diagnostics to two existing CI-adoption assertions after the first candidate CI failure; expected outcomes and verification remain unchanged. Clarify historical source packaging status versus environment installation, observed loading and governance adoption in the Codex loader and its staged counterpart. Add only safe decision/reason diagnostics to the existing first-use concurrency assertion and hide this synthetic fixture material from its representation.

## RISK
Unlike the prior source-only proposal, these paths intentionally apply engineering guidance when supported agents open this branch. Guidance must not grant operational authority or silently replace baseline constraints. Live GitHub adoption verification can fail closed without its reason appearing in existing assertion output; diagnostics expose only reason and HTTP status. A historical PREPARED_NOT_INSTALLED source label must not be interpreted as current installation evidence. The latest native CI cycle returned zero allowed first uses where one was expected. Existing failure output did not include reason codes and exposed synthetic signing fixture material; do not carry that raw material into evidence.

## POLICY LINK
Baseline AGENTS.md; PB-023/PB-026 generated metadata contracts; .github/pull_request_template.md; reviewed shared source and inert adapters merged by PR424 at 227c5144c63c715a09acf0be41ef8fe8a918a071.

## REQUIRED APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE CHECKS
- Owner authorized instruction installation in reachable non-production environments. Owner separately authorized publication as a Draft PR. Merge, deployment, product activation and permission widening remain outside scope.
- Preserve the baseline AGENTS.md as an exact prefix. Active instruction files must equal their staged counterparts. The Codex pair receives only the pending-review installation-context note; Cursor and Copilot retain the original reviewed bytes. Do not change shared source, application code, dependencies, workflows, secrets, trust or permissions.
- These are intentional instruction loader paths, not inert proposals. Keep REVIEW_REQUIRED / AWAITING_APPROVAL and obtain two independent exact-head reviews before merge.
- A local installed file or model response does not prove account-wide settings, future-session loading, runtime enforcement or production readiness.
- Owner authorized this bounded test-diagnostic addition and one new CI cycle. Do not alter assertion conditions, fixtures, policy, adoption verifier, credentials, workflows or authority. Do not automatically rerun CI after this cycle.
- Keep the canonical shared source, its SHA256 and all other adapters unchanged. Do not infer installation, loading, policy adoption or runtime enforcement from another state. Owner separately authorized this status clarification, publication, one new CI cycle and Codex re-reviews. Merge, thread resolution, deployment and product activation remain outside scope.
- Owner separately authorized this additional test-only diagnostic publication and one new CI cycle. Keep the exactly-one-winner assertion and all other conditions unchanged. Do not alter replay logic, policy, dependencies, workflows or timeouts; do not retry CI automatically.

## AUDIT
Initial candidate de101b9f2e5d0e038208fe5f22d897d998c3d727: auto-fix job127256802439/run42030905408 reported 2816 passed, 2 failed, 194 subtests passed, 4378 deselected. The two live PR410 CI-adoption assertions returned FAIL_CLOSED; the underlying reason was absent from output. Original failure evidence is preserved. Diagnostics are not a remediation or approval. Baseline 227c5144c63c715a09acf0be41ef8fe8a918a071. Diagnostic commit7343b65324dec9e84f471534668ad023134dadfd passed 13 checks, 2818 tests and 194 subtests in one cycle; the original CI failure did not recur and its precise cause remains UNKNOWN. Codex review finding4481155807 requests installation-status clarification. Status-correction head1b5bdedbe4be80a114a8a8e51723b4f512dde8b9 failed CI run42039091742/job127284837444: 2817 tests and 194 subtests passed; test_concurrent_first_use_exactly_one_winner observed 0 ALLOW versus expected1. Individual reason codes were not reported. Code/security re-reviews completed without new findings; no application fix is claimed.

## IMPACT
Consistent engineering guidance for repository agents without application/runtime changes, operational grants or product activation.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL

## MECHANISM
Keep the shared source and its content hash unchanged. Add the same bounded installation-context paragraph to AGENTS.md and its staged Codex adapter. Separate historical source packaging status, source approval, environment installation, observed loading, policy adoption and runtime enforcement. Existing diagnostic assertion messages remain unchanged. The existing concurrency assertion now reports only decision/reason_code pairs. Its tuple fixture preserves all contained values and tuple behavior while using a constant safe representation.

## GAP
Current first-use concurrency failure cause remains UNKNOWN. The exactly-one ALLOW requirement remains enforced. This additional diagnostic cycle is authorized once; no root-cause fix, runtime readiness or automatic retry is claimed. Independent exact-head reviews/loading evidence remain open.

## VALIDATION
AST proof: all assertion conditions unchanged, only the concurrency assertion message added, fixture values unchanged, and otherwise identical module AST after accounting for the repr-only tuple subclass. PB-023/PB-026 validators and exact source/tree checks. One new CI cycle authorized; no local application/tests executed.

## ROLLBACK
Any later reversal must preserve prior instructions and evidence; no reset or history rewrite is performed.

## SOURCE
https://github.com/USJAY77/usbay-policy-brain-public/commit/227c5144c63c715a09acf0be41ef8fe8a918a071

## CHANGED FILES
- AGENTS.md
- .cursor/rules/usbay-discipline.mdc
- .github/copilot-instructions.md
- docs/engineering/adapters/CODEX_AGENTS.md.proposed
- governance/evidence/pb373_repository_instruction_installation/metadata.json
- governance/evidence/pb373_repository_instruction_installation/generated_pr_body.md
- tests/test_governance_actions_policy_approvals.py
- tests/test_intent_governance.py

## VALIDATION RESULTS
Latest native CI on head1b5bdedbe4: 2817 passed, 1 failed, 194 subtests passed, 4378 deselected. No secret fixture values copied into this record. Static diagnostic checks pass; new-head CI must be observed separately.

## ROLLBACK PLAN
Prepare a minimal source reversal of only these additions if separately authorized; preserve baseline instructions and audit history.

## COMMIT OR SOURCE REFERENCE
Diagnostic parent: 1b5bdedbe4be80a114a8a8e51723b4f512dde8b9; failed run: https://github.com/USJAY77/usbay-policy-brain-public/actions/runs/42039091742/job/127284837444; source baseline: 227c5144c63c715a09acf0be41ef8fe8a918a071
