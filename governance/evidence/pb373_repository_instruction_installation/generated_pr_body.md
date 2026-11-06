## PURPOSE
Install the reviewed USBAY engineering guidance in repository agent loader locations, with explicit separation of historical source packaging, environment installation, observed loading and governance adoption. Preserve bounded failure diagnostics for CI-policy adoption and first-use intent concurrency. Exercise the existing exactly-one-winner test in 16 isolated cases with eight threads each.

## RISK
Repository guidance intentionally loads when supported agents open this branch under owner-authorized installation scope. It grants no operational authority. Earlier native CI returned zero successful first uses; a later passing run did not establish its cause. Diagnostics must never expose signing material or raw inputs.

## POLICY LINK
Baseline AGENTS.md; PB-023/PB-026 metadata contracts; .github/pull_request_template.md; shared source and staged adapters from PR424/base227c5144c63c715a09acf0be41ef8fe8a918a071; administrative work item https://github.com/USJAY77/usbay-policy-brain-public/issues/423.

## REQUIRED APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE CHECKS
- Preserve baseline AGENTS.md as an exact prefix. Keep active/staged Codex guidance equal, retain original Cursor/Copilot adapter bytes and leave the canonical shared source/hash unchanged.
- Guidance, observed loading, source approval, policy adoption and runtime enforcement are separate. No account-wide installation or runtime authority is inferred.
- Every original test assertion condition remains unchanged, including exactly one ALLOW and rejection of subsequent replay. The observer calls original reserve once and re-raises its original error; it adds no recovery, retry, wait or permissive fallback.
- Use 16 function-scoped synthetic cases, each with a fresh temporary state and eight threads. Diagnostics contain only attempt number, decision/reason codes and typed SQLite error code/name. The constant fixture representation must not expose signing material.
- Owner authorized publication of this bounded reproduction and one new CI cycle. No automatic rerun, runtime/application change, policy modification, workflow/dependency change, trust/permission widening, merge, deployment or product activation.
- Two independent reviews must bind the exact final head. Previous-head approvals/reviews do not establish approval of changed test code.

## AUDIT
Base227c5144c63c715a09acf0be41ef8fe8a918a071. Original CI-policy failures at headde101b9f/job127256802439 remain historical. Concurrency failure at head1b5bdedbe4/job127284837444 observed zero ALLOW; its per-attempt causes were not logged. Parent08b6f9b4201d3231814d32fae5db63b6922d4fe8 passed 2818 tests and 194 subtests, with14 checks, in run42040948367 attempt1. These are distinct runs, not cumulative new proof; historical causes remain UNKNOWN.

## IMPACT
Repository agents receive consistent bounded engineering guidance. Native test diagnostics investigate concurrency without changing production replay semantics, weakening safety assertions or granting operational authority.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL

## MECHANISM
Install exact staged engineering adapters with the Codex installation-context clarification. In tests, expose bounded CI-adoption failure reasons and observe existing first-use reservation errors without replacing behavior. Preserve the redacted fixture representation and all assertion conditions.

## GAP
Earlier live-adoption and zero-winner CI failure causes remain UNKNOWN. A passing stress run cannot prove their absence or production readiness. Native reproduction and independent final-head review remain pending until observed.

## VALIDATION
Static AST checks preserve every original assertion condition, the replay postcondition, all unrelated module code and fixture behavior. The observer calls reserve once and re-raises original errors. PB-023/PB-026 validators and exact source/tree checks apply. One new native CI cycle is authorized; no local tests/application are run.

## ROLLBACK
No rollback or history rewrite is performed. A later reviewed reversal must preserve baseline instructions, historical failures and governed replay/uncertainty evidence.

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
Parent08b6f9b420 passed2818 tests plus194 subtests and14 checks. Bounded16-case reproduction is not executed during preparation; current-head CI results must be reported separately. Parameter repetitions are not distinct new behavior proofs.

## ROLLBACK PLAN
Prepare a minimal reviewed source reversal if needed, retaining prior source guidance and diagnostic evidence. Do not reset replay consumption or infer recovery authority.

## COMMIT OR SOURCE REFERENCE
Reproduction parent08b6f9b4201d3231814d32fae5db63b6922d4fe8; initial concurrency failure https://github.com/USJAY77/usbay-policy-brain-public/actions/runs/42039091742/job/127284837444; latest passing diagnostic run https://github.com/USJAY77/usbay-policy-brain-public/actions/runs/42040948367
