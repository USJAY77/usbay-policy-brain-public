## PURPOSE
Correct dashboard wording that can imply general approval from narrower evidence checks, and render evidence/runtime values as literal text. Administrative proposal: https://github.com/USJAY77/usbay-policy-brain-public/issues/432. The presentation patch is bound to reachable public main dc549b2167dc6bdbe8e5b1c988bb27e9176e388e. Include the existing standalone dashboard boot test in the existing governance PR selection with one explicit pytest marker; do not change its assertions.

## RISK
Broad approval labels can overstate execution authority or human independence. Direct HTML interpolation of verdict/runtime text can create a conditional injection route. Renderer checks alone do not prove backend, browser or production safety.

## POLICY LINK
Baseline AGENTS.md; existing fail-closed identity, tenant, signature, revocation, replay and audit controls; PB-023 metadata authority and PB-026 generated review-body contract. No policy, trust or permissions are changed.

## REQUIRED APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE CHECKS
- Owner authorized one separate public branch and Draft PR with existing automatic PR CI; no manual reruns or merge are authorized.
- Keep REVIEW_REQUIRED / AWAITING_APPROVAL. Existing reviewer accounts are controlled by one owner and do not prove two independent human reviewers. No human approval is supplied.
- Preserve backend producers, route handlers, API outcomes, policy/identity/signature/replay/revocation/audit enforcement and all non-copy test assertions.
- Only three presentation functions, two pure rendering helpers and twelve copy-dependent assertion strings and one explicit governance test marker change; 193 other top-level function/class raw blocks and module initialization match the pinned base.
- Do not incorporate unrelated signer-fixture PR431, removed Replit runtime modules, workflow/dependency changes, provider operations or deployment.
- Observe actual exact-head CI results and preserve failures. Echo-only gates are not runtime validation; selection of the four backend UI tests must be confirmed from collection evidence.
- Retain the unchanged live-pilot verifier and its assertions. Restore the Runtime state: display prefix with the explicit reported-observation/no-permission qualification. A real source correction creates new-head automatic CI; do not rerun the failed unchanged head.
- Select tests/test_live_pilot_v1.py::test_dashboard_boot_cannot_be_blank using its existing governance marker category. Assert that this is the only AST difference from the previously passing test file; preserve application bytes and every assertion. Observe new-head collection and actual test execution.

## AUDIT
Fresh local Python 3.12.14 standard-library renderer-only run passed 17 unique cases and 31 subtests, exit 0. All 11 private preservation files were remotely reread and SHA256-matched at preservation commit 5ae899ab453326808f5601f24ce2fd84bef51242. Public source patch SHA256: 261bce5193249ba932f2f7e8dcc21e9e8dec2e449a911a6563124e21c28ced9c. Private preservation is evidence storage, not an application commit or approval. Initial native run 42362290089 at head 41fd42b56b1c169e3349efbbf314dc7081d22c64 reported 2848 passed, 1 failed and 194 subtests passed; its failed unchanged pilot verifier expected the literal Runtime state: prefix. Preserve this failure; new-head CI is pending. Corrected prior head 137e98a43094b6f35fb0a37bf73ba6f7a18622e4 passed native run 42362796234: 2849 tests and 194 subtests; all 13 observed checks succeeded. The standalone boot test was not selected there. This selector change requires fresh native evidence.

## IMPACT
Reviewers can distinguish reported checks and analysis/review items from actual action authority. Dynamic values render as text. The patch does not enable mail execution, establish production readiness or synchronize a proven serving build.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL

## MECHANISM
Display specific digest/sourcehash/policy-signature observations separately; preserve observation scope and times; show missing authority/freshness as UNKNOWN; qualify review items; escape verdict/runtime text and nested JSON. Existing assessment JavaScript remains textContent-based. Retain the existing Runtime state: compatibility prefix while explicitly qualifying it as a reported observation, not action permission; no verifier or marker definition is changed. One pytest.mark.governance decorator selects the unchanged dashboard boot test through the existing collection hook; no workflow or runtime implementation changes.

## GAP
Fresh native collection and execution of the explicitly selected boot test are pending on this new head. Browser/live/provider acceptance, serving-build binding and independent human review remain open. Previous native success belongs to head 137e98a43094b6f35fb0a37bf73ba6f7a18622e4 and is not new-head CI evidence.

## VALIDATION
17 renderer-only cases and 31 subtests passed on Python 3.12.14 without Gateway import or dependency installation. Static AST/raw-block checks confirmed rendering-only changes and preserved non-copy test AST. Existing automatic PR CI is pending; no workflow configuration changes. Marker-only AST comparison proved that deleting exactly the new decorator restores the prior test AST and source SHA256. Application files are byte-identical to the prior green head, so unchanged local renderer evidence is reused; no unnecessary local rerun.

## ROLLBACK
Keep this proposal unmerged on any failed or unresolved required check. Preserve all commits and failure evidence. Any later reversal after adoption requires its own reviewed change.

## SOURCE
Pinned base: https://github.com/USJAY77/usbay-policy-brain-public/commit/dc549b2167dc6bdbe8e5b1c988bb27e9176e388e . Proposed source bytes are identified by the PR head and metadata file hashes; no circular self-hash is embedded.

## CHANGED FILES
- gateway/app.py
- tests/test_gateway_app.py
- tests/test_live_pilot_v1.py
- governance/evidence/pb376_dashboard_observation_boundaries/metadata.json
- governance/evidence/pb376_dashboard_observation_boundaries/generated_pr_body.md

## VALIDATION RESULTS
Candidate: 17/17 cases, 31 subtests, zero failures/errors/skips, exit 0. Focused existing-renderer baseline control: three failing cases and one already-passing demo case; these four are a subset of the seventeen. Initial full-harness baseline extraction failure is retained as a harness diagnostic, not functional regression evidence. Four backend UI tests remain NOT RUN locally. Initial native CI: 2848 passed, 1 failed, 194 subtests passed at head 41fd42b56b1c169e3349efbbf314dc7081d22c64. The selected three Gateway UI tests were absent from the sole-failure list and no skips were reported; the standalone boot test was deselected. The unchanged verifier dashboard predicate was reproduced false against the first presentation candidate and true after the qualified-prefix correction, without importing Gateway/verifier. The same 17 renderer cases and 31 subtests passed again on corrected bytes. New-head native CI remains pending; reruns are not additional unique cases. Corrected prior head 137e98a43094b6f35fb0a37bf73ba6f7a18622e4 passed 2849 native tests and 194 subtests in run42362796234; all 13 checks passed. This head adds only one selector marker and proposal evidence; new native results remain pending.

## ROLLBACK PLAN
No merge, deployment, activation, permission change or automatic CI retry. Retain the public Draft PR and exact-head failure evidence for review if native CI fails.

## COMMIT OR SOURCE REFERENCE
Application base dc549b2167dc6bdbe8e5b1c988bb27e9176e388e; registration https://github.com/USJAY77/usbay-policy-brain-public/issues/432; prepared source patch SHA256 261bce5193249ba932f2f7e8dcc21e9e8dec2e449a911a6563124e21c28ced9c. The prior Replit-bound candidate is not used as source identity or new test evidence. Initial native failure: https://github.com/USJAY77/usbay-policy-brain-public/actions/runs/42362290089/job/128373004954 . Prior green native run: https://github.com/USJAY77/usbay-policy-brain-public/actions/runs/42362796234 .
