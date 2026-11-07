## PURPOSE
Correct dashboard wording that can imply general approval from narrower evidence checks, and render evidence/runtime values as literal text. Administrative proposal: https://github.com/USJAY77/usbay-policy-brain-public/issues/432. The presentation patch is bound to reachable public main dc549b2167dc6bdbe8e5b1c988bb27e9176e388e.

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
- Only three presentation functions, two pure rendering helpers and twelve copy-dependent assertion strings change; 193 other top-level function/class raw blocks and module initialization match the pinned base.
- Do not incorporate unrelated signer-fixture PR431, removed Replit runtime modules, workflow/dependency changes, provider operations or deployment.
- Observe actual exact-head CI results and preserve failures. Echo-only gates are not runtime validation; selection of the four backend UI tests must be confirmed from collection evidence.

## AUDIT
Fresh local Python 3.12.14 standard-library renderer-only run passed 17 unique cases and 31 subtests, exit 0. All 11 private preservation files were remotely reread and SHA256-matched at preservation commit 5ae899ab453326808f5601f24ce2fd84bef51242. Public source patch SHA256: 11cf82cac44fe5f41f48b8265623d833c85ca83a9741032195c538c19b61c0a9. Private preservation is evidence storage, not an application commit or approval.

## IMPACT
Reviewers can distinguish reported checks and analysis/review items from actual action authority. Dynamic values render as text. The patch does not enable mail execution, establish production readiness or synchronize a proven serving build.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL

## MECHANISM
Display specific digest/sourcehash/policy-signature observations separately; preserve observation scope and times; show missing authority/freshness as UNKNOWN; qualify review items; escape verdict/runtime text and nested JSON. Existing assessment JavaScript remains textContent-based.

## GAP
The four backend-coupled UI tests, full application import/lifespan, browser/provider/live acceptance and serving-build binding remain unproven locally. Existing record-transfer and operational authority gaps remain open. No independent human review has been established.

## VALIDATION
17 renderer-only cases and 31 subtests passed on Python 3.12.14 without Gateway import or dependency installation. Static AST/raw-block checks confirmed rendering-only changes and preserved non-copy test AST. Existing automatic PR CI is pending; no workflow configuration changes.

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
Candidate: 17/17 cases, 31 subtests, zero failures/errors/skips, exit 0. Focused existing-renderer baseline control: three failing cases and one already-passing demo case; these four are a subset of the seventeen. Initial full-harness baseline extraction failure is retained as a harness diagnostic, not functional regression evidence. Four backend UI tests remain NOT RUN locally.

## ROLLBACK PLAN
No merge, deployment, activation, permission change or automatic CI retry. Retain the public Draft PR and exact-head failure evidence for review if native CI fails.

## COMMIT OR SOURCE REFERENCE
Application base dc549b2167dc6bdbe8e5b1c988bb27e9176e388e; registration https://github.com/USJAY77/usbay-policy-brain-public/issues/432; prepared source patch SHA256 11cf82cac44fe5f41f48b8265623d833c85ca83a9741032195c538c19b61c0a9. The prior Replit-bound candidate is not used as source identity or new test evidence.
