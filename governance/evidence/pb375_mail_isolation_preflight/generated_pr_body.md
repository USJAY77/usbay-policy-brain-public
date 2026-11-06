## PURPOSE
Repair the integration between existing synthetic release fixtures, the Gitless runtime scanner and production-mode staging startup. The published cc932cf2 component tests passed, but its broader PR regression lane reported 201 failures and 29 errors. This proposal addresses that integration; it is not validated deployment readiness.

## RISK
Source verification and release evidence must refer to the actual package loaded by the runtime. Fixture defaults must never downgrade production or manufacture operational authority. Stale or substituted paths, files and source objects must fail closed. Synthetic issuer fixtures prove no operational trust or enrollment.

## POLICY_LINK
Preserve applicable AGENTS.md, fail-closed source/release verification, tenant boundaries, replay and policy checks. No trust/policy/permission widening, operational key provisioning or new authority.

## REQUIRED_APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE_CHECKS
The owner authorized publication of this fifteen-file batch on PR427 and up to three directed CI rounds by replying "lets go" to the concrete batch request. Earlier eleven-file authorization remains historical. Authorized budget: at most three evidence-backed new-head CI rounds within these files, stopping when all applicable acceptance checks pass; no unchanged retries or skipped failed checks. No merge, deployment, activation, live Replit change, dependency addition or native permission widening.

## MECHANISM
- Explicit opt-in development context for shared synthetic Git-backed release fixtures. Production, invalid mode and explicit artifact contexts are rejected before environment mutation. Hydra/monitor fixtures declare test preparation explicitly; no global conftest fallback or signing-key injection.
- Scanner and deployment provenance share one freshness-checked source authority in artifact mode. Runtime enforcement consumes its source commit. Source/trust errors propagate without falling back to Git.
- Preserve existing forbidden-file rules while pinning parent directories and file descriptors; compare file identity before/after reads and traversal. Existing read/traversal fault injections now target actual descriptor I/O and assert that the fault was reached.
- Retain the four staging cases (valid, missing, tampered, stale). Prepare the staging package explicitly from immutable Git HEAD/tree objects and verify every exported blob; keep the separate clean-working-tree snapshot contract unchanged. Dirty suite state is neither copied nor repaired. A separate fixed child loads actual package modules, installs the existing additive no-exec filter, verifies module bytes/origins, and calls the unmodified ASGI lifespan. Source/signing fixtures are synthetic and remain inside that process. No verification function is mocked and no private key is serialized.

## AUDIT
Base cc932cf2e8d3a8297b95db6c08fa12fe209de81d, PR main base 53e4c0efea5d5f67c91f70ba6b2b488b067d1530. Separate local repair/release-fixture-integration worktree preserves the previous candidate and failure evidence. Source/signature/release verifiers, cryptographic algorithms and both existing CI workflows remain byte-equal to the published base. Local source-preparation tests use disposable Git fixtures only, not project commits.

## GAP
PARTIAL. The 201 failures and 29 errors have NOT been rerun. All four package-bound lifespan cases and descriptor-scanner application cases are NOT_RUN. Full kernel isolation, mutable-state mapping, actual deployment module origins, build-to-runtime handoff and operational issuer trust are not established by the synthetic child. Its no-exec filter alone is not a complete sandbox. EGAP-HYDRA-REMOTE-TRANSPORT-AUTH remains open.

## VALIDATION
189 pure local harness/preparation tests PASS; seventeen new methods cover development-context boundaries and exact source snapshots, including dirty source, symlinks, nested/existing destinations and concurrent mutation. Python AST and git diff --check PASS. No product module was imported and no application/lifespan was executed locally. Historical native run 42136551762 passed 60 artifact/package/release cases, 20 mail cases and 13 controls at cc932cf2; that result does not validate these new startup changes. Historical broader regression run 42136551733 FAILED and remains preserved.

## ROLLBACK
Discard the unpublished candidate if rejected. Failed validation preserves bounded evidence and stops at the authorized budget. Do not repair production failures by weakening checks, removing positive tests, granting synthetic trust operational status or changing the active application.

## CHANGED FILES
- .github/workflows/mail-readiness-isolation.yml
- gateway/app.py
- governance/evidence/pb375_mail_isolation_preflight/generated_pr_body.md
- governance/evidence/pb375_mail_isolation_preflight/metadata.json
- governance/mail_draft_preview.py
- governance/mail_draft_repository.py
- governance/mail_preview_access_proposal.py
- governance/release_integrity.py
- runtime/enforcement_gateway.py
- security/deployment_attestation.py
- security/runtime_artifact_authority.py
- security/runtime_artifact_package.py
- security/runtime_artifact_provenance.py
- tests/helpers/provenance_manifest.py
- tests/helpers/release_environment.py
- tests/helpers/staging_artifact_child.py
- tests/helpers/staging_source_package.py
- tests/test_hydra_consensus.py
- tests/test_public_release_safety.py
- tests/test_runtime_artifact_scanner_candidate.py
- tests/test_runtime_governance_monitor.py
- tests/test_staging_launch.py
- validation/mail_readiness/README.md
- validation/mail_readiness/execution_boundary.py
- validation/mail_readiness/gidmap_guard.py
- validation/mail_readiness/isolation_preflight.py
- validation/mail_readiness/offline_mail_cases.py
- validation/mail_readiness/offline_mail_contract.py
- validation/mail_readiness/result_contract.py
- validation/mail_readiness/runner_bootstrap.py
- validation/mail_readiness/runtime_artifact_cases.py
- validation/mail_readiness/runtime_artifact_contract.py
- validation/mail_readiness/runtime_crypto.lock
- validation/mail_readiness/runtime_dependencies.py
- validation/mail_readiness/test_execution_boundary.py
- validation/mail_readiness/test_gidmap_guard.py
- validation/mail_readiness/test_offline_mail_contract.py
- validation/mail_readiness/test_result_contract.py
- validation/mail_readiness/test_runner_bootstrap.py
- validation/mail_readiness/test_runtime_artifact_harness.py
- validation/mail_readiness/test_staging_snapshot.py
- validation/mail_readiness/test_synthetic_release_context.py

## THIS BATCH
- gateway/app.py
- governance/evidence/pb375_mail_isolation_preflight/generated_pr_body.md
- governance/evidence/pb375_mail_isolation_preflight/metadata.json
- runtime/enforcement_gateway.py
- tests/helpers/provenance_manifest.py
- tests/helpers/release_environment.py
- tests/helpers/staging_artifact_child.py
- tests/helpers/staging_source_package.py
- tests/test_hydra_consensus.py
- tests/test_public_release_safety.py
- tests/test_runtime_artifact_scanner_candidate.py
- tests/test_runtime_governance_monitor.py
- tests/test_staging_launch.py
- validation/mail_readiness/test_staging_snapshot.py
- validation/mail_readiness/test_synthetic_release_context.py

## VALIDATION RESULTS
Local pure tests: 189 passed. Native gateway/staging/regression validation: NOT_RUN. Overall: PARTIAL. No production readiness claim.

## ROLLBACK PLAN
No active state changed. Preserve the previous published commit and all failed-run evidence; do not merge or activate this proposal.

## COMMIT OR SOURCE REFERENCE
Prepared against cc932cf2e8d3a8297b95db6c08fa12fe209de81d. No new project commit, publication or approval is claimed.

## IMPACT
A reviewable local integration candidate only. Existing failure evidence remains open pending actual native regression/staging execution. No active application or operational authority is changed.

## DECISION
REVIEW_REQUIRED

## STATUS
OWNER_AUTHORIZED_PUBLICATION_AND_BOUNDED_CI; current-head reviewer approvals remain independently required before any future merge.

## SOURCE
Exact prepared parent: cc932cf2e8d3a8297b95db6c08fa12fe209de81d.

## CI ROUND 1 AND CORRECTION
Published a7a7bb78391a4fa914915abd14d1db3e43eb7a52. Native run42140036869 passed182 harness tests,60 artifact/package/release cases,20 mail cases and13 controls; artifact digest3a07a626f88c6c568c99c6df1a0aca3955c9ba4e0c48409b47f0703e81038e10 verified. Broader run42140036829:2844 passed,194 subtests passed,4 staging setup errors (synthetic_source_requires_clean_candidate),4378 deselected. Preserve that failure. Round2 explicitly selects immutable Git objects instead of the dirty shared working tree; no fallback, reset or production relaxation. Seven added pure export checks pass, including preserved dirty state, symlink rejection, Git-attribute omission/substitution, changed HEAD, executable mode and unsafe destination. Staging outcomes remain NOT_RUN on the corrected source until round2 completes.
