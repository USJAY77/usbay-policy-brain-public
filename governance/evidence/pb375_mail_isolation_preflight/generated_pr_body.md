## PURPOSE
Prepare fixed native validation of the runtime source-artifact verifier and freshness consumer. Add the two existing reviewed candidate modules byte-for-byte, a fixed 30-case synthetic verifier driver and hash-bound dependency staging. Preserve the existing 20 offline mail cases and 13 native controls. This working-tree proposal is not published or executed in CI.

## RISK
A valid signature establishes correspondence to a configured synthetic test key; it does not establish an operational producer, issuer or execution grant. Downloaded native extensions increase the test payload and require exact hash binding plus containment before import. No result establishes full gateway startup or Governed Mail production readiness.

## POLICY_LINK
Existing fail-closed and source-identity boundaries; baseline AGENTS.md; PB-375 remains an administrative review identifier, not a policy or product authority grant.

## REQUIRED_APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE_CHECKS
- Owner authorized this concrete proposal by replying "lets go" to the explicit request for publication on PR #427 and one isolated hosted CI round including the three hash-locked test packages. This authorizes this test batch only; historical authorizations retain their separate scopes.
- Authorized batch: publish this exact batch on PR #427 and allow one automatic hosted CI round, including only cryptography==50.0.2, cffi==2.1.1 and pycparser==3.11 from the existing hash-locked profile. No pip install, build backend, dependency resolution or additional packages.
- The nonprivileged controller downloads only binary wheels with required hashes. The privileged bootstrap independently verifies the source export, wheel hashes and extracted tree before namespace launch.
- Existing mapping guard, capability drop, kernel restrictions and fixed Python/loader startup remain unchanged. Native dependency import occurs only after all 13 controls, fresh identity, no-exec gate, source binding and read-only dependency checks pass. No executable allowlist widening.
- Private synthetic signing keys exist only in process memory. No operational secrets, live mailbox, provider, signing service or real release issuance are used.
- Stop on missing/ambiguous binding, unsupported Python or wheels, failed containment, failed cases or unexpected source/permission changes. Preserve bounded evidence. No unchanged reruns.
- No merge, deployment, activation, live execution or authority/trust/policy widening. Any future head requires applicable independent reviews.

## AUDIT
Local proposal based on bebf7227f2974610ab7411b95c09a99a0bf279ba (tree 26c97fb9602db2369e64dde15cb8a148ebbc4bde). 158 pure harness unit tests passed under Python 3.12.14. Syntax checks passed for 18 Python source files; embedded probe AST parsed. Existing kernel_restrictions AST and execution_boundary.py, gidmap_guard.py, result_contract.py and offline_mail_cases.py remain unchanged. Two artifact modules match the existing private review candidate byte-for-byte. No cryptographic/product modules were imported by the local test suite. No packages were downloaded or installed, no filters or privileged bootstrap were run, and no new native or CI result is claimed. Historical native results cover previous exact heads only.

## IMPACT
Provide a bounded next validation of artifact signature, source binding, path/mutation handling and freshness without changing the active Replit checkout or claiming full startup/readiness. Production authority, producer build wiring, gateway integration, provider behavior, recovery and remote transport remain separate open boundaries.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL

## MECHANISM
Fixed source export, immutable result selection, exact existing three-package lock subset, independent wheel/tree verification and post-gate native test import. Outcome-only diagnostics with execution_authorized=false.


## GAP
PARTIAL: 30 new native artifact cases are prepared but NOT_RUN. Python 3.12 wheel compatibility and availability are UNKNOWN until authorized CI. Entire gateway startup, producer/build-to-runtime artifact wiring, cached authority concurrency, operational trust and production readiness are not demonstrated. In-process native code remains outside any claim of exhaustive sandbox containment.


## VALIDATION
PROVEN within local pure-harness scope: 158 tests PASS. New runtime cases and previous mail cases were not executed locally. No CI run, download, install, application import or production change in this batch.


## ROLLBACK
Abandon the unpublished candidate if not approved. Future CI must dispose of the runner and preserve bounded failure evidence; existing mapping-policy restoration remains mandatory. No operational rollback is authorized by this proposal.


## SOURCE
https://github.com/USJAY77/usbay-policy-brain-public/commit/bebf7227f2974610ab7411b95c09a99a0bf279ba


## CHANGED FILES
- .github/workflows/mail-readiness-isolation.yml
- governance/evidence/pb375_mail_isolation_preflight/generated_pr_body.md
- governance/evidence/pb375_mail_isolation_preflight/metadata.json
- governance/mail_draft_preview.py
- governance/mail_draft_repository.py
- governance/mail_preview_access_proposal.py
- security/runtime_artifact_authority.py
- security/runtime_artifact_provenance.py
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


## VALIDATION RESULTS
158 local pure harness tests passed. 30 new artifact cases NOT_RUN; 20 existing offline mail cases retained without modification. No new native result or readiness claim.


## ROLLBACK PLAN
Disposable test runner only; no active Replit, provider, deployment or activation changes.


## COMMIT OR SOURCE REFERENCE
Parent bebf7227f2974610ab7411b95c09a99a0bf279ba; PR base 53e4c0efea5d5f67c91f70ba6b2b488b067d1530. Proposed worktree has no new commit identity. Public CI, third-party wheel staging and publication require new explicit authorization.
