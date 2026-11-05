## PURPOSE
Prepare a public pre-issued-manifest packaging path alongside the existing fixed mail/artifact validation. The new packaging API/CLI verifies an independently signed public manifest and explicit expected source references, copies the declared bytes into a fresh output and verifies that output. It does not execute Git or consume a private key in this path. Ten new native cases are prepared; no new native run is claimed.

## RISK
Packaging a signed declared source set does not independently reconstruct Git history, establish operational producer/issuer authority, select a trust anchor or authorize a deployment. The unpublished CLI replaces --signing-key-file with public manifest/source inputs; external callers of the old CLI are UNKNOWN and require migration review. Full gateway startup remains outside this phase.

## POLICY_LINK
Existing AGENTS.md and fail-closed source, trust, identity, tenant and evidence boundaries. PB-375 is an administrative review identifier; this proposal does not adopt a policy or create operational authority.

## REQUIRED_APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE_CHECKS
- Owner authorized publication of this prepared eight-file batch on PR #427 and at most three evidence-backed new-head CI rounds by replying "lets go" to the explicit scoped request. Stop at first success; no unchanged retry or permission/dependency widening. Earlier scoped authorizations remain historical.
- Proposed publication changes eight files including accurate review metadata; preserve the entire 27-path cumulative PR inventory.
- Require independently supplied public verifier trust and exact expected commit/tree references. Reject missing/mismatched bindings, invalid signatures, changed source and an existing destination. No generated/default signer, trust or manifest.
- Write the public manifest last and verify the copied output. Partial failed output is not automatically reused, deleted or promoted.
- The public packaging path calls no Git or signing API. The old in-memory producer API remains separate; its Git helper import is deferred until that API is called. No producer module is added to the fixed native export.
- Preserve all13 controls, existing kernel/identity/source/no-exec checks, capability drop, mapping restoration and existing three hash-locked test dependencies. No dependency or native permission widening.
- Require all40 fixed artifact/public-package cases,20 mail cases and168 pure harness tests to pass in a future scoped native round. Preserve bounded outcomes and source/dependency bindings.
- No live mailbox, independent issuer, deployment hook, operational key, merge, deployment, activation or active Replit change. Synthetic test keys exist only in memory.
- Stop on failure, missing authority/input/binding, unsupported runtime or any requirement for additional permissions. Do not silently fall back to Git/private-key CLI behavior.

## AUDIT
Prepared locally on 41b8368519399c037e3184870fd3224847af82f4 (treefa8896353c8de089e2793315f61ba2cfc9546482). 168 pure harness tests passed. Five new pure tests check CLI inputs, verification/copy/publish ordering, private-key serialization absence, closed source export and bounded argument diagnostics. Existing30 artifact methods remain AST-equal and existing20 mail cases/native safety files are byte-equal. Ten new actual packaging/CLI cases are NOT_RUN. The historical exact-head native result on 41b8368519399c037e3184870fd3224847af82f4 remains163 harness,30 artifact,20 mail and13 controls passed; it is not new proof for this worktree.

## IMPACT
Remove a private-key-file/Git requirement from the prepared packaging handoff while keeping issuance, trust provisioning and activation independent. This is a bounded next step toward source-package/startup integration; it does not establish production readiness.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL

## MECHANISM
package_preissued_runtime_artifact validates a previously signed public manifest, copies declared bytes through the existing descriptor-based copier, rechecks source and verifies the completed package. The CLI reads only public manifest/trust inputs. No build/run configuration is installed.


## GAP
PARTIAL: new packaging code and ten cases are prepared but native execution is pending. Operational manifest issuance, independently governed trust, runtime-root ownership/selection and actual build-to-runtime handoff remain UNKNOWN. Full gateway imports, state-directory mapping and scanner/provenance composition are unvalidated.


## VALIDATION
168 local pure harness tests PASS. Syntax/source/patch checks PASS. No product/crypto imports in the local test run; no dependency installation/download or new native execution. Existing native results bind their historical head only.


## ROLLBACK
Discard the unpublished proposal if rejected. Failed packaging leaves an unaccepted destination; no automatic deletion, overwrite, promotion or execution. A future failed native round must stop and retain bounded evidence.


## SOURCE
https://github.com/USJAY77/usbay-policy-brain-public/commit/41b8368519399c037e3184870fd3224847af82f4


## CHANGED FILES
- .github/workflows/mail-readiness-isolation.yml
- governance/evidence/pb375_mail_isolation_preflight/generated_pr_body.md
- governance/evidence/pb375_mail_isolation_preflight/metadata.json
- governance/mail_draft_preview.py
- governance/mail_draft_repository.py
- governance/mail_preview_access_proposal.py
- security/runtime_artifact_authority.py
- security/runtime_artifact_package.py
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
New worktree:168 pure harness tests passed;40 artifact cases prepared (30 unchanged plus10 new),20 existing mail cases retained. New native cases NOT_RUN; no gateway startup or operational readiness claimed.


## ROLLBACK PLAN
No active deployment/configuration has changed. Disposable future test runner only; do not infer authority to revert live state.


## COMMIT OR SOURCE REFERENCE
Prepared parent 41b8368519399c037e3184870fd3224847af82f4; PR base 53e4c0efea5d5f67c91f70ba6b2b488b067d1530. The worktree has no new commit identity and is not externally published.
