## PURPOSE
Prepare native integration of the signed source artifact with the deployment release reader and the startup release-validation function. Add20 fixed release-consumer cases to the existing40 artifact/package cases, retaining20 mail cases and all13 native controls. Reuse the existing three-package crypto profile; do not import or start gateway.app.

## RISK
A valid source artifact does not authorize release issuance, production trust, a tenant action or deployment. Release-path fallback must not generate missing evidence. Ambiguous JSON and development signing defaults must not establish production validation. Public synthetic fixtures exercise reader behavior only; they do not demonstrate adopted policy signatures, real node enrollment or operational issuer authority.

## POLICY_LINK
Existing AGENTS.md and fail-closed source, trust, tenant, currentness and evidence boundaries. PB-375 remains an administrative validation identifier. No adopted policy, signing algorithm, key storage/provider or operational trust anchor is created by this proposal.

## REQUIRED_APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE_CHECKS
- Owner authorized publication of this eleven-file release-consumer batch on PR #427 and at most three evidence-backed new-head CI rounds by replying "lets go" in this conversation. Stop at first success; earlier batch authorizations remain historical.
- Authorized budget: at most three evidence-backed new-head CI rounds within this exact batch; stop at first success. No unchanged retries, dependency additions, native permission widening or unrelated changes.
- Require one current shared/fresh source verifier in the release consumer; reject substituted source objects, stale files and release/source/expected-commit mismatches without Git fallback.
- Packaged runtime requires explicit release-path selection. A missing or malformed public release must not be generated or repaired; force does not authorize runtime release generation.
- Tighten existing production signing-input validation: missing independent material and the development default fail closed. Existing key sources/storage and HMAC signature algorithm remain unchanged. No actual signing material is read during preparation or provisioned by this batch.
- Use a bounded regular-file/no-follow release reader. Reject duplicate object fields, nonfinite numbers and float overflow. Existing missing/malformed-read error classification remains bounded; no raw input or path is logged.
- Export only the statically identified ten-module consumer closure in addition to the existing fixed sources. Update workflow path coverage for every new exported product path. No Redis/FastAPI/network/service or Git permission is added.
- Native fixtures use in-memory source keys, explicit test-mode HMAC evidence and public synthetic policy snapshots. Patch fixture paths/cache configuration only; do not mock verifier or signing functions.
- Require172 pure harness tests,60 exact artifact/package/release cases,20 mail cases and13 controls in a future native round; verify source/runtime/dependency/identity bindings and mapping restoration.
- No merge, deployment, activation, active Replit update, live state, operational key, provider action or new policy/issuer/recovery/remote-transport authority.

## AUDIT
Prepared on c71c89d5b50d714fcdda088c8859c18a736fc002 (tree482cac2e9c9d93a94463473a9a80fe3d597d13b1), preserving the concurrent Cursor packager-path filter correction. Current-base GitHub status reports all15 checks successful; this is not new consumer validation. Local172 pure harness tests pass. One initial structural assertion failure was retained and corrected to inspect the actual signing helper. New20 native release cases are NOT_RUN. The ten-module static import closure requires cryptography only; the existing dependency lock/profile and kernel/inside/bootstrap/no-exec code are unchanged. Historical native40 artifact/package,20 mail,168 harness and13 control results remain bound to their earlier heads.

## IMPACT
Validate the next real startup component without expanding native permissions or installing the full gateway dependency graph. This is release-reader/source-artifact integration preparation, not full gateway/server startup or Governed Mail production readiness.

## Decision
REVIEW_REQUIRED

## Status
AWAITING_APPROVAL

## MECHANISM
Shared source-artifact consumption in deployment attestation; explicit read-only release selection; packaged-mode Git-lineage denial; stricter production signing-input validation; bounded no-follow JSON parsing with duplicate/nonfinite rejection. The native driver calls actual release resolution and assert_startup_release_integrity using isolated public fixtures.


## GAP
PARTIAL: actual release-consumer behavior and20 new cases remain unexecuted. Full gateway/scanner imports, mutable-state mapping, producer output to actual runtime-root handoff, operational issuer/root trust and live tenant/provider authority remain unproven. Synthetic policy fixtures are not adopted policy-signature or node-attestation proof. Release-file symlinks and ambiguous JSON formerly accepted by the permissive reader may now be rejected; review compatibility before adoption.


## VALIDATION
172 local pure harness tests PASS; syntax/import-closure/patch checks PASS. The existing40 case method ASTs and native enforcement functions remain unchanged. No product/crypto import or application execution in local preparation. Twenty new native cases NOT_RUN.


## ROLLBACK
Abandon the unpublished proposal if rejected. Failed native validation stops and preserves bounded evidence. No automatic key/trust replacement, release generation, runtime repair, rollback or deployment action is permitted.


## SOURCE
https://github.com/USJAY77/usbay-policy-brain-public/commit/c71c89d5b50d714fcdda088c8859c18a736fc002


## CHANGED FILES
- .github/workflows/mail-readiness-isolation.yml
- governance/evidence/pb375_mail_isolation_preflight/generated_pr_body.md
- governance/evidence/pb375_mail_isolation_preflight/metadata.json
- governance/mail_draft_preview.py
- governance/mail_draft_repository.py
- governance/mail_preview_access_proposal.py
- governance/release_integrity.py
- security/deployment_attestation.py
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
172 pure local harness tests passed. Prepared native selection:40 retained artifact/package cases plus20 new release cases;20 mail cases retained. No new native pass, server startup or readiness claim.


## ROLLBACK PLAN
Disposable preparation/test environment only; production state and active Replit configuration are unchanged.


## COMMIT OR SOURCE REFERENCE
Prepared parent c71c89d5b50d714fcdda088c8859c18a736fc002; PR base 53e4c0efea5d5f67c91f70ba6b2b488b067d1530. No new commit identity or publication is claimed. Previous verification/failure artifacts are retained.
