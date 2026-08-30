# PB-1L

## Canonical Capability Name

`PB-1L Governance Release Candidate Evidence Lock`

PB-1L SHALL NOT authorize runtime execution.

## Purpose

PB-1L defines the metadata-only capability that follows the merged PB-1K implementation. It verifies that PB-1K approval evidence closure output, release-candidate metadata, approval references, audit references, rollback references, replay metadata, evidence chronology, and validation evidence can be locked into a deterministic governance release-candidate package for human review.

PB-1L does not approve a release, deploy software, call providers, activate production, mutate policy, mutate runtime state, or replace the gateway. It prepares a hash-only release-candidate evidence lock proving that required governance references are complete before any later release authorization process may inspect them.

## Governance Objective

PB-1L must preserve USBAY as an execution control layer by ensuring release-candidate evidence is complete, deterministic, redacted, approval-driven, rollback-aware, replay-safe, auditable, and fail-closed.

PB-1L verifies evidence lock metadata only. It must not interpret evidence lock completion as execution permission, deployment approval, provider readiness, production readiness, legal certification, compliance certification, or release approval.

## Architecture

PB-1L is a standalone metadata evaluator with four implementation artifacts:

- Runtime-facing metadata validator.
- Hash-only evidence schema.
- Focused regression tests.
- Runtime governance documentation.

The validator consumes supplied PB-1K references and release-candidate metadata by hash/reference only. It computes deterministic hashes using canonical, sorted, redacted metadata. It emits only status metadata and deterministic reason codes.

No external service is contacted. No provider, network, subprocess, deployment, timestamp authority, signing authority, WORM system, object-lock system, regulator transport, or production runtime is invoked.

## Execution Boundary

PB-1L may:

- Validate supplied metadata.
- Validate hash-only references.
- Validate PB-1K approval evidence closure references.
- Validate release-candidate evidence references.
- Validate human approval, audit, replay, rollback, and evidence chronology metadata by reference only.
- Compute deterministic hashes from redacted metadata.
- Return `READY`, `READY_WITH_RESTRICTIONS`, or `BLOCKED`.

PB-1L must not:

- Authorize runtime execution.
- Execute runtime actions.
- Execute provider actions.
- Deploy.
- Activate production.
- Open sockets.
- Call networks.
- Execute subprocesses.
- Start background workers.
- Use async execution.
- Read credentials.
- Store secrets.
- Mutate policy.
- Mutate runtime state.
- Claim production readiness.

## Allowed Inputs

Allowed inputs:

- PB-1K final decision reference.
- PB-1K approval closure hash.
- PB-1K evidence hash.
- PB-1K package hash.
- PB-1K decision hash.
- PB-1K audit hash.
- Release-candidate intent reference.
- Release-candidate evidence hash.
- Human approval reference.
- Approval evidence hash.
- Approval chronology reference.
- Audit-chain reference.
- Evidence-chain reference.
- Rollback evidence reference.
- Rollback plan reference.
- Replay metadata reference.
- Validation evidence references.
- Policy version reference.
- Tenant reference.
- Correlation reference.
- Expected release-candidate lock hash.
- Expected evidence hash.
- Expected package hash.
- Safety flags explicitly set to false.

All evidence, audit, decision, approval, replay, rollback, tenant, policy, release-candidate, and correlation references must be hash-only or immutable external references.

## Blocked Inputs

Blocked inputs:

- Raw payloads.
- Prompts.
- Provider responses.
- Credentials.
- Tokens.
- Private keys.
- Cookies.
- Secrets.
- Personal data.
- Environment dumps.
- Runtime artifacts containing sensitive material.
- Commands or direct execution requests.
- Network endpoints intended for live execution.
- Provider identifiers claiming active execution.
- Deployment targets.
- Production activation flags.
- Mutable policy contents.
- Approval contents.
- Non-deterministic runtime-generated evidence.
- Unknown metadata fields.

## Decision States

PB-1L may emit only:

- `READY`
- `READY_WITH_RESTRICTIONS`
- `BLOCKED`

`READY` means all required release-candidate evidence lock metadata validates, PB-1K is not blocked, human approval reference metadata is present, rollback references are present, replay protection metadata is valid, evidence chronology is consistent, and every execution safety flag remains false.

`READY_WITH_RESTRICTIONS` means required metadata validates and explicit governed restriction metadata is present by reference only.

`BLOCKED` means at least one required governance condition is absent, malformed, mismatched, stale, duplicated, unsupported, sensitive, execution-shaped, replayed, or unverifiable.

No PB-1L decision authorizes execution.

## Canonical Reason Codes

PB-1L implementation must emit deterministic reason codes. Required reason-code categories include:

- `PB_1K_METADATA_MISSING`
- `INVALID_PB_1K_DECISION`
- `PB_1K_APPROVAL_CLOSURE_HASH_MISSING`
- `PB_1K_EVIDENCE_HASH_MISSING`
- `PB_1K_PACKAGE_HASH_MISSING`
- `PB_1K_DECISION_HASH_MISSING`
- `PB_1K_AUDIT_HASH_MISSING`
- `RELEASE_CANDIDATE_REFERENCE_MISSING`
- `RELEASE_CANDIDATE_EVIDENCE_MISSING`
- `APPROVAL_REFERENCE_MISSING`
- `APPROVAL_EVIDENCE_MISSING`
- `APPROVAL_INVALID`
- `AUDIT_CHAIN_MISSING`
- `AUDIT_HASH_MISMATCH`
- `EVIDENCE_CHAIN_MISSING`
- `EVIDENCE_HASH_MISMATCH`
- `ROLLBACK_REFERENCE_MISSING`
- `ROLLBACK_EVIDENCE_MISSING`
- `REPLAY_METADATA_MISSING`
- `DUPLICATE_RELEASE_CANDIDATE_METADATA`
- `VALIDATION_METADATA_MISSING`
- `POLICY_VERSION_MISSING`
- `POLICY_VERSION_MISMATCH`
- `TENANT_REFERENCE_MISSING`
- `TENANT_REFERENCE_MISMATCH`
- `CORRELATION_REFERENCE_MISSING`
- `CHRONOLOGY_MISMATCH`
- `STALE_METADATA`
- `UNSUPPORTED_CAPABILITY_METADATA`
- `UPSTREAM_BLOCKED`
- `HASH_REFERENCE_MISSING`
- `RELEASE_CANDIDATE_LOCK_HASH_MISMATCH`
- `PACKAGE_HASH_MISMATCH`
- `EXECUTION_FLAG_NOT_FALSE`
- `EXECUTION_SURFACE_REJECTED`
- `SENSITIVE_DATA_REJECTED`
- `CREDENTIAL_LITERAL_REJECTED`
- `MALFORMED_PB_1L_METADATA`
- `INTERNAL_ERROR`

Reason codes must be stable, sorted, deduplicated, and non-sensitive.

## Required Metadata

PB-1L input metadata must include:

- PB-1K final decision reference.
- PB-1K approval closure hash.
- PB-1K evidence hash.
- PB-1K package hash.
- PB-1K decision hash.
- PB-1K audit hash.
- Release-candidate intent reference.
- Release-candidate evidence reference.
- Human approval reference.
- Approval evidence reference.
- Audit-chain reference.
- Evidence-chain reference.
- Rollback evidence reference.
- Rollback plan reference.
- Replay metadata reference.
- Validation metadata reference.
- Policy version reference.
- Tenant reference.
- Correlation reference.
- Expected release-candidate lock hash.
- Expected evidence hash.
- Expected package hash.
- Safety flags explicitly set to false.

All hash references must use canonical `sha256:<64 lowercase hex>` values.

## Required Evidence

PB-1L evidence must be hash-only and redacted. Required evidence references:

- PB-1K approval closure reference.
- PB-1K evidence reference.
- PB-1K audit reference.
- Release-candidate evidence reference.
- Approval evidence reference.
- Human approval reference.
- Audit-chain evidence reference.
- Evidence-chain reference.
- Rollback evidence reference.
- Rollback plan evidence reference.
- Replay metadata evidence reference.
- Validation evidence reference.
- Boundary verification evidence reference.
- Sensitive-data scan evidence reference.
- Execution-surface scan evidence reference.

Evidence must never include raw payloads, prompts, provider responses, credentials, approval contents, tokens, cookies, private keys, personal data, environment dumps, runtime artifacts, or secret values.

## Required Approval References

PB-1L requires an external human approval reference before returning `READY` or `READY_WITH_RESTRICTIONS`.

Approval references must bind, by hash or immutable reference:

- PB-1L capability name.
- PB-1K decision hash.
- PB-1K package hash.
- Release-candidate intent reference.
- Release-candidate evidence hash.
- Rollback evidence reference.
- Policy version reference.
- Tenant reference.
- Correlation reference.
- Replay metadata reference.
- Chronology metadata.

PB-1L must not inspect, serialize, summarize, or expose approval contents.

## Required Audit References

PB-1L must validate audit metadata by reference only.

Required audit references:

- PB-1K audit hash.
- PB-1L validation audit hash.
- Previous audit hash.
- Current audit hash.
- Expected current audit hash.
- Approval audit reference.
- Release-candidate audit reference.
- Correlation reference.
- Policy version reference.
- Tenant reference.

Missing, malformed, reordered, stale, duplicate, or mismatched audit metadata must return `BLOCKED`.

## Required Rollback References

PB-1L must validate rollback metadata by reference only.

Rollback references must include:

- Rollback plan reference.
- Rollback evidence reference.
- Previous release-candidate package hash.
- Current release-candidate package hash.
- Rollback owner reference.
- Rollback chronology reference.

Missing, malformed, stale, mismatched, non-hash, or duplicated rollback metadata must return `BLOCKED`.

PB-1L must not execute rollback, mutate release state, deploy replacement artifacts, or contact external recovery systems.

## Replay Protection

PB-1L must validate replay metadata by reference only.

Replay metadata must include:

- Nonce reference.
- Timestamp or chronology reference.
- Previous package hash.
- Current package hash.
- Replay window metadata.
- Duplicate approval detection metadata.
- Duplicate release-candidate detection metadata.
- Duplicate package detection metadata.

Missing, stale, duplicated, reordered, expired, or mismatched replay metadata must return `BLOCKED`.

PB-1L must not generate live nonces, contact timestamp authorities, call external verifiers, or store mutable replay state.

## Evidence Chronology

PB-1L must verify chronology metadata by reference only.

Chronology must prove deterministic ordering from:

1. PB-1K approval evidence closure.
2. Release-candidate intent metadata.
3. Human approval reference.
4. Audit-chain reference.
5. Evidence-chain reference.
6. Rollback reference.
7. Replay metadata reference.
8. PB-1L validation evidence.

Missing, duplicated, reordered, stale, or mismatched chronology metadata must return `BLOCKED`.

## Deterministic Requirements

PB-1L must:

- Use canonical serialization.
- Sort metadata deterministically.
- Sort reason codes deterministically.
- Deduplicate reason codes deterministically.
- Emit identical output for identical input.
- Produce hash-only evidence.
- Preserve redacted metadata only.
- Preserve all execution flags as false.

PB-1L must not use wall-clock time, random values, generated UUIDs, environment-derived values, network state, filesystem mutation state, provider responses, or subprocess output as decision inputs.

## Fail-Closed Behavior

PB-1L must return `BLOCKED` for every unknown, missing, malformed, stale, unsupported, inconsistent, sensitive, execution-shaped, replayed, duplicated, or unverifiable input.

PB-1L must also return `BLOCKED` when:

- PB-1K metadata is missing.
- PB-1K final decision is `BLOCKED`.
- PB-1K final decision is unknown.
- PB-1K approval closure hash is missing.
- PB-1K evidence hash is missing.
- PB-1K package hash is missing.
- PB-1K decision hash is missing.
- PB-1K audit hash is missing.
- Release-candidate reference is missing.
- Release-candidate evidence is missing.
- Human approval reference is missing.
- Approval evidence is missing.
- Audit chain reference is missing.
- Evidence chain reference is missing.
- Rollback reference is missing.
- Rollback evidence is missing.
- Replay metadata is missing.
- Validation metadata is missing.
- Policy version reference is missing.
- Tenant reference is missing.
- Correlation reference is missing.
- Evidence chronology is missing or inconsistent.
- Any expected hash mismatches the computed hash.
- Any safety flag is not false.
- Any direct execution request is present.
- Any provider, deployment, production, network, subprocess, credential, secret, policy mutation, or runtime mutation surface is present.
- Any exception occurs during validation.

## Exact Implementation Boundary

PB-1L implementation must be isolated to the exact files listed below. The implementation boundary is mandatory and fail-closed.

## Exact Implementation Files

PB-1L implementation will be allowed to create only:

1. `docs/runtime/PB_1L_GOVERNANCE_RELEASE_CANDIDATE_EVIDENCE_LOCK.md`
2. `governance/evidence/pb_1l_governance_release_candidate_evidence_lock.json`
3. `runtime/computer_use/pb_1l_governance_release_candidate_evidence_lock.py`
4. `tests/test_pb_1l_governance_release_candidate_evidence_lock.py`

PB-1L implementation must not modify PB-1B through PB-1K files unless a later approved specification explicitly changes this boundary.

## Blocked Files

PB-1L must not modify:

- PB-1B implementation files.
- PB-1C implementation files.
- PB-1D implementation files.
- PB-1E implementation files.
- PB-1F implementation files.
- PB-1G implementation files.
- PB-1H implementation files.
- PB-1I implementation files.
- PB-1J implementation files.
- PB-1K implementation files.
- Gateway runtime files.
- Policy evaluation files.
- Provider execution files.
- Deployment files.
- CI workflow files.
- Dependency files.
- Secrets, credentials, key material, or environment configuration.
- Any file outside the exact PB-1L implementation boundary.

## Required Focused Tests

PB-1L implementation must include focused tests for:

- Valid release-candidate evidence lock.
- Valid lock with governed restrictions.
- Missing PB-1K metadata.
- Invalid PB-1K decision.
- Missing PB-1K hashes.
- Missing release-candidate reference.
- Missing release-candidate evidence.
- Missing approval reference.
- Invalid approval reference.
- Missing approval evidence.
- Missing audit chain.
- Audit hash mismatch.
- Missing evidence chain.
- Evidence hash mismatch.
- Missing rollback reference.
- Missing rollback evidence.
- Missing replay metadata.
- Duplicate approval metadata.
- Duplicate release-candidate metadata.
- Duplicate package metadata.
- Missing validation metadata.
- Missing policy version.
- Policy version mismatch.
- Missing tenant reference.
- Tenant mismatch.
- Missing correlation reference.
- Chronology mismatch.
- Stale metadata.
- Unsupported metadata.
- Upstream `BLOCKED`.
- Hash mismatch.
- Execution-shaped input.
- Provider execution request.
- Deployment request.
- Production activation request.
- Runtime mutation request.
- Policy mutation request.
- Network/subprocess request.
- Sensitive input.
- Credential-shaped literal.
- Malformed metadata.
- Deterministic repeated evaluation.
- Canonical decision-state output.
- Canonical reason-code output.
- False execution flags.
- Redacted evidence output.
- Internal exception behavior.

## Required Regressions

PB-1L implementation must run and keep passing:

- PB-1B regression tests.
- PB-1C regression tests.
- PB-1D regression tests.
- PB-1E regression tests.
- PB-1F regression tests.
- PB-1G regression tests.
- PB-1H regression tests.
- PB-1I regression tests.
- PB-1J regression tests.
- PB-1K regression tests.
- Relevant governance regression tests.
- Relevant evidence/hash regression tests.
- JSON validation for PB-1L evidence.
- Python syntax and import validation.
- Markdown validation.
- `git diff --check`.
- `git diff --cached --check`.
- Boundary validation.
- Conflict-marker scan.
- Sensitive-data scan.
- Credential-shaped literal scan.
- Prohibited execution-surface scan.

## Success Criteria

PB-1L implementation succeeds only when:

- The implementation follows this specification exactly.
- The changed-file boundary is exact.
- PB-1K metadata validates by hash/reference only.
- Release-candidate metadata validates by hash/reference only.
- Human approval metadata validates by external reference only.
- Audit, evidence, replay, rollback, validation, tenant, policy, and correlation metadata validate.
- Evidence chronology validates.
- Outputs are deterministic.
- Outputs are hash-only and redacted.
- All execution safety flags remain false.
- PB-1B through PB-1K regressions pass.
- Security scans pass.
- Human reviewers approve the PR.

## Rollback Criteria

PB-1L rollback must be isolated to the PB-1L implementation commit.

Rollback impact:

- Removes release-candidate evidence lock metadata.
- Does not remove PB-1B through PB-1K controls.
- Does not authorize execution.
- Does not affect production activation.
- Does not change gateway behavior.
- Does not alter provider behavior.
- Does not weaken audit lineage.

## Future Dependencies

PB-1L does not implement:

- Live deployment.
- Provider execution.
- Runtime execution.
- External signing.
- RFC3161 timestamp authority.
- WORM persistence.
- Object-lock persistence.
- Regulator submission.
- Production activation.
- Legal certification.
- Compliance certification.

Future batches may define these capabilities only through separate approved specifications.

## Explicitly Prohibited Behavior

PB-1L must not:

- Weaken PB-1B through PB-1K.
- Bypass approvals.
- Execute providers.
- Execute runtime actions.
- Deploy.
- Execute subprocesses.
- Execute network actions.
- Open sockets.
- Start background workers.
- Use async execution.
- Store secrets.
- Read credentials.
- Serialize sensitive data.
- Introduce nondeterminism.
- Mutate policy.
- Mutate runtime state.
- Claim production readiness.
- Claim provider readiness.
- Claim legal certification.
- Claim compliance certification.

PB-1L must preserve deterministic governance, fail-closed execution, audit evidence, replay safety, rollback traceability, the approval chain, and metadata-only governance.
