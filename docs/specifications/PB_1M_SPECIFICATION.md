# PB-1M

## Canonical Capability Name

`PB-1M Governance Final Release Review Package`

PB-1M SHALL NOT authorize runtime execution.

## Purpose

PB-1M defines the metadata-only capability that follows the merged PB-1L implementation. It verifies that PB-1L release-candidate evidence lock output, final release-review metadata, approval references, audit references, replay references, rollback references, evidence chronology, and validation evidence can be assembled into a deterministic final governance review package.

PB-1M does not approve a release, deploy software, call providers, activate production, mutate policy, mutate runtime state, execute rollback, or replace the gateway. It prepares a hash-only final release-review package proving that required governance references are complete before any later human release authorization process may inspect them.

## Governance Objective

PB-1M must preserve USBAY as an execution control layer by ensuring final release-review metadata is complete, deterministic, redacted, approval-driven, rollback-aware, replay-safe, audit-linked, chronology-linked, and fail-closed.

PB-1M verifies final governance review package metadata only. It must not interpret package completion as execution permission, deployment approval, provider readiness, production readiness, legal certification, compliance certification, or release approval.

## Architecture

PB-1M is a standalone metadata evaluator with four future implementation artifacts:

- Runtime-facing metadata validator.
- Hash-only evidence schema.
- Focused regression tests.
- Runtime governance documentation.

The validator consumes supplied PB-1L references and final release-review metadata by hash/reference only. It computes deterministic hashes using canonical, sorted, redacted metadata. It emits only status metadata and deterministic reason codes.

No external service is contacted. No provider, network, subprocess, deployment, timestamp authority, signing authority, WORM system, object-lock system, regulator transport, or production runtime is invoked.

## Execution Boundary

PB-1M may:

- Validate supplied metadata.
- Validate hash-only references.
- Validate PB-1L release-candidate evidence lock references.
- Validate final release-review metadata references.
- Validate human approval, audit, replay, rollback, and evidence chronology metadata by reference only.
- Compute deterministic hashes from redacted metadata.
- Return `READY`, `READY_WITH_RESTRICTIONS`, or `BLOCKED`.

PB-1M must not:

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

## Allowed Metadata

Allowed metadata:

- PB-1L final decision reference.
- PB-1L release-candidate lock hash.
- PB-1L evidence hash.
- PB-1L package hash.
- PB-1L decision hash.
- PB-1L audit hash.
- Final release-review intent reference.
- Final release-review evidence hash.
- Human approval reference.
- Approval evidence hash.
- Approval chronology reference.
- Audit-chain reference.
- Evidence-chain reference.
- Replay metadata reference.
- Rollback plan reference.
- Rollback evidence reference.
- Validation evidence references.
- Policy version reference.
- Tenant reference.
- Correlation reference.
- Expected final review package hash.
- Expected evidence hash.
- Expected package hash.
- Safety flags explicitly set to false.

All evidence, audit, decision, approval, replay, rollback, tenant, policy, final review, and correlation references must be hash-only or immutable external references.

## Blocked Metadata

Blocked metadata:

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

## Deterministic Outputs

PB-1M may output only:

- Final decision.
- Deterministic reason codes.
- Final review package hash.
- Evidence hash.
- Package hash.
- Decision hash.
- Redacted metadata.
- Execution safety flags set to false.

PB-1M must not output:

- Execution authorization.
- Provider authorization.
- Deployment authorization.
- Production activation.
- Runtime mutation.
- Policy mutation.
- Raw payload logs.
- Credential material.
- Secret values.
- Approval contents.
- Provider response contents.
- Network execution results.
- Non-deterministic runtime-generated evidence.

## Decision States

PB-1M may emit only:

- `READY`
- `READY_WITH_RESTRICTIONS`
- `BLOCKED`

`READY` means all required final release-review package metadata validates, PB-1L is not blocked, human approval reference metadata is present, rollback references are present, replay protection metadata is valid, evidence chronology is consistent, and every execution safety flag remains false.

`READY_WITH_RESTRICTIONS` means required metadata validates and explicit governed restriction metadata is present by reference only.

`BLOCKED` means at least one required governance condition is absent, malformed, mismatched, stale, duplicated, unsupported, sensitive, execution-shaped, replayed, or unverifiable.

No PB-1M decision authorizes execution.

## Canonical Reason Codes

PB-1M implementation must emit deterministic reason codes. Required reason-code categories include:

- `PB_1L_METADATA_MISSING`
- `INVALID_PB_1L_DECISION`
- `PB_1L_RELEASE_CANDIDATE_LOCK_HASH_MISSING`
- `PB_1L_EVIDENCE_HASH_MISSING`
- `PB_1L_PACKAGE_HASH_MISSING`
- `PB_1L_DECISION_HASH_MISSING`
- `PB_1L_AUDIT_HASH_MISSING`
- `FINAL_REVIEW_REFERENCE_MISSING`
- `FINAL_REVIEW_EVIDENCE_MISSING`
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
- `DUPLICATE_FINAL_REVIEW_METADATA`
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
- `FINAL_REVIEW_PACKAGE_HASH_MISMATCH`
- `PACKAGE_HASH_MISMATCH`
- `EXECUTION_FLAG_NOT_FALSE`
- `EXECUTION_SURFACE_REJECTED`
- `SENSITIVE_DATA_REJECTED`
- `CREDENTIAL_LITERAL_REJECTED`
- `MALFORMED_PB_1M_METADATA`
- `INTERNAL_ERROR`

Reason codes must be stable, sorted, deduplicated, and non-sensitive.

## Required Approval References

PB-1M requires an external human approval reference before returning `READY` or `READY_WITH_RESTRICTIONS`.

Approval references must bind, by hash or immutable reference:

- PB-1M capability name.
- PB-1L decision hash.
- PB-1L package hash.
- Final release-review intent reference.
- Final release-review evidence hash.
- Rollback evidence reference.
- Policy version reference.
- Tenant reference.
- Correlation reference.
- Replay metadata reference.
- Chronology metadata.

PB-1M must not inspect, serialize, summarize, or expose approval contents.

## Required Audit References

PB-1M must validate audit metadata by reference only.

Required audit references:

- PB-1L audit hash.
- PB-1M validation audit hash.
- Previous audit hash.
- Current audit hash.
- Expected current audit hash.
- Approval audit reference.
- Final review audit reference.
- Correlation reference.
- Policy version reference.
- Tenant reference.

Missing, malformed, reordered, stale, duplicate, or mismatched audit metadata must return `BLOCKED`.

## Replay References

PB-1M must validate replay metadata by reference only.

Replay metadata must include:

- Nonce reference.
- Timestamp or chronology reference.
- Previous package hash.
- Current package hash.
- Replay window metadata.
- Duplicate approval detection metadata.
- Duplicate final-review detection metadata.
- Duplicate package detection metadata.

Missing, stale, duplicated, reordered, expired, or mismatched replay metadata must return `BLOCKED`.

PB-1M must not generate live nonces, contact timestamp authorities, call external verifiers, or store mutable replay state.

## Rollback References

PB-1M must validate rollback metadata by reference only.

Rollback references must include:

- Rollback plan reference.
- Rollback evidence reference.
- Previous final review package hash.
- Current final review package hash.
- Rollback owner reference.
- Rollback chronology reference.

Missing, malformed, stale, mismatched, non-hash, or duplicated rollback metadata must return `BLOCKED`.

PB-1M must not execute rollback, mutate release state, deploy replacement artifacts, or contact external recovery systems.

## Evidence Chronology

PB-1M must verify chronology metadata by reference only.

Chronology must prove deterministic ordering from:

1. PB-1L release-candidate evidence lock.
2. Final release-review intent metadata.
3. Human approval reference.
4. Audit-chain reference.
5. Evidence-chain reference.
6. Rollback reference.
7. Replay metadata reference.
8. PB-1M validation evidence.

Missing, duplicated, reordered, stale, or mismatched chronology metadata must return `BLOCKED`.

## Required Metadata Schema

PB-1M input metadata must include:

- PB-1L final decision reference.
- PB-1L release-candidate lock hash.
- PB-1L evidence hash.
- PB-1L package hash.
- PB-1L decision hash.
- PB-1L audit hash.
- Final release-review intent reference.
- Final release-review evidence reference.
- Human approval reference.
- Approval evidence reference.
- Audit-chain reference.
- Evidence-chain reference.
- Replay metadata reference.
- Rollback plan reference.
- Rollback evidence reference.
- Validation metadata reference.
- Policy version reference.
- Tenant reference.
- Correlation reference.
- Expected final review package hash.
- Expected evidence hash.
- Expected package hash.
- Safety flags explicitly set to false.

All hash references must use canonical `sha256:<64 lowercase hex>` values.

## Deterministic Requirements

PB-1M must:

- Use canonical serialization.
- Sort metadata deterministically.
- Sort reason codes deterministically.
- Deduplicate reason codes deterministically.
- Emit identical output for identical input.
- Produce hash-only evidence.
- Preserve redacted metadata only.
- Preserve all execution flags as false.

PB-1M must not use wall-clock time, random values, generated UUIDs, environment-derived values, network state, filesystem mutation state, provider responses, or subprocess output as decision inputs.

## Fail-Closed Behavior

PB-1M must return `BLOCKED` for every unknown, missing, malformed, stale, unsupported, inconsistent, sensitive, execution-shaped, replayed, duplicated, or unverifiable input.

PB-1M must also return `BLOCKED` when:

- PB-1L metadata is missing.
- PB-1L final decision is `BLOCKED`.
- PB-1L final decision is unknown.
- PB-1L release-candidate lock hash is missing.
- PB-1L evidence hash is missing.
- PB-1L package hash is missing.
- PB-1L decision hash is missing.
- PB-1L audit hash is missing.
- Final release-review reference is missing.
- Final release-review evidence is missing.
- Human approval reference is missing.
- Approval evidence is missing.
- Audit chain reference is missing.
- Evidence chain reference is missing.
- Replay metadata is missing.
- Rollback reference is missing.
- Rollback evidence is missing.
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

## Implementation Boundary

PB-1M implementation must be isolated to the exact files listed below. The implementation boundary is mandatory and fail-closed.

## Allowed Implementation Files

PB-1M implementation will be allowed to create only:

1. `docs/runtime/PB_1M_GOVERNANCE_FINAL_RELEASE_REVIEW_PACKAGE.md`
2. `governance/evidence/pb_1m_governance_final_release_review_package.json`
3. `runtime/computer_use/pb_1m_governance_final_release_review_package.py`
4. `tests/test_pb_1m_governance_final_release_review_package.py`

PB-1M implementation must not modify PB-1B through PB-1L files unless a later approved specification explicitly changes this boundary.

## Blocked Files

PB-1M must not modify:

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
- PB-1L implementation files.
- Gateway runtime files.
- Policy evaluation files.
- Provider execution files.
- Deployment files.
- CI workflow files.
- Dependency files.
- Secrets, credentials, key material, or environment configuration.
- Any file outside the exact PB-1M implementation boundary.

## Required Focused Tests

PB-1M implementation must include focused tests for:

- Valid final release-review package.
- Valid package with governed restrictions.
- Missing PB-1L metadata.
- Invalid PB-1L decision.
- Missing PB-1L hashes.
- Missing final review reference.
- Missing final review evidence.
- Missing approval reference.
- Invalid approval reference.
- Missing approval evidence.
- Missing audit chain.
- Audit hash mismatch.
- Missing evidence chain.
- Evidence hash mismatch.
- Missing replay metadata.
- Missing rollback reference.
- Missing rollback evidence.
- Duplicate approval metadata.
- Duplicate final-review metadata.
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

PB-1M implementation must run and keep passing:

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
- PB-1L regression tests.
- Relevant governance regression tests.
- Relevant evidence/hash regression tests.
- JSON validation for PB-1M evidence.
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

PB-1M implementation succeeds only when:

- The implementation follows this specification exactly.
- The changed-file boundary is exact.
- PB-1L metadata validates by hash/reference only.
- Final release-review metadata validates by hash/reference only.
- Human approval metadata validates by external reference only.
- Audit, evidence, replay, rollback, validation, tenant, policy, and correlation metadata validate.
- Evidence chronology validates.
- Outputs are deterministic.
- Outputs are hash-only and redacted.
- All execution safety flags remain false.
- PB-1B through PB-1L regressions pass.
- Security scans pass.
- Human reviewers approve the PR.

## Rollback Criteria

PB-1M rollback must be isolated to the PB-1M implementation commit.

Rollback impact:

- Removes final release-review package metadata.
- Does not remove PB-1B through PB-1L controls.
- Does not authorize execution.
- Does not affect production activation.
- Does not change gateway behavior.
- Does not alter provider behavior.
- Does not weaken audit lineage.

## Future Dependencies

PB-1M does not implement:

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

PB-1M must not:

- Weaken PB-1B through PB-1L.
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

PB-1M must preserve deterministic governance, fail-closed execution, audit evidence, replay safety, rollback traceability, the approval chain, and metadata-only governance.
