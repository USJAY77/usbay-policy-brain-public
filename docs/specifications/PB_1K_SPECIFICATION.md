# PB-1K

## Canonical Capability Name

`PB-1K Governance Release Approval Evidence Closure`

PB-1K SHALL NOT authorize runtime execution.

## Purpose

PB-1K defines the metadata-only capability that follows the merged PB-1J implementation. It verifies that PB-1J release-readiness contract output, human approval references, audit evidence, replay metadata, rollback evidence, and validation evidence can be closed into a deterministic governance approval evidence package for human review.

PB-1K does not approve a release, deploy software, call providers, activate production, mutate runtime state, or replace the gateway. It prepares a hash-only closure package proving the governance evidence required for a future approval decision is complete and fail-closed.

## Governance Objective

PB-1K must preserve USBAY as an execution control layer by ensuring approval evidence is complete, deterministic, redacted, replay-safe, auditable, and human-reviewable before any later release authorization process may inspect it.

PB-1K verifies evidence closure only. It must not interpret evidence closure as execution permission, production readiness, provider readiness, deployment approval, legal certification, or compliance certification.

## Architecture

PB-1K is a standalone metadata evaluator with four implementation artifacts:

- Runtime-facing metadata validator.
- Hash-only evidence schema.
- Focused regression tests.
- Runtime governance documentation.

The validator consumes supplied PB-1J references and approval-evidence metadata by hash/reference only. It computes deterministic hashes using canonical, sorted, redacted metadata. It emits only status metadata and deterministic reason codes.

No external service is contacted. No provider, network, subprocess, deployment, timestamp authority, signing authority, WORM system, object-lock system, regulator transport, or production runtime is invoked.

## Execution Boundary

PB-1K may:

- Validate supplied metadata.
- Validate hash-only references.
- Validate human approval references by external reference only.
- Validate audit, replay, rollback, and evidence chronology metadata.
- Compute deterministic hashes from redacted metadata.
- Return `READY`, `READY_WITH_RESTRICTIONS`, or `BLOCKED`.

PB-1K must not:

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

## Allowed Inputs

Allowed inputs:

- PB-1J final decision reference.
- PB-1J contract hash.
- PB-1J evidence hash.
- PB-1J package hash.
- PB-1J decision hash.
- PB-1J audit hash.
- Human approval reference.
- Approval evidence hash.
- Approval chronology reference.
- Audit-chain reference.
- Evidence-chain reference.
- Replay metadata reference.
- Rollback evidence reference.
- Validation evidence references.
- Policy version reference.
- Tenant reference.
- Correlation reference.
- Expected approval-closure hash.
- Expected evidence hash.
- Expected package hash.
- Safety flags explicitly set to false.

All evidence, audit, decision, approval, replay, rollback, tenant, policy, and correlation references must be hash-only or immutable external references.

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

PB-1K may emit only:

- `READY`
- `READY_WITH_RESTRICTIONS`
- `BLOCKED`

`READY` means all required approval-evidence closure metadata validates, PB-1J is not blocked, human approval reference metadata is present, replay protection metadata is valid, and every execution safety flag remains false.

`READY_WITH_RESTRICTIONS` means required metadata validates and explicit governed restriction metadata is present by reference only.

`BLOCKED` means at least one required governance condition is absent, malformed, mismatched, stale, duplicated, unsupported, sensitive, execution-shaped, replayed, or unverifiable.

No PB-1K decision authorizes execution.

## Reason Codes

PB-1K implementation must emit deterministic reason codes. Required reason-code categories include:

- `PB_1J_METADATA_MISSING`
- `INVALID_PB_1J_DECISION`
- `PB_1J_CONTRACT_HASH_MISSING`
- `PB_1J_EVIDENCE_HASH_MISSING`
- `PB_1J_PACKAGE_HASH_MISSING`
- `PB_1J_DECISION_HASH_MISSING`
- `PB_1J_AUDIT_HASH_MISSING`
- `APPROVAL_REFERENCE_MISSING`
- `APPROVAL_EVIDENCE_MISSING`
- `APPROVAL_INVALID`
- `AUDIT_CHAIN_MISSING`
- `AUDIT_HASH_MISMATCH`
- `EVIDENCE_CHAIN_MISSING`
- `EVIDENCE_HASH_MISMATCH`
- `REPLAY_METADATA_MISSING`
- `DUPLICATE_APPROVAL_METADATA`
- `ROLLBACK_EVIDENCE_MISSING`
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
- `APPROVAL_CLOSURE_HASH_MISMATCH`
- `PACKAGE_HASH_MISMATCH`
- `EXECUTION_FLAG_NOT_FALSE`
- `EXECUTION_SURFACE_REJECTED`
- `SENSITIVE_DATA_REJECTED`
- `CREDENTIAL_LITERAL_REJECTED`
- `MALFORMED_PB_1K_METADATA`
- `INTERNAL_ERROR`

Reason codes must be stable, sorted, deduplicated, and non-sensitive.

## Required Evidence

PB-1K evidence must be hash-only and redacted. Required evidence references:

- PB-1J evidence reference.
- PB-1J audit reference.
- Approval evidence reference.
- Human approval reference.
- Audit-chain evidence reference.
- Evidence-chain reference.
- Replay metadata evidence reference.
- Rollback evidence reference.
- Validation evidence reference.
- Boundary verification evidence reference.
- Sensitive-data scan evidence reference.
- Execution-surface scan evidence reference.

Evidence must never include raw payloads, prompts, provider responses, credentials, approval contents, tokens, cookies, private keys, personal data, environment dumps, runtime artifacts, or secret values.

## Required Approval References

PB-1K requires an external human approval reference before returning `READY` or `READY_WITH_RESTRICTIONS`.

Approval references must bind, by hash or immutable reference:

- PB-1K capability name.
- PB-1J decision hash.
- PB-1J package hash.
- Approval evidence hash.
- Policy version reference.
- Tenant reference.
- Correlation reference.
- Replay metadata reference.
- Rollback evidence reference.
- Chronology metadata.

PB-1K must not inspect, serialize, summarize, or expose approval contents.

## Required Audit References

PB-1K must validate audit metadata by reference only.

Required audit references:

- PB-1J audit hash.
- PB-1K validation audit hash.
- Previous audit hash.
- Current audit hash.
- Expected current audit hash.
- Approval audit reference.
- Correlation reference.
- Policy version reference.
- Tenant reference.

Missing, malformed, reordered, stale, duplicate, or mismatched audit metadata must return `BLOCKED`.

## Replay Protection

PB-1K must validate replay metadata by reference only.

Replay metadata must include:

- Nonce reference.
- Timestamp or chronology reference.
- Previous package hash.
- Current package hash.
- Replay window metadata.
- Duplicate approval detection metadata.
- Duplicate package detection metadata.

Missing, stale, duplicated, reordered, expired, or mismatched replay metadata must return `BLOCKED`.

PB-1K must not generate live nonces, contact timestamp authorities, call external verifiers, or store mutable replay state.

## Deterministic Requirements

PB-1K must:

- Use canonical serialization.
- Sort metadata deterministically.
- Sort reason codes deterministically.
- Deduplicate reason codes deterministically.
- Emit identical output for identical input.
- Produce hash-only evidence.
- Preserve redacted metadata only.
- Preserve all execution flags as false.

PB-1K must not use wall-clock time, random values, generated UUIDs, environment-derived values, network state, filesystem mutation state, provider responses, or subprocess output as decision inputs.

## Fail-Closed Behavior

PB-1K must return `BLOCKED` for every unknown, missing, malformed, stale, unsupported, inconsistent, sensitive, execution-shaped, replayed, duplicated, or unverifiable input.

PB-1K must also return `BLOCKED` when:

- PB-1J metadata is missing.
- PB-1J final decision is `BLOCKED`.
- PB-1J final decision is unknown.
- PB-1J contract hash is missing.
- PB-1J evidence hash is missing.
- PB-1J package hash is missing.
- PB-1J decision hash is missing.
- PB-1J audit hash is missing.
- Human approval reference is missing.
- Approval evidence is missing.
- Audit chain reference is missing.
- Evidence chain reference is missing.
- Replay metadata is missing.
- Rollback evidence is missing.
- Validation metadata is missing.
- Policy version reference is missing.
- Tenant reference is missing.
- Correlation reference is missing.
- Any expected hash mismatches the computed hash.
- Any safety flag is not false.
- Any direct execution request is present.
- Any provider, deployment, production, network, subprocess, credential, secret, policy mutation, or runtime mutation surface is present.
- Any exception occurs during validation.

## Implementation Boundary

PB-1K implementation must be isolated to the exact files listed below. The implementation boundary is mandatory and fail-closed.

## Exact Implementation Files

PB-1K implementation will be allowed to create only:

1. `docs/runtime/PB_1K_GOVERNANCE_RELEASE_APPROVAL_EVIDENCE_CLOSURE.md`
2. `governance/evidence/pb_1k_governance_release_approval_evidence_closure.json`
3. `runtime/computer_use/pb_1k_governance_release_approval_evidence_closure.py`
4. `tests/test_pb_1k_governance_release_approval_evidence_closure.py`

PB-1K implementation must not modify PB-1B through PB-1J files unless a later approved specification explicitly changes this boundary.

## Blocked Implementation Files

PB-1K must not modify:

- PB-1B implementation files.
- PB-1C implementation files.
- PB-1D implementation files.
- PB-1E implementation files.
- PB-1F implementation files.
- PB-1G implementation files.
- PB-1H implementation files.
- PB-1I implementation files.
- PB-1J implementation files.
- Gateway runtime files.
- Policy evaluation files.
- Provider execution files.
- Deployment files.
- CI workflow files.
- Dependency files.
- Secrets, credentials, key material, or environment configuration.
- Any file outside the exact PB-1K implementation boundary.

## Required Focused Tests

PB-1K implementation must include focused tests for:

- Valid approval evidence closure.
- Valid closure with governed restrictions.
- Missing PB-1J metadata.
- Invalid PB-1J decision.
- Missing PB-1J hashes.
- Missing approval reference.
- Invalid approval reference.
- Missing approval evidence.
- Missing audit chain.
- Audit hash mismatch.
- Missing evidence chain.
- Evidence hash mismatch.
- Missing replay metadata.
- Duplicate approval metadata.
- Duplicate package metadata.
- Missing rollback evidence.
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

PB-1K implementation must run and keep passing:

- PB-1B regression tests.
- PB-1C regression tests.
- PB-1D regression tests.
- PB-1E regression tests.
- PB-1F regression tests.
- PB-1G regression tests.
- PB-1H regression tests.
- PB-1I regression tests.
- PB-1J regression tests.
- Relevant governance regression tests.
- Relevant evidence/hash regression tests.
- JSON validation for PB-1K evidence.
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

PB-1K implementation succeeds only when:

- The implementation follows this specification exactly.
- The changed-file boundary is exact.
- PB-1J metadata validates by hash/reference only.
- Human approval metadata validates by external reference only.
- Audit, evidence, replay, rollback, validation, tenant, policy, and correlation metadata validate.
- Outputs are deterministic.
- Outputs are hash-only and redacted.
- All execution safety flags remain false.
- PB-1B through PB-1J regressions pass.
- Security scans pass.
- Human reviewers approve the PR.

## Rollback Requirements

PB-1K rollback must be isolated to the PB-1K implementation commit.

Rollback impact:

- Removes approval evidence closure verification metadata.
- Does not remove PB-1B through PB-1J controls.
- Does not authorize execution.
- Does not affect production activation.
- Does not change gateway behavior.
- Does not alter provider behavior.
- Does not weaken audit lineage.

## Future Dependencies

PB-1K does not implement:

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

PB-1K must not:

- Weaken PB-1B through PB-1J.
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

PB-1K must preserve deterministic governance, fail-closed execution, audit evidence, replay safety, the approval chain, and metadata-only governance.
