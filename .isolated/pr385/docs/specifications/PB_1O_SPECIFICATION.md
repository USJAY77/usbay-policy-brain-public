# PB-1O

## Canonical Capability Name

`PB-1O Governance Release Authority Review Dossier`

PB-1O SHALL NOT authorize runtime execution.

## Purpose

PB-1O defines the metadata-only capability that follows the merged PB-1N implementation. It verifies that PB-1N release authorization readiness handoff output, release authority review metadata, approval references, audit references, replay references, rollback references, evidence references, validation metadata, and evidence chronology can be assembled into a deterministic release authority review dossier for human governance review.

PB-1O does not approve a release, authorize runtime execution, deploy software, call providers, activate production, mutate policy, mutate runtime state, execute rollback, or replace the gateway. It prepares a hash-only dossier proving that required governance references are complete before any later human release authority process may inspect them.

## Governance Objective

PB-1O must preserve USBAY as an execution control layer by ensuring release authority review metadata is complete, deterministic, redacted, approval-driven, audit-linked, replay-safe, rollback-aware, chronology-linked, and fail-closed.

PB-1O verifies release authority review dossier metadata only. It must not interpret dossier completion as execution permission, deployment approval, provider readiness, production readiness, legal certification, compliance certification, or release approval.

## Architecture

PB-1O is a standalone metadata evaluator with four future implementation artifacts:

- Runtime-facing metadata validator.
- Hash-only evidence schema.
- Focused regression tests.
- Runtime governance documentation.

The validator consumes supplied PB-1N references and release authority review metadata by hash/reference only. It computes deterministic hashes using canonical, sorted, redacted metadata. It emits only status metadata and deterministic reason codes.

No external service is contacted. No provider, network, subprocess, deployment, timestamp authority, signing authority, WORM system, object-lock system, regulator transport, or production runtime is invoked.

## Execution Boundary

PB-1O may:

- Validate supplied metadata.
- Validate hash-only references.
- Validate PB-1N release authorization readiness handoff references.
- Validate release authority review metadata references.
- Validate human approval, audit, replay, rollback, evidence, and chronology metadata by reference only.
- Compute deterministic hashes from redacted metadata.
- Return `READY`, `READY_WITH_RESTRICTIONS`, or `BLOCKED`.

PB-1O must not:

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

- PB-1N final decision reference.
- PB-1N release authorization readiness handoff hash.
- PB-1N evidence hash.
- PB-1N package hash.
- PB-1N decision hash.
- PB-1N audit hash.
- Release authority review intent reference.
- Release authority review evidence hash.
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
- Expected release authority review dossier hash.
- Expected evidence hash.
- Expected package hash.
- Safety flags explicitly set to false.

All evidence, audit, decision, approval, replay, rollback, tenant, policy, release-authority, and correlation references must be hash-only or immutable external references.

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

## Deterministic Outputs

PB-1O may output only:

- Final decision.
- Deterministic reason codes.
- Release authority review dossier hash.
- Evidence hash.
- Package hash.
- Decision hash.
- Redacted metadata.
- Execution safety flags set to false.

PB-1O must not output:

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

PB-1O may emit only:

- `READY`
- `READY_WITH_RESTRICTIONS`
- `BLOCKED`

`READY` means all required release authority review dossier metadata validates, PB-1N is not blocked, human approval reference metadata is present, rollback references are present, replay protection metadata is valid, evidence chronology is consistent, and every execution safety flag remains false.

`READY_WITH_RESTRICTIONS` means required metadata validates and explicit governed restriction metadata is present by reference only.

`BLOCKED` means at least one required governance condition is absent, malformed, mismatched, stale, duplicated, unsupported, sensitive, execution-shaped, replayed, or unverifiable.

No PB-1O decision authorizes execution.

## Canonical Reason Codes

PB-1O implementation must emit deterministic reason codes. Required reason-code categories include:

- `PB_1N_METADATA_MISSING`
- `INVALID_PB_1N_DECISION`
- `PB_1N_RELEASE_AUTHORIZATION_READINESS_HANDOFF_HASH_MISSING`
- `PB_1N_EVIDENCE_HASH_MISSING`
- `PB_1N_PACKAGE_HASH_MISSING`
- `PB_1N_DECISION_HASH_MISSING`
- `PB_1N_AUDIT_HASH_MISSING`
- `RELEASE_AUTHORITY_REVIEW_REFERENCE_MISSING`
- `RELEASE_AUTHORITY_REVIEW_EVIDENCE_MISSING`
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
- `DUPLICATE_AUTHORITY_REVIEW_METADATA`
- `DUPLICATE_APPROVAL_METADATA`
- `DUPLICATE_PACKAGE_METADATA`
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
- `RELEASE_AUTHORITY_REVIEW_DOSSIER_HASH_MISMATCH`
- `PACKAGE_HASH_MISMATCH`
- `EXECUTION_FLAG_NOT_FALSE`
- `EXECUTION_SURFACE_REJECTED`
- `SENSITIVE_DATA_REJECTED`
- `CREDENTIAL_LITERAL_REJECTED`
- `MALFORMED_PB_1O_METADATA`
- `INTERNAL_ERROR`

Reason codes must be stable, sorted, deduplicated, and non-sensitive.

## Approval References

PB-1O requires an external human approval reference before returning `READY` or `READY_WITH_RESTRICTIONS`.

Approval references must bind, by hash or immutable reference:

- PB-1O capability name.
- PB-1N decision hash.
- PB-1N package hash.
- PB-1N release authorization readiness handoff hash.
- Release authority review intent reference.
- Release authority review evidence hash.
- Rollback evidence reference.
- Policy version reference.
- Tenant reference.
- Correlation reference.
- Replay metadata reference.
- Chronology metadata.

PB-1O must not inspect, serialize, summarize, or expose approval contents.

## Audit References

PB-1O must validate audit metadata by reference only.

Required audit references:

- PB-1N audit hash.
- PB-1O validation audit hash.
- Previous audit hash.
- Current audit hash.
- Expected current audit hash.
- Approval audit reference.
- Release authority review audit reference.
- Correlation reference.
- Policy version reference.
- Tenant reference.

Missing, malformed, reordered, stale, duplicate, or mismatched audit metadata must return `BLOCKED`.

## Replay References

PB-1O must validate replay metadata by reference only.

Replay metadata must include:

- Nonce reference.
- Timestamp or chronology reference.
- Previous package hash.
- Current package hash.
- Replay window metadata.
- Duplicate approval detection metadata.
- Duplicate authority-review detection metadata.
- Duplicate package detection metadata.

Missing, stale, duplicated, reordered, expired, or mismatched replay metadata must return `BLOCKED`.

PB-1O must not generate live nonces, contact timestamp authorities, call external verifiers, or store mutable replay state.

## Rollback References

PB-1O must validate rollback metadata by reference only.

Rollback references must include:

- Rollback plan reference.
- Rollback evidence reference.
- Previous release authority review dossier hash.
- Current release authority review dossier hash.
- Rollback owner reference.
- Rollback chronology reference.

Missing, malformed, stale, mismatched, non-hash, or duplicated rollback metadata must return `BLOCKED`.

PB-1O must not execute rollback, mutate release state, deploy replacement artifacts, or contact external recovery systems.

## Evidence References

PB-1O evidence must be hash-only and redacted. Required evidence references:

- PB-1N release authorization readiness handoff reference.
- PB-1N evidence reference.
- PB-1N audit reference.
- Release authority review evidence reference.
- Approval evidence reference.
- Audit-chain reference.
- Evidence-chain reference.
- Replay evidence reference.
- Rollback evidence reference.
- Validation evidence reference.

No raw evidence payload, approval content, provider response, credential, secret, or sensitive personal data may be serialized.

## Metadata Schema

PB-1O input metadata must include:

- PB-1N final decision reference.
- PB-1N release authorization readiness handoff hash.
- PB-1N evidence hash.
- PB-1N package hash.
- PB-1N decision hash.
- PB-1N audit hash.
- Release authority review intent reference.
- Release authority review evidence reference.
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
- Expected release authority review dossier hash.
- Expected evidence hash.
- Expected package hash.
- Safety flags explicitly set to false.

All hash references must use canonical `sha256:<64 lowercase hex>` values.

## Deterministic Requirements

PB-1O must:

- Use canonical serialization.
- Sort metadata deterministically.
- Sort reason codes deterministically.
- Deduplicate reason codes deterministically.
- Emit identical output for identical input.
- Produce hash-only evidence.
- Preserve redacted metadata only.
- Preserve all execution flags as false.

PB-1O must not use wall-clock time, random values, generated UUIDs, environment-derived values, network state, filesystem mutation state, provider responses, or subprocess output as decision inputs.

## Fail-Closed Behavior

PB-1O must return `BLOCKED` for every unknown, missing, malformed, stale, unsupported, inconsistent, sensitive, execution-shaped, replayed, duplicated, or unverifiable input.

PB-1O must also return `BLOCKED` when:

- PB-1N metadata is missing.
- PB-1N final decision is `BLOCKED`.
- PB-1N final decision is unknown.
- PB-1N release authorization readiness handoff hash is missing.
- PB-1N evidence hash is missing.
- PB-1N package hash is missing.
- PB-1N decision hash is missing.
- PB-1N audit hash is missing.
- Release authority review reference is missing.
- Release authority review evidence is missing.
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

## Allowed Future Implementation Files

PB-1O implementation will be allowed to create only:

1. `docs/runtime/PB_1O_GOVERNANCE_RELEASE_AUTHORITY_REVIEW_DOSSIER.md`
2. `governance/evidence/pb_1o_governance_release_authority_review_dossier.json`
3. `runtime/computer_use/pb_1o_governance_release_authority_review_dossier.py`
4. `tests/test_pb_1o_governance_release_authority_review_dossier.py`

PB-1O implementation must not modify PB-1B through PB-1N files unless a later approved specification explicitly changes this boundary.

## Forbidden Files

PB-1O must not modify:

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
- PB-1M implementation files.
- PB-1N implementation files.
- PB-1O specification file.
- Gateway runtime files.
- Policy evaluation files.
- Provider execution files.
- Deployment files.
- CI workflow files.
- Dependency files.
- Security configuration files.
- Secrets, credentials, key material, or environment configuration.
- Any file outside the exact PB-1O implementation boundary.

## Required Focused Tests

PB-1O implementation must include focused tests for:

- Valid release authority review dossier.
- Valid dossier with governed restrictions.
- Missing PB-1N metadata.
- Invalid PB-1N decision.
- Missing PB-1N hashes.
- Missing release authority review reference.
- Missing release authority review evidence.
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
- Duplicate authority-review metadata.
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

## Required Regression Groups

PB-1O implementation must run and keep passing:

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
- PB-1M regression tests.
- PB-1N regression tests.
- Relevant governance regression tests.
- Relevant evidence/hash regression tests.
- JSON validation for PB-1O evidence.
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

PB-1O implementation succeeds only when:

- The implementation follows this specification exactly.
- The changed-file boundary is exact.
- PB-1N metadata validates by hash/reference only.
- Release authority review dossier metadata validates by hash/reference only.
- Human approval metadata validates by external reference only.
- Audit, evidence, replay, rollback, validation, tenant, policy, and correlation metadata validate.
- Evidence chronology validates.
- Outputs are deterministic.
- Outputs are hash-only and redacted.
- All execution safety flags remain false.
- PB-1B through PB-1N regressions pass.
- Security scans pass.
- Human reviewers approve the PR.

## Rollback Criteria

PB-1O rollback must be isolated to the PB-1O implementation commit.

Rollback impact:

- Removes release authority review dossier metadata.
- Does not remove PB-1B through PB-1N controls.
- Does not authorize execution.
- Does not affect production activation.
- Does not change gateway behavior.
- Does not alter provider behavior.
- Does not weaken audit lineage.

## Future Dependencies

PB-1O does not implement:

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

PB-1O must not:

- Weaken PB-1B through PB-1N.
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

PB-1O must preserve deterministic governance, fail-closed execution, audit evidence, replay safety, rollback traceability, the approval chain, and metadata-only governance.
