# PB-1J

## Purpose

Canonical capability name: `PB-1J Governance Chain Release Readiness Contract`.

PB-1J defines the next metadata-only governance capability after PB-1I. It verifies that the completed PB-1B through PB-1I execution-control chain can be treated as a reviewed release-readiness contract for later governance planning without authorizing runtime execution, provider execution, deployment, production activation, or policy mutation.

PB-1J is a contract-verification layer only. It does not replace PB-1B runtime enforcement, PB-1I chain closure verification, the gateway, human review, or production release controls.

PB-1J does not authorize execution.

## Problem Statement

PB-1I proves the PB-1B through PB-1H chain is complete, ordered, hash-linked, reviewed, and traceable. A remaining governance gap exists before later work may rely on that closed chain as a release-readiness baseline: no dedicated contract confirms that PB-1I output, release-intent metadata, human approval references, audit evidence, regression evidence, and rollback evidence align as one deterministic non-executing readiness package.

Without PB-1J, later phases could confuse chain closure with release authorization, rely on stale regression evidence, omit rollback metadata, or treat metadata readiness as permission to activate runtime or production behavior. PB-1J closes that gap by validating release-readiness contract metadata only.

## Governance Objective

PB-1J must preserve USBAY as an execution control layer by proving that release-readiness metadata is complete, deterministic, redacted, approval-driven, and fail-closed.

The objective is not to release software. The objective is to verify that a later human-reviewed release process has enough hash-only governance metadata to begin without weakening PB-1B through PB-1I.

## Architecture

PB-1J is a standalone metadata evaluator with four artifacts:

- A runtime-facing metadata validator.
- A hash-only evidence schema.
- Focused regression tests.
- Runtime governance documentation.

The evaluator consumes PB-1I chain-closure output and release-readiness metadata by reference only. It computes deterministic hashes over canonical, sorted, redacted metadata. It emits only governance status metadata.

The gateway remains authoritative for runtime enforcement. PB-1J does not call the gateway, providers, networks, subprocesses, deployment systems, signing systems, WORM systems, timestamp authorities, or production services.

## Execution Boundaries

PB-1J may validate supplied metadata.

PB-1J may compute deterministic hashes.

PB-1J may return `READY`, `READY_WITH_RESTRICTIONS`, or `BLOCKED`.

PB-1J must not execute runtime actions.

PB-1J must not execute runtime actions, provider actions, deployment actions, network actions, subprocess actions, background workers, asynchronous workers, external signing, RFC3161 timestamping, WORM persistence, object-lock persistence, regulator submission, or production activation.

PB-1J metadata must never be interpreted as deployment approval, runtime authorization, provider readiness, production readiness, legal certification, compliance certification, or release approval.

## Allowed Implementation Files

PB-1J implementation will be allowed to create only:

1. `docs/runtime/PB_1J_GOVERNANCE_CHAIN_RELEASE_READINESS_CONTRACT.md`
2. `governance/evidence/pb_1j_governance_chain_release_readiness_contract.json`
3. `runtime/computer_use/pb_1j_governance_chain_release_readiness_contract.py`
4. `tests/test_pb_1j_governance_chain_release_readiness_contract.py`

PB-1J implementation must not modify PB-1B through PB-1I files unless a later approved specification explicitly changes this boundary.

## Blocked Files

PB-1J must not modify:

- PB-1B implementation files.
- PB-1C implementation files.
- PB-1D implementation files.
- PB-1E implementation files.
- PB-1F implementation files.
- PB-1G implementation files.
- PB-1H implementation files.
- PB-1I implementation files.
- Gateway runtime files.
- Policy evaluation files.
- Provider execution files.
- Deployment files.
- CI workflow files.
- Dependency files.
- Secrets, credentials, key material, or environment configuration.
- Any file outside the allowed PB-1J implementation boundary.

## Required Metadata

PB-1J input metadata must include:

- PB-1I decision reference.
- PB-1I chain hash.
- PB-1I evidence hash.
- PB-1I package hash.
- PB-1I decision hash.
- PB-1B through PB-1I stage references.
- Policy version reference.
- Release intent reference.
- Regression evidence reference.
- Rollback evidence reference.
- Human approval reference.
- Audit chain reference.
- Evidence chain reference.
- Chronology marker.
- Expected release-readiness contract hash.
- Expected evidence hash.
- Expected package hash.
- Safety flags explicitly set to false.

All hash references must use canonical `sha256:<64 lowercase hex>` values.

## Required Evidence

PB-1J evidence must be hash-only and redacted. Required evidence references:

- PB-1I evidence reference.
- Regression test evidence reference.
- Governance regression evidence reference.
- Approval evidence reference.
- Audit-chain evidence reference.
- Rollback evidence reference.
- Boundary verification evidence reference.
- Sensitive-data scan evidence reference.
- Execution-surface scan evidence reference.

Evidence must never include raw payloads, prompts, provider responses, approval contents, credentials, tokens, cookies, private keys, personal data, environment dumps, runtime artifacts, or secret values.

## Required Approval Chain

PB-1J must require an external human approval reference before returning `READY` or `READY_WITH_RESTRICTIONS`.

The approval reference must bind, by hash or immutable reference:

- PB-1J capability name.
- PB-1I decision hash.
- Policy version reference.
- Release intent reference.
- Regression evidence reference.
- Rollback evidence reference.
- Timestamp or chronology metadata.

PB-1J must not inspect or serialize approval contents. Approval metadata remains a prerequisite for governance review, not permission for provider execution, runtime execution, deployment, production activation, or policy mutation.

## Required Audit Chain

PB-1J must validate audit-chain metadata by reference only.

The audit chain must include:

- PB-1I audit reference.
- PB-1J validation audit reference.
- Previous audit hash.
- Current audit hash.
- Correlation reference.
- Policy version reference.
- Human approval reference.

Missing, malformed, reordered, stale, duplicate, or mismatched audit metadata must return `BLOCKED`.

## Replay Protection

PB-1J must validate replay metadata by reference only.

Replay protection must include:

- Nonce reference.
- Timestamp or chronology reference.
- Previous package hash.
- Current package hash.
- Replay window metadata.
- Duplicate package detection metadata.

Missing, stale, duplicated, reordered, or mismatched replay metadata must return `BLOCKED`.

PB-1J must not generate live nonces, contact timestamp authorities, call external verifiers, or store mutable replay state.

## Fail-Closed Behaviour

PB-1J must return `BLOCKED` for every unknown, missing, malformed, stale, unsupported, inconsistent, sensitive, execution-shaped, or unverifiable input.

PB-1J must also return `BLOCKED` when:

- PB-1I metadata is missing.
- PB-1I final decision is `BLOCKED`.
- PB-1I final decision is unknown.
- PB-1I hash continuity is missing.
- PB-1I evidence hash is missing.
- PB-1I audit hash is missing.
- PB-1I decision hash is missing.
- Release intent metadata is missing.
- Human approval reference is missing.
- Audit chain reference is missing.
- Evidence chain reference is missing.
- Regression evidence reference is missing.
- Rollback evidence reference is missing.
- Replay metadata is missing.
- Any expected hash mismatches the computed hash.
- Any safety flag is not false.
- Any direct execution request is present.
- Any provider, deployment, production, network, subprocess, credential, secret, or runtime mutation surface is present.
- Any exception occurs during validation.

## Decision Semantics

PB-1J may emit only:

- `READY`
- `READY_WITH_RESTRICTIONS`
- `BLOCKED`

`READY` means all required release-readiness contract metadata validates and all execution safety flags remain false.

`READY_WITH_RESTRICTIONS` means required metadata validates, PB-1I is not blocked, and explicit governed restriction metadata is present by reference only.

`BLOCKED` means at least one required governance condition is absent, malformed, mismatched, stale, unsupported, unsafe, execution-shaped, sensitive, or unverifiable.

No PB-1J output authorizes execution.

## Expected Outputs

Allowed outputs:

- Final decision.
- Deterministic reason codes.
- Release-readiness contract hash.
- Evidence hash.
- Package hash.
- Decision hash.
- Redacted metadata.
- Execution safety flags set to false.

Blocked outputs:

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

## Expected Blocked States

PB-1J implementation must include blocked states for:

- Missing PB-1I metadata.
- Invalid PB-1I decision.
- Missing PB-1I chain hash.
- Missing PB-1I evidence hash.
- Missing PB-1I package hash.
- Missing PB-1I decision hash.
- Missing release intent.
- Missing human approval.
- Missing audit chain.
- Missing evidence chain.
- Missing regression evidence.
- Missing rollback evidence.
- Missing replay metadata.
- Hash mismatch.
- Chronology mismatch.
- Duplicate package metadata.
- Stale metadata.
- Unsupported capability metadata.
- Upstream `BLOCKED` propagation.
- Direct execution request.
- Provider execution request.
- Deployment request.
- Production activation request.
- Runtime mutation request.
- Network execution request.
- Subprocess execution request.
- Sensitive data.
- Credential-shaped literals.
- Malformed metadata.
- Internal exception.

## Validation Metadata

PB-1J must require validation metadata for:

- Focused PB-1J tests.
- PB-1B regression.
- PB-1C regression.
- PB-1D regression.
- PB-1E regression.
- PB-1F regression.
- PB-1G regression.
- PB-1H regression.
- PB-1I regression.
- Governance regression.
- JSON validation.
- Python validation.
- Markdown validation.
- Boundary validation.
- Conflict-marker scan.
- Sensitive-data scan.
- Credential scan.
- Execution-surface scan.
- Deterministic-output validation.
- Fail-closed validation.

Validation metadata must be supplied as redacted references and status values only.

## Regression Requirements

PB-1J implementation must run and keep passing:

- PB-1J focused tests for valid metadata, `READY_WITH_RESTRICTIONS`, missing PB-1I metadata, invalid PB-1I decision, missing PB-1I hashes, missing release intent, missing approval, missing audit chain, missing evidence chain, missing regression evidence, missing rollback evidence, missing replay metadata, hash mismatch, chronology mismatch, duplicate package metadata, stale metadata, unsupported capability metadata, upstream `BLOCKED`, direct execution rejection, provider execution rejection, deployment rejection, production activation rejection, runtime mutation rejection, network/subprocess rejection, sensitive-data rejection, credential literal rejection, deterministic output, and redacted evidence.
- PB-1B regression tests.
- PB-1C regression tests.
- PB-1D regression tests.
- PB-1E regression tests.
- PB-1F regression tests.
- PB-1G regression tests.
- PB-1H regression tests.
- PB-1I regression tests.
- Relevant governance regression tests.
- JSON validation for PB-1J evidence.
- Python syntax and import validation.
- Markdown validation.
- `git diff --check`.
- `git diff --cached --check`.
- Conflict-marker scan.
- Sensitive-data scan.
- Prohibited execution-surface scan.

## Boundary Verification

PB-1J implementation must prove that the changed-file list exactly matches the allowed implementation files.

If any file outside the PB-1J boundary is modified, staged, committed, pushed, or included in the PR, PB-1J must be considered blocked until the boundary is repaired.

## Security Constraints

PB-1J must reject sensitive keys and credential-shaped literals.

PB-1J must never log, serialize, hash in raw form, print, or persist:

- Credentials.
- Tokens.
- Cookies.
- Private keys.
- Secrets.
- Prompts.
- Raw payloads.
- Provider responses.
- Approval contents.
- Personal data.
- Environment dumps.
- Runtime artifacts containing sensitive material.

Hash payloads must be canonical, sorted, deterministic, and redacted.

## Implementation Order

PB-1J implementation must proceed in this order:

1. Re-verify PB-1J specification is merged into `origin/main`.
2. Create the isolated PB-1J implementation branch from current `origin/main`.
3. Create only the allowed PB-1J files.
4. Implement the metadata-only evaluator.
5. Add focused PB-1J tests.
6. Add hash-only evidence schema.
7. Add runtime documentation.
8. Run focused tests and validations.
9. Run PB-1B through PB-1I regressions.
10. Verify boundary and security scans.
11. Commit only the PB-1J boundary after validation.
12. Push and open a PR for human review.

## Rollback Strategy

PB-1J rollback must be isolated to the PB-1J implementation commit.

Rollback impact:

- Removes release-readiness contract verification metadata.
- Does not remove PB-1B through PB-1I controls.
- Does not authorize execution.
- Does not affect production activation.
- Does not change gateway behavior.
- Does not alter provider behavior.
- Does not weaken audit lineage.

## Success Criteria

PB-1J implementation succeeds only when:

- The implementation follows this specification exactly.
- The changed-file boundary is exact.
- PB-1I metadata validates by hash/reference only.
- Release intent metadata validates by hash/reference only.
- Human approval metadata validates by external reference only.
- Audit, evidence, regression, rollback, and replay metadata validate.
- Outputs are deterministic.
- Outputs are hash-only and redacted.
- All execution safety flags remain false.
- PB-1B through PB-1I regressions pass.
- Security scans pass.
- Human reviewers approve the PR.

## Future Dependencies

PB-1J does not implement:

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

## Explicitly Prohibited Behaviour

PB-1J must not:

- Weaken PB-1B through PB-1I.
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

PB-1J must preserve deterministic governance, fail-closed execution, audit evidence, replay safety, the approval chain, and metadata-only governance.
