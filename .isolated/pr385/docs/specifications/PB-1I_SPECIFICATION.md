# PB-1I

## Purpose

Canonical capability name: `PB-1I Chain Closure Verification`.

PB-1I adds a governed chain-closure verification capability for the PB-1 execution-control program. It verifies that PB-1B through PB-1H are present, ordered, hash-linked, reviewable, and traceable as one complete metadata-only governance chain before any later runtime or production-readiness work may rely on the chain.

PB-1I is not an execution gateway, provider adapter, deployment gate, or production authorization layer. It is a deterministic verification layer that proves the already merged PB-1 controls remain complete and fail closed as a chain.

## Problem Statement

PB-1B through PB-1H add separate fail-closed controls for runtime execution gating, dependency readiness, adapter contracts, evidence export, precommit validation, integrated chain validation, and integrated chain hardening. After those controls are merged, a remaining governance gap exists: no dedicated capability proves that the full PB-1 chain is complete, chronologically consistent, hash-linked, reviewed, and safe to reference as a single execution-control baseline.

Without PB-1I, later phases could accidentally reference an incomplete or stale PB-1 chain, skip one control, rely on unreviewed evidence, or treat metadata readiness as runtime authorization. PB-1I closes that gap by validating chain completeness and traceability only.

## Scope

PB-1I is allowed to create a new metadata-only wrapper capability and its evidence, tests, and documentation.

PB-1I is allowed to validate:

- PB-1B through PB-1H presence.
- PB-1B through PB-1H expected order.
- Required evidence references.
- Required audit references.
- Required merge/review metadata.
- Required human approval metadata.
- Deterministic chain hash continuity.
- Canonical decision and reason propagation.
- Fail-closed status propagation.
- Absence of execution, deployment, provider, network, subprocess, credential, and sensitive-data surfaces.

PB-1I is NOT allowed to modify:

- PB-1B implementation files.
- PB-1C implementation files.
- PB-1D implementation files.
- PB-1E implementation files.
- PB-1F implementation files.
- PB-1G implementation files.
- PB-1H implementation files.
- Gateway runtime behavior.
- Policy evaluation semantics.
- Provider execution logic.
- Deployment logic.
- Production activation controls.
- CI workflows unless a future approved batch explicitly authorizes it.
- Dependency files unless a future approved batch explicitly authorizes it.

## Inputs

Allowed inputs:

- PB-1B through PB-1H metadata records.
- PB-1B through PB-1H evidence hashes.
- PB-1B through PB-1H audit hashes.
- PB-1B through PB-1H decision hashes.
- Merge commit references.
- Pull request references.
- Human approval references.
- Policy version references.
- Chain chronology metadata.
- Expected chain hash.
- Expected evidence hash.
- Redacted validation metadata.

Blocked inputs:

- Raw payloads.
- Prompts.
- Provider responses.
- Credentials.
- Tokens.
- Private keys.
- Secrets.
- Cookies.
- Personal data.
- Environment dumps.
- Runtime artifacts containing sensitive content.
- Commands or direct execution requests.
- Network endpoints intended for live execution.
- Provider identifiers claiming active execution.
- Deployment targets.
- Production activation flags.
- Mutable policy contents.

## Outputs

Allowed outputs:

- `READY`
- `READY_WITH_RESTRICTIONS`
- `BLOCKED`
- Deterministic reason codes.
- Hash-only evidence references.
- Chain hash.
- Evidence hash.
- Package hash.
- Redacted metadata.
- Execution safety flags set to false.

Blocked outputs:

- Execution authorization.
- Provider authorization.
- Deployment authorization.
- Production activation.
- Runtime mutation.
- Raw payload logs.
- Credential material.
- Secret values.
- Human approval contents.
- Provider response contents.
- Network execution results.
- Non-deterministic timestamps unless supplied as metadata and hash-linked.

## Fail-Closed Rules

PB-1I MUST return `BLOCKED` when any of the following is true:

- Missing PB-1B metadata.
- Missing PB-1C metadata.
- Missing PB-1D metadata.
- Missing PB-1E metadata.
- Missing PB-1F metadata.
- Missing PB-1G metadata.
- Missing PB-1H metadata.
- PB-1B through PB-1H chain order is invalid.
- Any required evidence hash is missing.
- Any required audit hash is missing.
- Any required decision hash is missing.
- Any hash is malformed.
- Any expected hash mismatches the computed hash.
- Any merge metadata is missing or inconsistent.
- Any human approval reference is missing where required.
- Any policy version reference is missing.
- Any stage reports `BLOCKED`.
- Any stage reports an unknown decision.
- Any stage reports unsupported capability metadata.
- Any stage reports degraded metadata without explicit governed restriction metadata.
- Any fail-closed propagation flag is missing.
- Any chronology marker is missing, reordered, or inconsistent.
- Any metadata is malformed.
- Any metadata is stale or unverifiable.
- Any direct execution request is present.
- Any provider execution flag is true.
- Any production activation flag is true.
- Any deployment authorization flag is true.
- Any runtime mutation flag is true.
- Any network, subprocess, socket, or provider execution surface is present.
- Any sensitive-data key or credential-shaped literal is present.
- Any exception occurs during validation.

## Human Approval

PB-1I requires human governance review before merge.

PB-1I must preserve existing human approval requirements from PB-1B through PB-1H. If any upstream control requires human approval, PB-1I must verify the presence of an external approval reference and must not inspect or serialize approval contents.

PB-1I must not convert approval metadata into execution authorization. Human approval remains a prerequisite for review and merge, not a permission for provider execution, production activation, deployment, or runtime mutation.

## Evidence

Required audit evidence:

- PB-1B evidence reference.
- PB-1C evidence reference.
- PB-1D evidence reference.
- PB-1E evidence reference.
- PB-1F evidence reference.
- PB-1G evidence reference.
- PB-1H evidence reference.
- PB-1B through PB-1H audit references.
- PB-1B through PB-1H decision references.
- Human approval references.
- Policy version reference.
- Merge commit references.
- Pull request references.
- Deterministic chain hash.
- Deterministic evidence hash.
- Deterministic package hash.

Hash requirements:

- All evidence hashes must use canonical `sha256:<64 lowercase hex>` references.
- Hashes must be computed from canonical, sorted, redacted metadata.
- Raw payloads must never be included in hash payloads.
- Hash continuity must change when tenant, policy version, stage order, decision, evidence reference, audit reference, or approval reference changes.

Metadata:

- Metadata must be deterministic.
- Metadata must be redacted.
- Metadata must be hash-only where evidence or audit material is referenced.
- Metadata must explicitly preserve execution safety flags as false.

Traceability:

- Every PB-1I decision must be traceable to PB-1B through PB-1H references.
- Every `BLOCKED` decision must include deterministic reason codes.
- Every `READY_WITH_RESTRICTIONS` decision must include governed restriction metadata by reference only.

## Required Controls

Mandatory controls:

- Fail-closed default.
- Chain completeness validation.
- Chain order validation.
- Evidence hash validation.
- Audit hash validation.
- Decision hash validation.
- Policy version validation.
- Human approval reference validation.
- Merge metadata validation.
- Pull request reference validation.
- Chronology validation.
- Canonical serialization.
- Deterministic reason ordering.
- Redacted output.
- Sensitive-data rejection.
- Provider execution rejection.
- Production activation rejection.
- Deployment authorization rejection.
- Runtime mutation rejection.
- Network execution rejection.
- Subprocess execution rejection.
- Metadata-only output.

## Acceptance Criteria

Concrete PASS conditions:

- Complete PB-1B through PB-1H metadata validates.
- PB-1B through PB-1H order is canonical.
- All required evidence hashes are present and valid.
- All required audit hashes are present and valid.
- All required decision hashes are present and valid.
- Required human approval references are present.
- Policy version metadata is present.
- Merge and PR references are present.
- Chain hash matches expected hash.
- Evidence hash matches expected hash.
- Outputs are deterministic across repeated runs.
- Outputs are hash-only and redacted.
- All execution safety flags remain false.
- PB-1C through PB-1H regression tests continue passing.

Concrete BLOCK conditions:

- Any missing, malformed, stale, degraded, inconsistent, unsupported, unknown, unverifiable, or sensitive input.
- Any hash mismatch.
- Any missing evidence.
- Any missing audit reference.
- Any missing approval reference.
- Any missing policy version.
- Any invalid chain order.
- Any upstream `BLOCKED` decision.
- Any direct execution, provider, deployment, production, network, subprocess, credential, or runtime mutation surface.

## File Boundary

PB-1I implementation will be allowed to create only:

1. `docs/runtime/PB_1I_CHAIN_CLOSURE_VERIFICATION.md`
2. `governance/evidence/pb_1i_chain_closure_verification.json`
3. `runtime/computer_use/pb_1i_chain_closure_verification.py`
4. `tests/test_pb_1i_chain_closure_verification.py`

PB-1I implementation must not modify PB-1B through PB-1H files unless a later approved specification explicitly changes this boundary.

## Regression Requirements

PB-1I implementation must run and keep passing:

- PB-1I focused tests for complete chain validation, missing stage metadata, invalid stage order, missing evidence hash, missing audit hash, missing decision hash, missing approval reference, missing policy version, hash mismatch, chronology mismatch, stale metadata, unsupported capability metadata, upstream `BLOCKED` propagation, direct execution rejection, sensitive-data rejection, deterministic output, and redacted evidence.
- PB-1C regression tests.
- PB-1D regression tests.
- PB-1E regression tests.
- PB-1F regression tests.
- PB-1G regression tests.
- PB-1H regression tests.
- Relevant governance regression tests.
- JSON validation for PB-1I evidence.
- Python syntax and import validation.
- `git diff --check`.
- Conflict-marker scan.
- Sensitive-data scan.
- Prohibited execution-surface scan.
- Deterministic output tests.
- Fail-closed negative tests.

## Rollback

PB-1I rollback must be isolated to the single PB-1I commit. Reverting PB-1I must not alter PB-1B through PB-1H behavior or evidence.

Rollback impact:

- Removes chain-closure verification metadata.
- Does not remove upstream PB controls.
- Does not authorize execution.
- Does not affect production activation.
- Does not alter provider behavior.

## Security

Sensitive-data handling:

- Reject sensitive keys.
- Reject credential-shaped literals.
- Never log raw payloads.
- Never serialize prompts.
- Never serialize provider responses.
- Never serialize personal data.
- Never serialize secrets, tokens, cookies, private keys, or environment dumps.

Credential handling:

- No credentials may be introduced.
- No credentials may be read.
- No credentials may be validated through a live provider.
- Credential presence must return `BLOCKED`.

Network restrictions:

- No network calls.
- No sockets.
- No HTTP/API calls.
- No provider calls.

Provider restrictions:

- No provider execution.
- No provider activation.
- No provider readiness claims.
- Provider metadata may only be treated as redacted references when supplied by upstream controls.

Subprocess restrictions:

- No subprocess execution.
- No shell execution.
- No runtime command execution.
- No background workers.

## Deployment

PB-1I explicitly provides:

- NO deployment
- NO production activation
- NO provider execution
- NO runtime mutation

PB-1I metadata must never be interpreted as deployment approval, runtime authorization, production readiness, provider readiness, or legal/compliance certification.
