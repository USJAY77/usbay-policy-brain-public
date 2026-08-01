# PB-1R

## Canonical Capability Name

`PB-1R Governance Release Successor Authority Handoff`

PB-1R SHALL NOT authorize runtime execution.

## Purpose

PB-1R defines the metadata-only governance capability that continues directly from PB-1Q Governance Release Continuity Review. It verifies that release continuity review metadata can be converted into a deterministic successor-authority handoff package for human governance review.

PB-1R does not approve a release, authorize runtime execution, deploy software, call providers, activate production, mutate policy, mutate runtime state, execute rollback, replace the gateway, or create operational trust claims. It only defines the governance metadata required before any later capability may inspect successor-authority handoff readiness.

## Governance Objective

PB-1R preserves USBAY as an Execution Control Layer by requiring successor-authority handoff metadata to remain deterministic, hash-only, redacted, approval-linked, audit-linked, evidence-linked, dependency-linked, rollback-aware, tenant-isolated, policy-version-isolated, correlation-linked, replay-safe, chronology-preserving, and fail-closed.

PB-1R treats missing evidence as failed evidence, unknown state as unsafe state, and incomplete chronology as non-authoritative.

## Architecture

PB-1R is a specification for a standalone metadata-only governance review stage. The capability consumes immutable references from PB-1Q and validates successor-authority handoff metadata by hash/reference only.

PB-1R may define only governance metadata. It must not define executable behavior, provider behavior, gateway behavior, deployment behavior, workflow behavior, dependency changes, secret handling, credential handling, or runtime authorization behavior.

No external service is contacted. No provider, network, subprocess, deployment, timestamp authority, signing authority, WORM system, object-lock system, regulator transport, or production runtime is invoked.

## Inputs

Allowed inputs are limited to immutable metadata references:

- PB-1Q decision reference.
- PB-1Q release continuity review hash.
- PB-1Q evidence hash.
- PB-1Q package hash.
- PB-1Q audit hash.
- PB-1Q chronology reference.
- Successor-authority handoff reference.
- Successor-authority evidence reference.
- Human approval reference.
- Approval evidence reference.
- Audit-chain reference.
- Evidence-chain reference.
- Dependency readiness reference.
- Replay metadata reference.
- Rollback plan reference.
- Rollback evidence reference.
- Tenant reference.
- Policy version reference.
- Correlation reference.
- Required predecessor reference.
- Required successor reference.
- Validation evidence reference.
- Safety flags explicitly set to false.

All references must be hash-only or immutable external references. All hash references must use canonical `sha256:<64 lowercase hex>` values.

## Decisions

PB-1R may emit only:

- `READY`
- `READY_WITH_RESTRICTIONS`
- `BLOCKED`

`READY` means all required metadata references validate, PB-1Q is not blocked, successor-authority handoff metadata is complete, approvals are referenced, audit and evidence chronology are consistent, dependency references are present, rollback references are present, required predecessor and successor references are present, and every safety flag remains false.

`READY_WITH_RESTRICTIONS` means the same metadata package validates with explicit governed restriction metadata by reference only.

`BLOCKED` means at least one required governance condition is unknown, missing, malformed, stale, unsupported, inconsistent, duplicated, replayed, unverifiable, sensitive, credential-shaped, or execution-shaped.

No PB-1R decision authorizes execution, deployment, production activation, provider execution, runtime mutation, or policy mutation.

## Safety Flags

PB-1R outputs must always preserve:

- `execution_allowed=false`
- `provider_execution=false`
- `production_activation=false`
- `deployment_authorized=false`
- `runtime_mutation=false`
- `policy_mutation=false`

Any input, output, or intermediate metadata that sets, implies, omits, or contradicts these false safety flags must return `BLOCKED`.

## Fail-Closed Rules

PB-1R must return `BLOCKED` for every unknown, missing, malformed, stale, unsupported, inconsistent, duplicated, replayed, unverifiable, sensitive, credential-shaped, or execution-shaped input.

PB-1R must also return `BLOCKED` when:

- PB-1Q metadata is missing.
- PB-1Q decision is `BLOCKED`.
- PB-1Q decision is unknown.
- PB-1Q release continuity review hash is missing.
- PB-1Q evidence hash is missing.
- PB-1Q package hash is missing.
- PB-1Q audit hash is missing.
- PB-1Q chronology reference is missing.
- Successor-authority handoff reference is missing.
- Successor-authority evidence reference is missing.
- Human approval reference is missing.
- Approval evidence reference is missing.
- Audit-chain reference is missing.
- Evidence-chain reference is missing.
- Dependency readiness reference is missing.
- Replay metadata reference is missing.
- Rollback plan reference is missing.
- Rollback evidence reference is missing.
- Tenant reference is missing.
- Policy version reference is missing.
- Correlation reference is missing.
- Required predecessor reference is missing.
- Required successor reference is missing.
- Validation evidence reference is missing.
- Evidence chronology is missing or inconsistent.
- Any expected hash mismatches the computed hash.
- Any safety flag is not false.
- Any direct execution request is present.
- Any provider, deployment, production, network, subprocess, credential, secret, policy mutation, or runtime mutation surface is present.
- Any exception occurs during validation.

## Approved Implementation Files

PB-1R implementation may create or modify only:

1. `docs/runtime/PB_1R_GOVERNANCE_RELEASE_SUCCESSOR_AUTHORITY_HANDOFF.md`
2. `governance/evidence/pb_1r_governance_release_successor_authority_handoff.json`
3. `runtime/computer_use/pb_1r_governance_release_successor_authority_handoff.py`
4. `tests/test_pb_1r_governance_release_successor_authority_handoff.py`

Any file not listed in this section SHALL NOT be modified by PB-1R implementation.

## Rollback Criteria

PB-1R specification rollback must be isolated to the PB-1R specification commit.

Rollback impact:

- Removes the PB-1R capability specification.
- Does not remove PB-1B through PB-1Q controls.
- Does not authorize execution.
- Does not affect production activation.
- Does not change gateway behavior.
- Does not alter provider behavior.
- Does not weaken audit lineage.

## Required Predecessor References

PB-1R requires PB-1Q predecessor references:

- PB-1Q final decision reference.
- PB-1Q release continuity review hash.
- PB-1Q evidence hash.
- PB-1Q package hash.
- PB-1Q audit hash.
- PB-1Q chronology reference.
- PB-1Q tenant reference.
- PB-1Q policy version reference.
- PB-1Q correlation reference.

Missing, malformed, stale, duplicate, replayed, tenant-mismatched, policy-version-mismatched, chronology-mismatched, hash-mismatched, unsupported, or unverifiable predecessor references must return `BLOCKED`.

## Required Successor References

PB-1R requires successor metadata by immutable reference only:

- Successor capability reference.
- Successor handoff reference.
- Successor evidence reference.
- Successor audit reference.
- Successor chronology reference.
- Successor dependency reference.

Missing, malformed, stale, duplicated, unsupported, replayed, or unverifiable successor references must return `BLOCKED`.

PB-1R must not implement the successor capability, pre-approve successor behavior, or authorize future runtime execution.

## Audit Requirements

PB-1R audit metadata must be deterministic, hash-only, redacted, tenant-isolated, policy-version-isolated, correlation-linked, replay-traceable, rollback-linked, dependency-linked, successor-linked, and chronology-preserving.

Audit metadata must include:

- PB-1R capability name.
- Decision state.
- Deterministic reason codes.
- PB-1Q predecessor references.
- Successor-authority handoff references.
- Human approval references.
- Audit-chain references.
- Evidence-chain references.
- Dependency references.
- Replay metadata references.
- Rollback references.
- Successor references.
- Tenant reference.
- Policy version reference.
- Correlation reference.
- Safety flags set to false.

Audit metadata must not include raw payloads, prompts, approval contents, provider responses, credentials, secrets, personal data, environment dumps, runtime artifacts, deployment targets, production activation material, private keys, cookies, tokens, or unredacted regulator material.

## Sensitive-Data Rules

PB-1R must reject and must not serialize:

- Credentials.
- Tokens.
- Private keys.
- Cookies.
- Secrets.
- Personal data.
- Approval contents.
- Provider responses.
- Prompts.
- Raw payloads.
- Environment dumps.
- Certificate bodies.
- Access-token material.
- Secret values.

Sensitive data must never appear in outputs, logs, evidence, audit records, reason codes, documentation examples, or future test fixtures.

## Acceptance Criteria

PB-1R is acceptable only when:

- The specification is documentation-only.
- The changed-file boundary is exactly one file.
- PB-1R continues directly from PB-1Q.
- PB-1R remains metadata-only.
- PB-1R preserves USBAY as an Execution Control Layer.
- PB-1R does not authorize runtime execution.
- PB-1R requires predecessor references.
- PB-1R requires successor references.
- PB-1R requires human approval references.
- PB-1R requires audit, evidence, dependency, replay, rollback, tenant, policy, and correlation references.
- PB-1R preserves fail-closed behavior.
- PB-1R preserves false safety flags.
- PB-1R rejects sensitive, credential-shaped, and execution-shaped metadata.
- Human reviewers approve the PR.

## Explicitly Prohibited Behaviour

PB-1R must not:

- Weaken PB-1B through PB-1Q.
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

PB-1R must preserve deterministic governance, fail-closed execution, audit evidence, replay safety, rollback traceability, dependency traceability, successor traceability, the approval chain, and metadata-only governance.
