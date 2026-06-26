# PB-104 Governance State Registry

## Decision
REGISTRY_DEFINED

## Status
READY_FOR_REVIEW

## Evidence Boundary
This PB is evidence-only. No activation or external mutation occurred.

## Where Are Approvals Stored?
Approvals are stored in the approval registry schema as append-only records linked by `connector_id`, `approval_id`, `evidence_ref`, `approval_hash`, and `audit_record_id`.

## Where Are Authorizations Stored?
Authorizations are stored in the authorization registry schema with approval ids, activation evidence references, authorization hash, rollback reference, and audit record id.

## Where Are Revocations Stored?
Revocations are stored in the revocation registry schema with revocation authority, reason, affected approval ids, revocation hash, and audit record id.

## How Is State Enforced?
State is enforced by validating current connector state, allowed transitions, required registry records, hashes, non-expired approvals, non-revoked approvals, and audit linkage before allowing any transition.

## What Blocks Invalid State Transitions?
- Missing state record.
- Missing approval record.
- Missing authorization record.
- Revocation conflict.
- Missing audit linkage.
- State hash mismatch.
- Approval hash mismatch.
- Expired approval.
- Revoked approval.
- Unsupported state.
- Direct OPEN to AUTHORIZED attempt.

## Generated PR Body
## PURPOSE
PB-104 defines the governance state registry that stores and enforces USBAY connector states, approvals, authorizations, revocations, and audit linkage.

## RISK
Without a state registry, connector approval or authorization state could be inferred from scattered evidence, causing invalid transitions or premature activation.

## POLICY LINK
AGENTS.md fail-closed, audit-first engineering, human oversight, rollback and forensics, trust-state isolation, and secret/data hygiene rules. PB-102 Governance Approval Workflow and PB-103 Governance Review Execution Framework.

## REQUIRED APPROVALS
USBAY-AUDIT and USBAY-GLOBAL23 review are required before merge. This PB does not authorize activation, external mutations, runtime storage changes, API calls, or credential creation.

## GOVERNANCE CHECKS
JSON evidence must parse. State storage model, connector registry schema, approval registry schema, revocation registry schema, authorization registry schema, audit linkage, fail-closed enforcement, and acceptance answers must validate.

## AUDIT
PB-104 generates governance/evidence/pb104/governance_state_registry.json, governance_state_registry_summary.md, generated_commit_title.txt, generated_pr_title.txt, and generated_pr_body.md.

## IMPACT
USBAY gains a deterministic registry model for connector governance state while preserving fail-closed blocking for invalid or unsupported transitions.

## Decision
VERIFIED

## Status
READY_FOR_REVIEW
