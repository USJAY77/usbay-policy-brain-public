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
