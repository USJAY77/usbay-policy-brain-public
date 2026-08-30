# PB-042 GitHub Production Connector Design

## Decision
PARTIAL

## Status
READY_FOR_REVIEW

## Evidence Boundary
This PB is architecture and governance only. It does not create live credentials, create a GitHub App, create a PAT, call GitHub APIs, or mutate any repository.

## Selected Authentication Model
USBAY should use a repository-scoped GitHub App installation as the primary production authentication model.

The GitHub App model is selected because it provides the strongest fit for least privilege, fail-closed governance, auditability, credential rotation, organization deployment, and long-term automation. It separates automation authority from individual user tokens while still requiring USBAY to bind every action to an explicit human approval reference.

## Rejected Primary Alternative
Fine-Grained PAT is rejected as the primary production model.

Reason: a Fine-Grained PAT can be scoped for a limited pilot, but it remains tied to a user token lifecycle, creates more attribution ambiguity, and is weaker for long-term production automation. USBAY may use a Fine-Grained PAT only as a time-boxed governed pilot or break-glass exception with explicit approval, external secret storage, short expiration, audit evidence, and revocation evidence.

## Production Architecture
```text
Policy Brain
  -> Approval Layer
  -> GitHub Connector
  -> Audit Layer
```

Policy Brain validates the requested GitHub action, repository scope, capability permission, tenant context, and policy reference.

Approval Layer verifies required human approval before branch, pull request, merge, release, ruleset, branch protection, or secret actions.

GitHub Connector obtains a short-lived GitHub App installation token only after policy and approval pass.

Audit Layer writes a pre-action audit record before mutation and captures a post-action GitHub receipt after the response.

## Required Controls Before First Live GitHub Action
- Repository-scoped GitHub App installation.
- Approved secret storage outside the repository.
- Credential authority record with app id hash, installation id hash, repository allow-list, capability allow-list, owner, rotation rule, and revocation owner.
- Capability permission matrix bound to the first action.
- Human approval workflow for mutating or public actions.
- Pre-action audit write implemented and verified.
- Post-action GitHub receipt capture implemented and verified.
- Secret redaction verified for logs, audit records, and reports.
- Fail-closed negative tests for missing credential, missing approval, permission mismatch, GitHub API failure, audit failure, and receipt failure.

## Minimum Production Rollout Sequence
1. Authorize this connector design through governance review.
2. Create a repository-scoped GitHub App outside this PB.
3. Store the GitHub App private key outside the repository.
4. Record credential authority, rotation, and revocation evidence.
5. Implement the connector adapter behind the PB-038 policy gate.
6. Enable one non-destructive pilot capability.
7. Run a governed live pilot with pre-action audit and post-action receipt capture.
8. Review pilot evidence before enabling additional capabilities.

## Readiness Decision
`PARTIAL`

The design is complete enough to guide implementation, but GitHub production onboarding is not ready because repository evidence does not yet include live credential authority, secret storage evidence, production connector implementation, pre-action audit writes, post-action receipts, or live fail-closed validation.

## Generated PR Body
## PURPOSE
PB-042 designs the first production-governed GitHub connector for USBAY without activating live credentials, creating a GitHub App, creating a PAT, calling GitHub APIs, or mutating repositories.

## RISK
A GitHub connector can mutate branches, pull requests, releases, rulesets, protections, and secrets. If the authentication model, approval gate, audit chain, or receipt capture is wrong, USBAY could create an ungoverned execution path.

## POLICY LINK
AGENTS.md fail-closed, audit-first engineering, human oversight, branch governance, network governance, and secret/data hygiene rules. PB-038 connector framework, PB-039 orchestrator simulation, PB-040 connector readiness assessment, and PB-041 GitHub connector authority evidence.

## REQUIRED APPROVALS
USBAY-AUDIT and USBAY-GLOBAL23 review are required before merge. Future live connector activation requires separate human approval, credential authority evidence, and live fail-closed validation.

## GOVERNANCE CHECKS
JSON evidence must parse. Summary must answer the selected authentication model, rejected alternative, required controls before first live action, minimum rollout sequence, and readiness decision. Diff hygiene and conflict marker scan must pass.

## AUDIT
PB-042 generates governance/evidence/pb042/github_production_connector_design.json and governance/evidence/pb042/github_production_connector_summary.md. No credentials, API calls, or repository mutations are produced.

## IMPACT
USBAY gains a production connector design path for GitHub while preserving PARTIAL readiness until live credential, audit, receipt, and fail-closed evidence exists.

## Decision
VERIFIED

## Status
READY_FOR_REVIEW
