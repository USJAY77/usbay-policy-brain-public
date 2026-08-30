## PURPOSE
PB-134 defines how to build the revocation store.

## RISK
Revocation store gaps could allow revoked connectors to execute.

## POLICY LINK
AGENTS.md fail-closed, audit-first engineering, backend truth source-of-truth, human oversight, rollback and forensics, test discipline, and secret/data hygiene rules. PB-121 through PB-130 runtime implementation blueprint evidence.

## REQUIRED APPROVALS
USBAY-AUDIT and USBAY-GLOBAL23 review are required before merge. This PB does not authorize production activation, runtime deployment, external API calls, credential creation, live mutation, or production changes.

## GOVERNANCE CHECKS
JSON evidence must parse. Generated metadata, repository targets, implementation dependencies, required interfaces, tests, audit hooks, fail-closed enforcement points, deployment blockers, and required PR sections must validate.

## AUDIT
PB-134 generates revocation store build-plan evidence.

## IMPACT
USBAY gets a build plan for revocation enforcement.

## Decision
VERIFIED

## Status
READY_FOR_REVIEW
