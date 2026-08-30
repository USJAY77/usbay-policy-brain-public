# Runtime Approval Gate

## Purpose

Runtime Approval Gate validates hash-only references to external human approval decisions for Phase B runtime-adjacent governance. Humans approve. This component only validates approval metadata and never approves, executes, schedules, dispatches, queues, invokes, or activates anything.

## Trust Boundary

The approval content remains outside the repository and outside this component. The gate stores no names, email addresses, comments, credentials, tokens, prompts, or sensitive approval content.

## Required Metadata

Approval references use a strict schema:

- `approval_id`
- `approval_hash`
- `policy_hash`
- `evidence_hash`
- `tenant_hash`
- `decision_hash`
- `actor_role_hash`
- `action_contract_hash`
- `issued_at`
- `expires_at`
- `schema_version`
- `approval_version`
- `approval_status`
- `required_approver_count`
- `recorded_approver_count`
- `dual_approval_required`
- `approver_hashes`
- `execution_allowed`
- `provider_execution`
- `production_activation`
- `hash_algorithm`
- `redacted`
- `hash_only`

Unknown metadata fails closed.

## Approval Status Allow-List

Only these values are valid:

- `PENDING`
- `APPROVED`
- `REJECTED`
- `EXPIRED`
- `REVOKED`
- `BLOCKED`

The only status eligible for metadata continuation is `APPROVED`. Every other status blocks. Case changes, whitespace variants, empty values, and near matches fail closed.

## Validation Rules

Runtime Approval Gate validates:

- all required fields exist
- all hashes use canonical `sha256:<64 lowercase hex>` form
- `approval_hash` is reproducible from canonical approval metadata
- policy, evidence, tenant, decision, actor-role, and action-contract hashes match the request
- timestamps use canonical `YYYY-MM-DDTHH:MM:SSZ` format
- `expires_at` is later than `issued_at`
- approval is issued before the deterministic `as_of` timestamp
- approval is not expired at the deterministic `as_of` timestamp
- schema and approval versions are supported
- recorded approver count satisfies required approver count
- dual approval has at least two distinct approver hashes
- duplicate approver hashes are rejected
- evidence is hash-only and redacted
- execution flags remain hard false

## Security Boundaries

This component contains no runtime execution, subprocess spawning, process creation, sockets, networking, HTTP/API/provider/LLM calls, threads, async execution, Redis, Kafka, brokers, worker queues, tmux execution, credential access, secret access, approval-content logging, or production activation.

## Evidence Minimization

Outputs contain only hashes, status labels, schema/version metadata, denial metadata, and remaining gap labels. Raw approval content and sensitive data are rejected.

## Remaining Gaps

- Human approval content remains external.
- A successful gate result is not runtime authorization.
- Merge and deployment review remain separate governed processes.
