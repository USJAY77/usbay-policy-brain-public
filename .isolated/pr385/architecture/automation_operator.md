# PB-352 Governed Automation Operator

Status: PB-352_GOVERNED_AUTOMATION_OPERATOR_DRY_RUN

## Mission

The Governed Automation Operator is the first USBAY control-plane operator contract for coordinating Terminal, Codex, GitHub, Notion, LinkedIn, Email, Tasks, and Audit Evidence through governed dry-run workflow decisions.

The operator may observe, plan, prepare, validate, and draft automatically. It may not perform live external mutations in this dry-run contract.

## Systems

The operator covers these systems:

- Terminal commands
- Codex task dispatch
- GitHub PR, check, review, and merge workflows
- Notion documentation updates
- LinkedIn draft and publication workflow
- Email draft and send workflow
- Task creation and status workflow
- Audit evidence generation

## Governance Rule

Every requested action must be evaluated before execution. The operator blocks by default when governance evidence is incomplete.

The operator blocks on:

- unknown agent
- unknown connector
- missing policy
- missing approval when mutation approval is required
- missing audit hash
- connector or API failure
- unsafe terminal command without approval
- any live mutation request in the dry-run contract

## Approval Gates

The dry-run operator defines these approval gates:

- `TERMINAL_EXECUTION_APPROVAL`
- `CODEX_TASK_APPROVAL`
- `GITHUB_MUTATION_APPROVAL`
- `NOTION_WRITE_APPROVAL`
- `LINKEDIN_PUBLICATION_APPROVAL`
- `EMAIL_SEND_APPROVAL`
- `TASK_STATUS_MUTATION_APPROVAL`

Approval evidence must be present before an approval-required action can move beyond blocked state. Even with approval, this PB-352 contract does not perform live external mutation.

## Audit Evidence

Every decision returns an evidence object with:

- `action_id`
- `actor`
- `connector`
- `requested_action`
- `policy_decision`
- `approval_state`
- `timestamp`
- `evidence_hash`
- `outcome`
- `blocked_reason`

Evidence is hash-only and bounded. Raw secrets, tokens, raw payloads, private keys, raw approval contents, audio, and video are forbidden.

## External Mutation Boundary

This phase does not execute external mutations. The operator can prepare a dry-run decision and audit evidence only.

Live mutations remain blocked until a future phase adds a separately reviewed execution adapter with explicit human approval, connector policy, and audit evidence storage.

