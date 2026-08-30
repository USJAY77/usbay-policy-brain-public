# USBAY Governance Control Plane v1

Status: PHASE_1_ARCHITECTURE_ONLY

## Purpose

The USBAY Governance Control Plane v1 coordinates USBAY agents and external work systems through a single governed workflow. It does not authorize live external mutation by default. Every action must pass policy evaluation, approval checks, connector capability checks, and audit evidence generation before the control plane may report the action as complete.

The v1 control plane integrates existing USBAY capabilities instead of creating isolated execution paths.

## Existing Components Reused

The architecture reuses these existing USBAY components:

- `governance/connector_framework.py`: governed connector registry, capability checks, redaction, dry-run decisions, and fail-closed connector evaluation.
- `governance/connector_orchestrator_simulation.py`: existing dry-run connector workflow model and connector audit summaries.
- `governance/orchestrator_state_model.py`: canonical remediation/orchestration state model and fail-closed transition behavior.
- `governance/approval_gate_contract.py`: human approval gate contract for publication, execution, and merge-eligibility controls.
- `control_plane/ui/*`: existing control-plane UI view models for review, execution queue, adapter registry, audit explorer, and tenant dashboard state.
- `audit/audit_writer.py`: redacted audit record writer and audit hash generation.
- `audit/hash_chain.py`: append-only event hash-chain primitive.
- `audit/ledger.py`: deterministic ledger hash-chain validation helpers.

## Planned Phase 1 Artifacts

Phase 1 produces architecture only:

- `architecture/control_plane.md`
- `architecture/control_plane_sequence.md`
- `architecture/control_plane_trust_boundaries.md`

No Agent Registry, connector implementation, orchestrator implementation, dashboard implementation, runtime change, gateway change, policy change, workflow change, dependency change, or evidence payload mutation is authorized in Phase 1.

## Control Plane Model

The control plane coordinates the following layers:

1. USBAY Control Plane
2. USBAY Agents
3. Governed Connector Layer
4. External systems: GitHub, Notion, LinkedIn, Email, Tasks
5. Audit Evidence Layer
6. Dashboard projections

The control plane is a policy and evidence coordinator. It must not become a bypass around existing gateway, runtime, connector, policy, approval, or audit controls.

## Agent Model

The planned Agent Registry will support these agents:

- Codex Agent
- Runtime Agent
- Hydra Agent
- Governance Agent

Agent state must include:

- registration state
- enabled or disabled state
- health state
- approval state
- audit state

Unknown, disabled, unhealthy, unaudited, or unapproved agents must be treated as blocked.

## Connector Model

The planned connector layer will cover:

- GitHub
- Notion
- LinkedIn
- Email
- Tasks

Connectors must be capability-based. A connector action is not executable unless all of the following are true:

- connector is known
- connector capability is registered
- requested permission is present
- policy evaluation allows the action
- human approval exists when required
- audit evidence can be generated
- sensitive payloads are redacted or hashed

Connector failure, missing capability, missing policy, missing approval, or missing audit evidence must fail closed.

## Governance Checkpoints

Every task must pass these checkpoints:

1. Task intake validation
2. Agent registration and health validation
3. Connector capability validation
4. Policy evaluation
5. Human approval validation when required
6. Connector execution decision
7. Audit evidence generation
8. Evidence storage validation
9. Dashboard state update from backend evidence only

The control plane must never mark a task approved, executed, verified, or complete without backend evidence for the corresponding state.

## Human Approval Checkpoints

Human approval is required for:

- enabling an agent beyond registered-disabled state
- connector write actions
- public LinkedIn actions
- email send actions
- Notion write actions
- GitHub mutation actions
- task status mutation that changes operational state
- any action classified as high risk
- any action where policy returns `APPROVAL_REQUIRED`

Self-approval is forbidden. Missing, stale, unverifiable, or mismatched approval evidence blocks execution.

## Fail-Closed Checkpoints

The control plane must block on:

- unknown task type
- malformed task
- unknown agent
- disabled agent
- unhealthy agent
- unknown connector
- missing connector capability
- connector auth unknown or invalid
- missing policy decision
- policy deny or block
- approval required but absent
- connector failure
- evidence generation failure
- evidence hash missing
- audit write failure
- dashboard source missing or uncertain

Unknown state is unsafe state. Unsafe state is blocked state.

## Audit Evidence Contract

Every governed action must generate an evidence object containing:

- `action_id`
- `policy_version`
- `approver`
- `timestamp`
- `outcome`
- `evidence_hash`

Evidence must be hash-only or redacted metadata only. Raw secrets, tokens, private keys, raw prompts, raw payloads, raw approval contents, audio, and video are forbidden in logs and evidence.

If evidence generation or storage fails, the action outcome must be `BLOCKED`.

## Dashboard Contract

The dashboard is a read-only projection of backend governance state. It must show blocked or unverified when evidence is missing or stale.

Required dashboard views:

- Agent Status
- GitHub Activity
- Notion Activity
- LinkedIn Activity
- Email Activity
- Task Queue
- Evidence Queue
- Human Approvals

Dashboard implementation is not part of Phase 1. Phase 1 documents the required view contract only.

## Phase 1 Non-Goals

Phase 1 does not:

- perform live GitHub, Notion, LinkedIn, Email, or Task mutations
- add runtime execution paths
- modify gateway enforcement
- change policy rules
- change workflow definitions
- change dependency locks
- mutate audit evidence payloads
- implement Agent Registry code
- implement connector code
- implement orchestrator code
- implement dashboard UI code

## Governance Impact

Phase 1 is documentation-only. It clarifies the integration boundary for future implementation and preserves existing USBAY fail-closed, audit-first, human-review, and connector-governance controls.
