# USBAY Control Plane Trust Boundaries

Status: PHASE_1_ARCHITECTURE_ONLY

## Boundary Summary

The control plane operates across five major trust boundaries:

1. Human operator to USBAY Control Plane
2. USBAY Control Plane to USBAY Agents
3. USBAY Control Plane to governed connectors
4. Governed connectors to external systems
5. Control Plane and connectors to audit evidence

Each boundary must preserve fail-closed behavior, redacted/hash-only evidence, human approval where required, and backend truth as source of truth.

## Boundary 1: Human Operator to Control Plane

Inputs from humans are untrusted until validated.

Controls:

- task schema validation
- actor identity binding
- policy version binding
- tenant or scope binding
- approval freshness validation
- no raw approval contents in logs

Fail-closed conditions:

- missing actor
- missing policy version
- malformed task
- stale approval
- self-approval
- approval without evidence hash

## Boundary 2: Control Plane to Agents

Agents are not trusted solely because they are known by name. Every agent must have explicit registry, health, approval, and audit state.

Supported agents:

- Codex Agent
- Runtime Agent
- Hydra Agent
- Governance Agent

Controls:

- agent registration
- enable or disable state
- health check
- approval state
- audit state

Fail-closed conditions:

- unknown agent
- disabled agent
- missing health state
- unhealthy state
- missing audit state
- approval required but absent

## Boundary 3: Control Plane to Connectors

Connector requests are governed by capability, policy, approval, auth, and audit requirements.

Connectors:

- GitHub
- Notion
- LinkedIn
- Email
- Tasks

Existing connector governance from `governance/connector_framework.py` remains the source pattern for:

- known connector registry
- required permissions
- approval-required actions
- dry-run support
- sensitive-field redaction
- connector error blocking

Fail-closed conditions:

- unknown connector
- unknown capability
- missing permission
- unsupported action type
- connector error
- auth unknown
- auth invalid
- action attempts live mutation without explicit approval and policy allowance

## Boundary 4: Connectors to External Systems

External systems are outside the trusted USBAY boundary. Network calls and mutations are not safe by default.

Systems:

- GitHub
- Notion
- LinkedIn
- Email
- Tasks

Controls:

- capability-based execution
- dry-run default
- human approval for writes and public actions
- no raw secrets in connector payload logs
- no silent fallback on connector failure
- explicit policy decision before execution

Fail-closed conditions:

- network unavailable
- auth unavailable
- auth invalid
- connector response malformed
- external system state ambiguous
- execution evidence unavailable

## Boundary 5: Control Plane to Audit Evidence

Audit evidence is mandatory for every control-plane decision. Evidence writes must be append-only and hash-linked when stored.

Existing evidence helpers from `audit/audit_writer.py`, `audit/hash_chain.py`, and `audit/ledger.py` remain the source patterns for:

- redaction
- payload hashing
- audit hash creation
- append-only chain behavior
- ledger verification

Required action evidence:

- `action_id`
- `policy_version`
- `approver`
- `timestamp`
- `outcome`
- `evidence_hash`

Fail-closed conditions:

- evidence generation fails
- evidence hash missing
- audit writer fails
- append-only chain mismatch
- raw sensitive payload detected
- evidence storage path unavailable

## Dashboard Trust Boundary

The dashboard is not a source of truth. It is a read-only projection of backend evidence.

Controls:

- verified only with backend proof
- approval state rendered only from approval evidence
- connector activity rendered only from connector audit evidence
- missing evidence renders as `UNVERIFIED` or `BLOCKED`

Fail-closed conditions:

- missing dashboard source
- stale dashboard source
- malformed evidence
- unverifiable evidence hash

## Sensitive Data Boundary

The control plane must never log or store:

- secrets
- tokens
- raw payloads
- raw prompts
- private keys
- raw approval contents
- audio
- video
- sensitive connector responses

Allowed diagnostics:

- hashes
- redacted metadata
- bounded reason codes
- policy versions
- timestamps
- non-sensitive connector state

## Phase 1 Boundary Constraints

Phase 1 documents trust boundaries only. It does not authorize new live connector execution, new runtime behavior, gateway changes, policy changes, workflow changes, dependency changes, or audit evidence mutation.
