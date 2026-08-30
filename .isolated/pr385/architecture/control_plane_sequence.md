# USBAY Control Plane Sequence

Status: PHASE_1_ARCHITECTURE_ONLY

## Nominal Governed Flow

```mermaid
sequenceDiagram
    autonumber
    participant User as Human Operator
    participant CP as USBAY Control Plane
    participant AR as Agent Registry
    participant Policy as Policy Evaluation
    participant Approval as Human Approval Gate
    participant Connector as Governed Connector Layer
    participant External as External System
    participant Audit as Audit Evidence Layer
    participant Dash as Dashboard Projection

    User->>CP: Submit governed task
    CP->>AR: Validate agent registration, health, approval, audit state
    AR-->>CP: Agent state or BLOCKED
    CP->>Policy: Evaluate task, connector, capability, tenant, risk
    Policy-->>CP: ALLOW, DENY, BLOCK, or APPROVAL_REQUIRED
    CP->>Approval: Check human approval when required
    Approval-->>CP: APPROVED or BLOCKED
    CP->>Connector: Evaluate capability-based connector action
    Connector-->>CP: DRY_RUN_READY, EXECUTION_READY, or BLOCKED
    CP->>External: Execute only if policy and approval allow
    External-->>CP: Outcome or connector failure
    CP->>Audit: Generate redacted/hash-only evidence
    Audit-->>CP: Evidence hash or BLOCKED
    CP->>Dash: Publish backend-derived state
    Dash-->>User: Verified, blocked, or unverified state
```

## Required Execution Pipeline

1. Receive task.
2. Validate task schema and required governance metadata.
3. Validate agent registration and health.
4. Evaluate policy.
5. Check human approval when required.
6. Evaluate connector capability and auth state.
7. Execute connector action only when permitted.
8. Generate audit evidence.
9. Store evidence through append-only audit flow.
10. Update control-plane state.
11. Render dashboard from backend evidence only.

## Fail-Closed Sequence

```mermaid
sequenceDiagram
    autonumber
    participant CP as USBAY Control Plane
    participant Policy as Policy Evaluation
    participant Approval as Human Approval Gate
    participant Connector as Governed Connector Layer
    participant Audit as Audit Evidence Layer

    CP->>Policy: Evaluate action
    Policy-->>CP: Missing or BLOCK
    CP-->>CP: Set outcome BLOCKED
    CP->>Audit: Generate blocked-action evidence
    alt evidence generated
        Audit-->>CP: evidence_hash
        CP-->>CP: Persist BLOCKED state
    else evidence unavailable
        Audit-->>CP: AUDIT_WRITE_FAILED
        CP-->>CP: Persist FAIL_CLOSED runtime state only
    end
    CP-->>Approval: No approval bypass
    CP-->>Connector: No connector execution
```

## Human Approval Sequence

```mermaid
sequenceDiagram
    autonumber
    participant CP as USBAY Control Plane
    participant Policy as Policy Evaluation
    participant Approval as Human Approval Gate
    participant Audit as Audit Evidence Layer
    participant Connector as Governed Connector Layer

    CP->>Policy: Evaluate requested action
    Policy-->>CP: APPROVAL_REQUIRED
    CP->>Approval: Verify approver, timestamp, policy version, evidence hash
    alt approval valid
        Approval-->>CP: APPROVED
        CP->>Connector: Continue connector capability evaluation
    else approval missing or invalid
        Approval-->>CP: BLOCKED
        CP->>Audit: Record blocked approval checkpoint
        CP-->>Connector: No execution
    end
```

## Dashboard Update Sequence

```mermaid
sequenceDiagram
    autonumber
    participant CP as USBAY Control Plane
    participant Audit as Audit Evidence Layer
    participant Dash as Dashboard Projection

    CP->>Audit: Read action evidence summary
    Audit-->>CP: Hash-only/redacted evidence state
    CP->>Dash: Send backend-derived state
    alt evidence complete
        Dash-->>Dash: Render verified or blocked outcome
    else evidence missing
        Dash-->>Dash: Render UNVERIFIED or BLOCKED
    end
```

## Phase 1 Sequence Constraints

Phase 1 defines the sequence only. It does not implement execution, connector calls, dashboard rendering, or audit writes.
