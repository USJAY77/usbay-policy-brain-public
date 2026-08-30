# USBAY Enterprise Architecture

This document explains the USBAY pilot review architecture for enterprise reviewers. It is visual documentation only. It does not change runtime behavior, governance enforcement, verifier logic, evidence-pack logic, or release ZIP contents.

## Runtime, Evidence, Verifier

- Runtime: the USBAY Policy Brain and Enforcement Gateway evaluate governance state and expose health/dashboard surfaces.
- Evidence: the pilot evidence pack contains hash-only gate history and chain summary artifacts for review.
- Verifier: the offline verifier validates exported evidence without network access or the live runtime.
- Demo/pilot-only: the packaged release demonstrates governance visibility and audit continuity; it is not production certification.

## Architecture Flow

```mermaid
flowchart LR
    A["USBAY Policy Brain"] --> B["Enforcement Gateway"]
    B --> C["Runtime Dashboard"]
    B --> D["Governance Evidence Pack"]
    D --> E["Offline Verifier"]
    E --> F["Enterprise Reviewer"]
    C --> F
```

## Fail-Closed Decision Flow

```mermaid
flowchart TD
    A["Governance Request"] --> B{"Required Evidence Present?"}
    B -- "Yes" --> C{"Signer Continuity Stable?"}
    B -- "No" --> G["BLOCKED"]
    C -- "Yes" --> D{"Hash Chain Valid?"}
    C -- "No" --> H["REVIEW_REQUIRED"]
    D -- "Yes" --> E["ALLOWED Demo Path"]
    D -- "No" --> I["VERIFY_FAIL / BLOCKED"]
    E --> F["Evidence Exported"]
    G --> F
    H --> F
    I --> F
```

## Tamper-Evident Hash Chain

```mermaid
flowchart LR
    A["GENESIS"] --> B["Event 0 current_event_hash"]
    B --> C["Event 1 previous_event_hash"]
    C --> D["Event 1 current_event_hash"]
    D --> E["Event 2 previous_event_hash"]
    E --> F["Event 2 current_event_hash"]
    F --> G["latest_event_hash"]
```

Each event hash is derived from the canonicalized previous event, current event payload, and signer continuity metadata. Changing an older event causes offline verification to return VERIFY_FAIL.

## Enterprise Reviewer Offline Verification

```mermaid
sequenceDiagram
    participant Reviewer as "Enterprise Reviewer"
    participant Zip as "Pilot ZIP"
    participant Pack as "Evidence Pack"
    participant Verifier as "Offline Verifier"
    Reviewer->>Zip: "Unzip release"
    Reviewer->>Pack: "Locate gate_history.json and chain_summary.json"
    Reviewer->>Verifier: "Run verify_governance_evidence_pack.py"
    Verifier->>Pack: "Recompute hash continuity"
    Verifier-->>Reviewer: "VERIFY_PASS or VERIFY_FAIL"
```

## Not Production Certification

The pilot package does not certify production deployment, approve execution, or override USBAY governance. BLOCKED and REVIEW_REQUIRED states remain visible and fail-closed.
