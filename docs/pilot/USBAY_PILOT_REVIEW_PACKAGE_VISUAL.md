# USBAY Pilot Review Package Visual README

This visual README summarizes the pilot release package and how enterprise reviewers should inspect it. It is documentation only and makes no production certification claims.

## Package Contents

```mermaid
flowchart TD
    A["USBAY_Pilot_Review_Package_v0.1.zip"] --> B["README.md"]
    A --> C["MANIFEST.json"]
    A --> D["Pilot Docs"]
    A --> E["Offline Verifier Script"]
    A --> F["Evidence Pack"]
    F --> G["gate_history.json"]
    F --> H["chain_summary.json"]
```

## Evidence Review Path

```mermaid
flowchart LR
    A["Unzip Package"] --> B["Read MANIFEST.json"]
    B --> C["Run Offline Verifier"]
    C --> D{"Verifier Result"}
    D -- "VERIFY_PASS" --> E["Evidence Chain Intact"]
    D -- "VERIFY_FAIL" --> F["Review Broken Evidence"]
```

## Runtime Versus Evidence

```mermaid
flowchart TB
    subgraph Runtime["Runtime"]
        A["Policy Brain"]
        B["Enforcement Gateway"]
        C["Dashboard"]
    end
    subgraph Evidence["Portable Evidence"]
        D["gate_history.json"]
        E["chain_summary.json"]
        F["SHA256 Release Checksum"]
    end
    subgraph Verification["Offline Verification"]
        G["verify_governance_evidence_pack.py"]
        H["VERIFY_PASS / VERIFY_FAIL"]
    end
    A --> B
    B --> C
    C --> D
    D --> G
    E --> G
    G --> H
```

## Pilot Scope

- Runtime: shows governance dashboard state and health surfaces.
- Evidence: contains hash-only pilot gate history and signer continuity metadata.
- Verifier: validates evidence offline without network access.
- Demo/pilot-only: demonstrates audit visibility and fail-closed behavior.
- Not production certification: does not assert production readiness or approve governance actions.

## Offline Verification Command

```bash
python3 scripts/verify_governance_evidence_pack.py artifacts/governance-demo-evidence-pack
```

Expected passing output:

```text
VERIFY_PASS
```

If evidence is missing, malformed, tampered, or secret-bearing, the verifier must return VERIFY_FAIL.
