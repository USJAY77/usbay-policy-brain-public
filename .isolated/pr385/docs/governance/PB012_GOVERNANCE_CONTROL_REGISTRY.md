# PB-012 Governance Control Registry

## Purpose

PB-012 protects and verifies the governance controls themselves.

The control registers PB-005 through PB-011, records their local definition artifacts, hashes those artifacts, and fails closed when the registered control set or control definitions drift.

## Scope

PB-012 registers:

- PB-005 durable evidence backend evidence
- PB-006 evidence integrity control
- PB-007 independent evidence verifier
- PB-008 RFC3161 timestamp control
- PB-009 immutable evidence archive
- PB-010 governance chain certification
- PB-011 baseline drift detection

PB-012 generates:

- `governance_control_registry.json`
- `governance_control_manifest.json`
- `governance_self_attestation.json`

## Authority Boundary

PB-012 is local governance validation only.

PB-012 must not call:

- AWS
- PostgreSQL
- Timestamp Authority services
- External networks
- External certification providers

PB-012 does not claim:

- regulatory certification
- external certification
- production readiness

## Validation Rules

PB-012 verifies:

- required controls exist
- control identifiers are unique
- control count matches the registry
- registered definition artifacts exist
- control definition artifact hashes match the manifest
- registry hash matches the stored manifest
- manifest signature matches the stored manifest payload

## Fail-Closed Conditions

PB-012 returns `Decision: BLOCKED` if any of the following occur:

- registered control missing
- duplicate control identifier
- control count mismatch
- registered control artifact missing
- registry hash mismatch
- control manifest mismatch
- control manifest signature mismatch
- unauthorized control modification
- unauthorized control registered

## Execution

Generate registry:

```bash
python3 scripts/pb012_governance_control_registry.py generate . governance/evidence/pb012_control_registry
```

Verify registry:

```bash
python3 scripts/pb012_governance_control_registry.py verify . governance/evidence/pb012_control_registry
```

Expected verified output:

```text
Decision: VERIFIED
PB012_GOVERNANCE_CONTROL_REGISTRY_VERIFIED
```

## Registry

`governance_control_registry.json` records:

- control id
- title
- version
- definition paths
- control count
- local-only validation boundary

## Manifest

`governance_control_manifest.json` records:

- registry hash
- control definition hashes
- aggregate definition hash
- registered control count
- expected control count
- deterministic registry signature

## Self-Attestation

`governance_self_attestation.json` records:

- decision
- fail-closed status
- errors
- duplicate control detection
- missing control detection
- control count mismatch detection
- registry hash mismatch detection
- control manifest mismatch detection
- unauthorized control modification detection

## Governance Rule

Evidence before claims.

The governance controls are themselves governed artifacts. Any change to a registered control definition must be detected, reviewed, and re-registered through governed evidence generation.
