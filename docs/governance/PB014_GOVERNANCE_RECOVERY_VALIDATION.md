# PB-014 Governance Recovery Validation

## Purpose

PB-014 validates that USBAY can recover its local certified governance baseline after local artifact loss, corruption, or deletion.

The control builds a local recovery backup manifest from the PB-012 control registry and PB-013 continuous governance monitor state, simulates missing and corrupted artifacts in an isolated recovery workspace, restores from the local backup copy, and verifies recovered artifacts against expected hashes.

## Scope

PB-014 uses:

- PB-012 control registry to identify required controls
- PB-010 certification report as certification reference
- PB-011 drift report as baseline reference
- PB-013 continuous governance monitor output as current health reference

PB-014 generates:

- `pb014_recovery_backup_manifest.json`
- `pb014_recovery_simulation_report.json`
- `pb014_recovery_verification_report.json`
- `pb014_recovery_scorecard.json`

## Authority Boundary

PB-014 is local governance recovery validation only.

PB-014 must not call:

- AWS
- PostgreSQL
- Timestamp Authority services
- External networks
- External certification providers

PB-014 does not claim:

- external backup certification
- WORM certification
- disaster recovery certification
- production readiness

## Recovery Flow

1. Read PB-012 control registry.
2. Add PB-012 registry artifacts and PB-013 monitor artifacts to the recovery set.
3. Copy required artifacts into `backup_artifacts/`.
4. Generate `pb014_recovery_backup_manifest.json`.
5. Copy backup artifacts into an isolated recovery workspace.
6. Simulate one missing artifact.
7. Simulate one corrupted artifact.
8. Restore both from backup.
9. Verify all recovered hashes match the manifest.
10. Verify PB-012, PB-010, PB-011, and PB-013 recovered reports remain valid.

## Fail-Closed Conditions

PB-014 returns `Decision: BLOCKED` when:

- recovery baseline missing
- required artifact missing after recovery
- restored artifact hash mismatch
- registry mismatch after recovery
- PB-010 certification mismatch after recovery
- PB-011 drift mismatch after recovery
- PB-013 health score below threshold
- unsupported recovery artifact detected
- backup manifest mismatch

## Execution

Run recovery validation:

```bash
python3 scripts/pb014_governance_recovery_validation.py run . governance/evidence/pb014_recovery
```

Verify existing backup:

```bash
python3 scripts/pb014_governance_recovery_validation.py verify governance/evidence/pb014_recovery
```

Expected verified output:

```text
Decision: VERIFIED
PB014_GOVERNANCE_RECOVERY_VALIDATED
```

## Governance Rule

Evidence before claims.

Recovery validation is not external backup certification. A local recovery simulation proves only that the current local baseline can be restored from the generated local backup artifact set.
