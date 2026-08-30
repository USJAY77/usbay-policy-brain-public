# PB-013 Continuous Governance Monitor

## Purpose

PB-013 continuously evaluates local governance health across PB-005 through PB-012.

The monitor consumes the existing local governance evidence chain, drift reports, certification reports, and control registry self-attestation. It produces a current health report, risk score, monitor report, and status summary.

## Scope

PB-013 verifies:

- PB-005 evidence artifacts
- PB-006 integrity report
- PB-007 independent verification report
- PB-008 timestamp report
- PB-009 archive integrity report
- PB-010 certification report
- PB-011 drift report
- PB-012 control registry self-attestation

PB-013 generates:

- `pb013_governance_health_report.json`
- `pb013_governance_risk_score.json`
- `pb013_governance_monitor_report.json`
- `pb013_governance_status_summary.json`

## Authority Boundary

PB-013 is local governance validation only.

PB-013 must not call:

- AWS
- PostgreSQL
- Timestamp Authority services
- External networks
- External certification providers

PB-013 does not claim:

- regulatory certification
- external certification
- production readiness

## Fail-Closed Conditions

PB-013 returns `Decision: BLOCKED` when:

- required control missing
- control registry mismatch detected
- drift report failed
- certification report failed
- governance health score below threshold
- unsupported governance artifact detected
- required report schema invalid
- required report contains errors

The health threshold is strict: all PB-005 through PB-012 controls must verify.

## Execution

Run the monitor:

```bash
python3 scripts/pb013_continuous_governance_monitor.py \
  governance/evidence/pb005 \
  governance/evidence/pb009_archive \
  governance/evidence/pb010_chain \
  governance/evidence/pb011_baseline \
  governance/evidence/pb012_control_registry \
  governance/evidence/pb013_monitor
```

Expected verified output:

```text
Decision: VERIFIED
PB013_CONTINUOUS_GOVERNANCE_MONITOR_VERIFIED
```

## Reports

`pb013_governance_health_report.json` records:

- verified controls
- total controls
- health score
- per-control status
- fail-closed state

`pb013_governance_risk_score.json` records:

- risk score
- risk level
- threshold status

`pb013_governance_monitor_report.json` records:

- drift failure status
- certification failure status
- control registry mismatch status
- required control missing status
- unsupported artifact status

`pb013_governance_status_summary.json` records:

- current governance status
- health score
- risk score
- fail-closed state

## Governance Rule

Evidence before claims.

Continuous monitoring must fail closed on any governance uncertainty. Unknown health is unsafe health.
