# USBAY Governance Operations Observability

USBAY governance operations observability provides read-only health snapshots
and diagnostics for release integrity, dependency boundaries, signer
continuity, baseline lineage, rollback validity, and fail-closed rejection
counts.

## Incident Response

When diagnostics report `valid=false`, operators must treat the runtime as
governance-blocked until the failed control is resolved. The diagnostic output
contains only public hashes, status labels, aggregate counters, and failure
codes. It intentionally omits private keys, raw evidence, raw nonces, approval
contents, and secrets.

Recommended response:

1. Run `python3 scripts/governance_diagnostics.py status`.
2. Inspect failure codes.
3. Run the focused verifier for the failing control.
4. Preserve diagnostic output as audit evidence.
5. Do not override fail-closed enforcement.

## Rollback Procedure

Rollback validation is explicit. A release with non-`GENESIS` previous release
metadata is accepted only when the previous release hash appears in the
operator-supplied rollback target set. Invalid rollback targets produce
fail-closed rejection metrics and must not be deployed.

## Release Recovery

Release recovery requires a valid governance baseline tag, consistent
dependency graph hash, canonical DER trust-policy fingerprint, and signed
release integrity metadata. If any of those values drift, recovery is blocked
until a new signed release integrity manifest is generated and verified.

## Governance Drift Handling

Dependency drift, baseline drift, signer continuity failures, and release
mismatches are surfaced through operational metrics:

- `validation_latency_ns`
- `release_integrity_latency_ns`
- `trust_policy_validation_count`
- `dependency_drift_events`
- `rollback_validation_events`
- `fail_closed_rejection_count`

These metrics are deterministic in structure and audit-safe in content.

