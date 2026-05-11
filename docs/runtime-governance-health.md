# Runtime Governance Health

USBAY runtime governance health continuously validates that the running process still matches the signed governance state it started from.

The runtime monitor enforces:

- policy bundle hash continuity
- signed release manifest continuity
- immutable runtime provenance authority identity
- runtime git lineage continuity
- release manifest freshness
- authority bootstrap freshness
- optional RFC3161 timestamp freshness

The monitor fails closed on drift or stale evidence. It does not reinterpret GitHub Actions lineage or create a second provenance authority boundary for downstream subsystems; callers inject the immutable `RuntimeProvenanceAuthority` when one already exists.

Diagnostics are deterministic and contain hashes, identifiers, status, and failure reason codes only:

- `governance_runtime_health.json`
- `attestation_freshness.json`
- `runtime_drift_report.json`

The diagnostics intentionally do not include raw nonces, secrets, approval material, private signing material, or raw governance decisions.

Runtime freshness policy is configured in `governance/runtime_governance_policy.json`:

- `release_manifest_max_age_seconds`
- `authority_bootstrap_max_age_seconds`
- `rfc3161_timestamp_max_age_seconds`
- `max_attestation_age_seconds`
- `monitor_interval_seconds`
- `require_runtime_rfc3161_timestamp`

If a configured freshness window expires, USBAY reports the exact failed control and blocks runtime governance health validation. In production, this keeps governance enforcement tied to current signed evidence rather than stale startup state.
