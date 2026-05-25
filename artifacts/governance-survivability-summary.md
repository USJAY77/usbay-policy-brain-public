# USBAY Governance Survivability Summary

Generated: 2026-05-25T13:49:55Z
Branch: `governance/survivability-regression-isolation`
Conclusion: `GOVERNANCE_SURVIVABILITY_BLOCKED`

## Exact Degradation Boundaries

- Full regression remains degraded at `5 failed, 1303 passed` over `1:25:56`.
- The five full-regression failures are confined to runtime/UI/legacy contract expectations:
  - `/dashboard` and `/playground/demo` render governed demo evidence, but legacy tests expect older text markers.
  - `/health` returns expected fail-closed base fields plus additional degraded trust-state evidence fields, causing strict equality tests to fail.
- Persisted governance evidence does not degrade under verifier, replay, queue, or ZIP checksum pressure.
- Fresh concurrent evidence export generation degrades determinism: regenerated manifests differ in RFC3161 timestamp metadata even though each generated pack verifies successfully.

## Safe Operating Ranges

- Offline verifier: stable at 24 concurrent executions with `VERIFY_PASS` and `TIMESTAMP_VERIFY_PASS`.
- Replay pressure: stable at 200 repeated verifier executions against the persisted evidence pack.
- Governance queue pressure: stable at 60 queued verifier tasks with 12 workers and zero non-zero exits.
- Persisted evidence pack hashes: stable before and after stress.
- ZIP release checksum: stable and matching `USBAY_Pilot_Review_Package_v0.1.sha256`.

## Governance Stability Envelope

- `gate_history.json`: stable hash `6d980d9d0c173ea2b1375d2cf01205e5ce9fb1dde3943e30b220047cc2b9896a`.
- `chain_summary.json`: stable hash `84734c78a2e49b53cfea67994d340b4329e679d38a01af9bb2bbee6840345e5a`.
- `manifest.json`: persisted hash stable at `8aef83c6aeefd1f6f13da46138066333d61e39149cfc99300761495126243080`.
- `timestamp.tsr`: stable hash `dd40fccd95b01f0a98e271ff401239040b588f6a194e6d2faccd2ed0e134ce50`.
- Offline verifier reports:
  - `VERIFY_PASS latest_event_hash=f07e6a16893939a152387c3cf30a6bd60dc9efbdee132b95dc8e3be0b362e4b4 event_count=3`
  - `TIMESTAMP_VERIFY_PASS timestamp_hash=98fe3b506818487b29c62efccfd770a0c49bf95d91c3018084c4eb370475cf27`

## Known Instability Zones

- Runtime dashboard contract drift:
  - `tests/test_gateway_app.py::test_governance_runtime_demo_dashboard_routes_render_evidence`
  - `tests/test_live_pilot_v1.py::test_live_pilot_v1_verification_markers_all_pass`
  - `tests/test_live_pilot_v1.py::test_dashboard_boot_cannot_be_blank`
- Runtime health schema drift:
  - `tests/test_simulation_governance.py::test_health_reports_signed_policy_state`
  - `tests/test_simulation_governance.py::test_health_fails_closed_when_registry_invalid`
- Regenerated evidence export determinism:
  - Concurrent exports verify successfully, but generated manifest metadata differs in `timestamp_utc` and `timestamp_hash`.
  - This blocks deterministic evidence generation claims for freshly regenerated packs.

## Governance Survivability Conclusion

Persisted governance evidence, chain continuity, offline verifier behavior, timestamp verification, and ZIP checksum lineage survive prolonged regression pressure and concurrent read/verify stress.

The system is not survivability-clear for regenerated evidence exports. The timestamp lineage metadata is verification-valid but not byte-stable across fresh concurrent exports. Under USBAY fail-closed rules, regenerated evidence packs must be treated as `GOVERNANCE_SURVIVABILITY_BLOCKED` until timestamp acquisition and deterministic pack rendering are separated or sealed so metadata reproduces byte-for-byte.
