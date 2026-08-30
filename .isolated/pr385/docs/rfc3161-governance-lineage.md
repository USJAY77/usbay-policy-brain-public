# RFC3161 Governance Lineage

USBAY timestamp governance uses RFC3161-style evidence scaffolding to prove when governed evidence would be anchored to a trusted time source. This layer is test and policy scaffolding only. It does not introduce production TSA trust, signing keys, secrets, or network timestamp calls.

## Purpose

RFC3161 timestamping protects evidence chronology by binding a hash-only message imprint to externally governed time. USBAY policy requires timestamp evidence to validate before it can support governance lineage.

## Trusted Timestamp Governance

`governance/rfc3161_timestamp_policy.json` defines the allowed hash algorithms, required audit events, drift threshold, and trusted-time-source expectations. The current TSA authority is explicitly a placeholder and is marked `non_production_scaffolding=true`.

## Fail-Closed Semantics

Timestamp evidence fails closed when:

- the timestamp is missing
- the timestamp payload is malformed
- the hash algorithm is unsupported
- the timestamp is unsigned
- the authority is unknown
- required audit events are missing
- observed drift exceeds policy
- timestamp queues saturate

Every unsupported condition must produce explicit `FAIL_CLOSED` evidence with `silent_pass=false`.

## Drift Handling

The policy sets `timestamp_accuracy_seconds` to a bounded tolerance. Evidence outside that tolerance is rejected as `RFC3161_TIMESTAMP_CLOCK_DRIFT_EXCEEDED`; local clock trust alone is not sufficient for production timestamp authority.

## Audit Event Requirements

Required audit events are:

- `timestamp_requested`
- `timestamp_token_received`
- `timestamp_signature_verified`
- `timestamp_hash_matched`
- `timestamp_drift_checked`
- `timestamp_queue_pressure_checked`

## Queue Saturation Governance

Resilience tests simulate timestamp queue pressure under the `resilience`, `stress`, and `slow` markers. These tests run through the manual/scheduled governance resilience workflow and are intentionally excluded from fast PR checks.

## Future TSA/HSM Integration

Future production integration must replace placeholder authority evidence with validated TSA certificate chains, token signature verification, HSM-backed trust anchors where required, and regulator-exportable audit lineage. The placeholder policy must not be interpreted as production timestamp trust.
