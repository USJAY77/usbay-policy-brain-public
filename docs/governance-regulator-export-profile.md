# Governance Regulator Export Profile Readiness

## Purpose

USBAY prepares governance evidence for future regulator-facing exports through deterministic local-only readiness profiles. The profile layer verifies existing governance evidence readiness artifacts and emits hash-only export planning records.

This module does not write external regulator exports, call external APIs, or export raw governance payloads.

## Supported Profile Types

- `EU_AI_ACT_AUDIT`
- `GDPR_ART32_SECURITY`
- `DORA_OPERATIONAL_RESILIENCE`
- `INTERNAL_GOVERNANCE_REVIEW`

## Required Evidence Bindings

`governance/regulator_export_profile.py` verifies and binds:

- sealed audit archive identity and archive root hash
- evidence record chain continuity
- WORM immutable storage readiness manifest
- TSA live verification readiness metadata
- hash-only policy decision metadata

The resulting profile references only hashes and deterministic identifiers. Export paths use local-only content-addressed notation:

```text
regulator-export://local-only/sha256/<profile_type>/<profile_id>
```

## Policy Decision Metadata

Policy decision metadata must remain hash-only and include:

- policy decision ID hash
- policy decision result
- policy hash
- policy version hash
- actor hash
- decision timestamp

Raw approval contents, raw requests, secrets, private keys, or runtime payloads are prohibited.

## Fail-Closed Conditions

Verification fails closed when:

- evidence chain continuity is missing
- sealed archive verification is missing
- WORM manifest verification is missing
- TSA metadata verification is missing
- policy decision metadata is missing or malformed
- export output paths are mutable
- evidence references are duplicated
- evidence entries are reordered
- raw payload leakage is detected
- diagnostics are unsafe or unredacted

## Future Integration Path

Future regulator export generation must consume this hash-only profile and preserve these fail-closed checks before any external transmission, portal upload, or customer/regulator package delivery is added in a separate governed capability branch.
