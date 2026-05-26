# Media Distribution Governance

This document describes non-production USBAY scaffolding for governing AI media distribution to platforms and distributors. It does not add real integrations, distributor credentials, OAuth tokens, network calls, production signing, or runtime enforcement changes.

## Release Authorization Chain

Distribution is allowed only after the media release chain is complete:

- provenance hash evidence
- human approval chain
- RFC3161-style timestamp evidence
- rights and consent evidence
- governed release token
- distributor/platform authorization

`VERIFIED_RELEASE` is not enough by itself. Platform publication requires a separate distribution authorization bound to the same `media_asset_id` and target platform.

## Distributor And Platform Governance

`governance/media_distribution_gateway_policy.json` defines placeholder platform scopes:

- `spotify`
- `youtube`
- `netflix`
- `broadcaster_internal`
- `studio_archive`

These names are test scaffolding only. They do not represent active platform integrations or permissions.

## Fail-Closed Distribution Semantics

USBAY distribution governance fails closed when:

- the platform is unknown
- distribution authority is missing
- platform scope does not match
- the distribution request is unsigned
- release-token binding is missing
- approval, timestamp, provenance, or rights/consent bindings are missing

Every unsupported condition returns explicit `FAIL_CLOSED` evidence with `silent_pass=false`.

## Platform Scope Validation

Distribution evidence must bind the request to the same platform selected by the publisher. A token scoped for `youtube` cannot authorize publication to `spotify`; mismatches are rejected before publication.

## Future Integration Path

Future CDN, distributor, or platform integrations must replace placeholder authority with governed credentials, signed requests, scoped platform policies, regulator-exportable audit records, and human approval gates. Network access and platform secrets must remain isolated from untrusted execution contexts.

## Non-Production Disclaimer

This layer is documentation and test scaffolding. It must not be treated as production release authority, platform certification, distributor approval, or evidence of successful publication.
