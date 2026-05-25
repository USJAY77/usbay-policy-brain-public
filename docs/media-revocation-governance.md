# Media Revocation Governance

This document describes non-production USBAY scaffolding for revocation and emergency freeze governance after AI media release and distribution authorization. It does not add real takedown APIs, distributor integrations, OAuth tokens, network calls, production signing, or runtime enforcement changes.

## Emergency Freeze Semantics

Emergency freeze is a hard override. If a media asset enters `EMERGENCY_FROZEN`, distribution fails closed even if earlier governance checks passed.

## Post-Release Governance

USBAY release governance continues after `VERIFIED_RELEASE` and `DISTRIBUTION_AUTHORIZED`. A release token, rights/consent record, or distribution authority can become revoked or expired, and that state blocks publication.

## Takedown Governance

`PLATFORM_TAKEDOWN_REQUIRED` represents a governed post-release state requiring human takedown review. The scaffold does not call platform APIs; it proves the governance decision blocks publication until humans resolve the takedown path.

## Dispute Handling

`LEGAL_DISPUTE_HOLD` blocks distribution when rights, consent, ownership, performer, sample, or platform publication authority is disputed. AI cannot bypass this state or infer clearance.

## Revocation Lineage

Revocation evidence is separate from initial release evidence. It must remain traceable to the same `media_asset_id`, distribution authority, release token, and rights/consent lineage.

## Fail-Closed Revocation Behavior

Distribution fails closed when:

- a release token is revoked
- a media asset is emergency frozen
- rights or consent are revoked
- distribution authority is revoked or expired
- a legal dispute hold exists
- platform takedown is required

Every unsupported condition returns explicit `FAIL_CLOSED` evidence with `silent_pass=false`.

## Future Platform/CDN Freeze Integrations

Future integrations must use governed credentials, scoped platform policies, signed revocation requests, append-only evidence, human approval, and isolated secret handling. This scaffold is not production authority and does not certify takedown execution.
