# Media Audit Export Governance

This document describes non-production USBAY scaffolding for regulator and external audit evidence exports across the AI media lifecycle. It does not add real regulator integrations, network calls, OAuth tokens, legal contracts, raw media, or runtime enforcement changes.

## Regulator Export Governance

Audit exports are allowed only when they are governed by explicit scope, approval lineage, timestamp lineage, provenance lineage, distribution lineage, and revocation state. The export manifest is signed with a placeholder-only scaffold marker and is not production authority.

## Privacy-Safe Audit Exports

Exports must contain references only. They must not include raw media, audio, video, voice samples, scripts, lyrics, legal contracts, OAuth tokens, personal data, or copyrighted payloads.

## Evidence-Reference Exports

`artifacts/media-audit-export-manifest.json` references:

- media provenance evidence
- approval-chain evidence
- timestamp policy evidence
- distribution gateway evidence
- revocation policy evidence

The manifest is non-production and hash/reference oriented.

## Fail-Closed Export Semantics

Exports fail closed when:

- export scope is missing or unapproved
- audit lineage is incomplete
- the export manifest is unsigned
- sensitive payload markers are detected
- fail-closed flags are missing or disabled

Every unsupported condition returns explicit `FAIL_CLOSED` evidence with `silent_pass=false`.

## Export Lineage

Export lineage must remain reconstructable from references to the same `media_asset_id`. Export evidence should show the decision chain without copying underlying media payloads.

## Future ETSI/RFC3161 Compatibility

Future regulator export work can attach ETSI-compatible evidence containers and RFC3161 timestamp proofs to the export manifest while still timestamping hashes and references rather than raw payloads.

## Future Regulator Integration Path

Future integrations must use governed credentials, human-approved export scopes, isolated secret handling, append-only audit records, and regulator-specific export schemas. This scaffold is not a production regulator connector and does not certify submission to any authority.
