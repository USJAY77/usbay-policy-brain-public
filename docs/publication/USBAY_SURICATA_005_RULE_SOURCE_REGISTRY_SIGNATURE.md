# USBAY-SURICATA-005 Rule Source Registry & Signature Verification

## Purpose

USBAY-SURICATA-005 adds a local-only governance control for Suricata rule source acceptance. Policy Brain may only consume live-rule-derived Suricata evidence when the rule source is explicitly registered, human approved, fresh, not revoked, policy-version aligned, and signature-bound to the approved public key hash.

This control does not fetch rules, call a network, execute connectors, expose endpoints, publish artifacts, or store raw rule payloads.

## Rule Source Registry

The canonical source registry stores hash-only source metadata:

- `approved_source_id`
- `source_name`
- `source_uri_hash`
- `approved_public_key_hash`
- `approved_policy_version`
- `max_age_seconds`
- `revoked`
- `human_approval_id`
- `registry_hash`

The registry fails closed when the source is unknown, duplicated, revoked, unsigned, stale, malformed, missing approval, or bound to the wrong policy version.

## Signature Verification

The signature verifier accepts local rule bundle metadata only:

- `approved_source_id`
- `policy_version`
- `rule_bundle_hash`
- `public_key_hash`
- `signature_hash`
- `generated_at`
- `rule_count`

The verifier checks that:

- the source registry result is approved
- the source is not revoked
- the policy version matches
- the bundle timestamp is within `max_age_seconds`
- the public key hash matches the approved source key hash
- the signature hash matches the deterministic expected bundle/key/policy hash

The verifier emits only `evidence_hash`, policy version, source id, rule bundle hash, and reason code. It never stores raw rule content.

## Runtime Aggregator Binding

When Suricata evidence is present, the runtime aggregator requires:

- Suricata evidence adapter approval
- Suricata policy gate approval
- Suricata policy registry approval
- Suricata rule source signature approval

If `suricata_rule_source` is missing or rejected, the aggregator returns fail-closed `NETWORK_IDS_EVIDENCE_INVALID` and propagates only hash/version/reason evidence.

## Reason Codes

- `SURICATA_RULE_SOURCE_APPROVED`
- `SURICATA_RULE_SOURCE_UNKNOWN`
- `SURICATA_RULE_SOURCE_REVOKED`
- `SURICATA_RULE_SOURCE_DUPLICATE`
- `SURICATA_RULE_SOURCE_POLICY_MISMATCH`
- `SURICATA_RULE_SOURCE_REGISTRY_MALFORMED`
- `SURICATA_RULE_SOURCE_APPROVAL_MISSING`
- `SURICATA_RULE_SOURCE_STALE`
- `SURICATA_RULE_SOURCE_NOT_APPROVED`
- `SURICATA_RULE_SOURCE_MISSING`
- `SURICATA_RULE_SIGNATURE_APPROVED`
- `SURICATA_RULE_SIGNATURE_METADATA_MISSING`
- `SURICATA_RULE_SIGNATURE_METADATA_MALFORMED`
- `SURICATA_RULE_SIGNATURE_MISSING`
- `SURICATA_RULE_SIGNATURE_KEY_MISMATCH`
- `SURICATA_RULE_SIGNATURE_MISMATCH`

## Evidence Hygiene

All evidence is hash-only and redacted:

- no raw rule payloads
- no raw source URI
- no connector payloads
- no external API responses
- no live Suricata dependency

## Remaining Gaps

- No live rule source fetcher exists.
- No external signature authority integration exists.
- No connector or publication path is enabled.
- Human policy approval is represented by local approval identifiers only.

## Rollback

Remove the SURICATA-005 scoped files and revert the runtime aggregator Suricata rule-source binding.
