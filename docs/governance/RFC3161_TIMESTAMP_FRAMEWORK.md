# RFC3161 Trusted Timestamp Framework

Purpose: define a trusted timestamp framework that attaches RFC3161-compatible timestamp metadata to evidence packages, validation results, review decisions, export bundles, and audit lineage records.

Runtime impact: none.

AWS resource creation: none.

Provider credentials stored in repository: prohibited.

Certification claim: prohibited.

Blocker status change: prohibited.

Default decision: BLOCKED.

## Framework Files

Timestamp framework files:

- `governance/timestamps/timestamp_schema.json`
- `governance/timestamps/timestamp_example.json`
- `governance/timestamps/timestamp_relationships.md`
- `scripts/verify_timestamp_chain.py`

## Timestamp Record Schema

Every timestamp record must include:

- Timestamp record ID.
- Timestamp subject type.
- Timestamp subject ID.
- Timestamp subject path.
- Timestamp subject SHA256.
- RFC3161 token SHA256.
- TSA policy identifier.
- TSA certificate SHA256.
- Timestamp UTC value.
- Previous timestamp record SHA256.
- Current timestamp record SHA256.
- Decision.

## Timestamp Chain Validation

Timestamp chain validation verifies:

- Required timestamp records exist.
- Required subject types exist.
- Timestamp subject paths exist.
- Timestamp values parse as UTC-compatible timestamps.
- Required hashes are valid SHA256 strings.
- Previous/current timestamp record hashes preserve continuity.
- Required relationships exist.

## Evidence Timestamp Linkage

Evidence package timestamp records bind:

- Evidence package path.
- Evidence package hash.
- RFC3161 token hash.
- Timestamp UTC value.

## Review Timestamp Linkage

Review timestamp records bind:

- Review decision path.
- Review decision hash.
- Reviewer reference.
- RFC3161 token hash.
- Timestamp UTC value.

## Export Timestamp Linkage

Export timestamp records bind:

- Export bundle path.
- Export bundle hash.
- Bundle verification result.
- RFC3161 token hash.
- Timestamp UTC value.

## Audit Lineage Timestamp Linkage

Audit lineage timestamp records bind:

- Audit lineage path.
- Audit lineage hash.
- Previous timestamp record hash.
- Current timestamp record hash.
- RFC3161 token hash.

## Missing And Invalid Timestamp Detection

Missing timestamp detection emits:

```text
TIMESTAMP_MISSING
```

Invalid timestamp detection emits:

```text
TIMESTAMP_INVALID
```

Incomplete chain detection emits:

```text
TIMESTAMP_CHAIN_INCOMPLETE
```

## Fail-Closed Verification

Run:

```text
python3 scripts/verify_timestamp_chain.py
```

Placeholder expected result:

```text
Decision = BLOCKED
TIMESTAMP_MISSING
TIMESTAMP_INVALID
TIMESTAMP_CHAIN_INCOMPLETE
```

Timestamp verification passes only when all required timestamp records, relationships, hashes, subject paths, and chain continuity values exist and verify.

This framework does not call a TSA.

This framework does not create certification claims.

This framework does not change blocker status.

## Canonical Runtime Timestamp Authority

Canonical owner: `governance.rfc3161_timestamp`

Provider and adapter roles:

- `governance.proof_timestamp_anchor`: provider
- `governance.timestamping`: adapter
- `scripts.verify_timestamp_chain`: adapter
- `scripts.pb008_timestamp_verifier`: deprecated provider

Production readiness must consume the canonical owner through `timestamp_chain_readiness_report`. Missing, invalid, or continuity-broken timestamp chains fail closed.
