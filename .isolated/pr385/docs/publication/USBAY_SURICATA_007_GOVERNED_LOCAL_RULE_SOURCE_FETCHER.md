# USBAY-SURICATA-007 Governed Local Rule Source Fetcher

## Purpose

USBAY-SURICATA-007 implements a local-only Suricata rule source fetcher contract. The fetcher accepts approved local file paths only, binds the local rule bundle hash to approved source registry evidence and signature verification evidence, and emits hash-only runtime evidence.

No network fetch, HTTP endpoint, connector execution, publication path, or live Suricata dependency is enabled.

## Runtime Model

### LocalRuleSourceFetchRequest

- `source_id`
- `local_path`
- `registry_evidence_hash`
- `signature_evidence_hash`
- `policy_version`
- `requested_at`

The request redacts `local_path` in evidence by storing only a deterministic path hash.

### LocalRuleSourceFetchResult

- `approved`
- `blocked`
- `reason`
- `source_id`
- `rule_bundle_hash`
- `rule_bundle_size`
- `registry_evidence_hash`
- `signature_evidence_hash`
- `policy_version`
- `evidence_hash`

The result never contains raw rule contents.

## Fail-Closed Rules

The fetcher blocks when:

- request is missing or malformed
- path is a URL or network-like path
- path contains traversal
- file is missing
- path is not a file
- file is empty
- registry evidence is missing, malformed, mismatched, or not approved
- signature evidence is missing, malformed, mismatched, or not approved
- source id mismatches registry or signature proof
- policy version mismatches registry or signature proof
- local rule bundle hash mismatches signature metadata

## Runtime Aggregator Binding

Runtime aggregation preserves the existing SURICATA-001/002/003/005 path when live rule source mode is disabled.

When `suricata_live_rule_source_enabled` is true, the runtime aggregator requires `suricata_rule_source_fetcher.approved == True` before Suricata evidence can participate in publication readiness. Missing or rejected fetcher evidence returns fail-closed `NETWORK_IDS_EVIDENCE_INVALID`.

## Evidence Hygiene

Allowed evidence:

- source id
- rule bundle hash
- rule bundle size
- registry evidence hash
- signature evidence hash
- policy version
- reason code
- fetch evidence hash

Forbidden evidence:

- raw Suricata rules
- raw source URI
- credentials
- authorization headers
- connector payloads
- external response bodies
- live network metadata

## Validation Coverage

The focused SURICATA-007 tests cover:

- approved local source
- URL path rejection
- traversal rejection
- missing file rejection
- empty file rejection
- unapproved registry rejection
- invalid signature rejection
- policy mismatch rejection
- deterministic bundle hash
- deterministic fetch evidence hash
- raw rule content redaction
- live-mode aggregator block on missing fetcher evidence
- disabled-mode aggregator compatibility
- SURICATA-001/002/003/005 regression

## Remaining Gaps

- No live network fetcher exists.
- No external signing authority integration exists.
- No source rollback/replacement runtime flow exists.
- No production trust anchor store exists.

## Rollback

Remove the SURICATA-007 scoped files and revert the live-mode fetcher parameters from `publication/runtime_aggregator.py` and exports from `publication/__init__.py`.
