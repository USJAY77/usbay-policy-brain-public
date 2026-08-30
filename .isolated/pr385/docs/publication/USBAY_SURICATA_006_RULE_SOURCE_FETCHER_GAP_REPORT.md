# USBAY-SURICATA-006 Rule Source Fetcher Gap Report

## Scope

This is a report-only implementation plan for a future local-governed Suricata rule source fetcher. No live fetcher, network call, connector, endpoint, publication path, or rule payload storage is implemented by this report.

## Evidence Reviewed

- `publication/suricata_evidence_adapter.py`
- `publication/suricata_policy_gate.py`
- `publication/suricata_policy_registry.py`
- `publication/suricata_rule_source_registry.py`
- `publication/suricata_rule_signature.py`
- `publication/runtime_aggregator.py`
- `tests/test_suricata_evidence_adapter.py`
- `tests/test_suricata_policy_gate.py`
- `tests/test_suricata_policy_registry.py`
- `tests/test_suricata_rule_source_registry.py`
- `docs/publication/USBAY_SURICATA_004_LIVE_RULE_SOURCE_GAP_REPORT.md`
- `docs/publication/USBAY_SURICATA_005_RULE_SOURCE_REGISTRY_SIGNATURE.md`

## Current State

USBAY now has a local-only Suricata governance chain:

1. `SURICATA-001` parses caller-provided EVE JSON, redacts sensitive fields, and emits hash-only evidence.
2. `SURICATA-002` evaluates severity against a policy-defined threshold.
3. `SURICATA-003` validates a human-approved Suricata policy registry record.
4. `SURICATA-004` documented the live rule-source ingestion gap.
5. `SURICATA-005` added a local source registry and signature verification requirement before Suricata evidence can participate in runtime aggregation.

The remaining gap is a governed fetcher design. USBAY still does not fetch rule bundles from any live source. This is correct and fail-closed until fetcher controls exist.

## Approved Source Allowlist Model

The future fetcher must consume only source records already approved by `SuricataRuleSourceRegistry`.

Required source controls:

- source identity must be referenced by `approved_source_id`
- source URI must remain hash-only in evidence as `source_uri_hash`
- approved signing key must be referenced only as `approved_public_key_hash`
- source policy version must match the active Suricata policy version
- source must have a non-empty `human_approval_id`
- source must not be revoked
- duplicate source ids must block

Fetcher input must never include raw credentials, raw source URLs with tokens, or private transport headers in audit output.

## Source Freshness Policy

The future fetcher must enforce two freshness windows:

- source approval freshness from `SuricataRuleSourceRecord.max_age_seconds`
- fetched bundle metadata freshness from `SuricataRuleBundleMetadata.generated_at`

Fail closed when:

- source approval is stale
- bundle timestamp is stale
- bundle timestamp is in the future
- timestamp format is invalid
- fetch receipt timestamp is missing
- source registry policy version differs from bundle policy version

Freshness evidence must be hash-only and deterministic.

## Source Revocation Policy

Revocation is authoritative at the source registry boundary.

The fetcher must block:

- source record with `revoked = true`
- previously fetched bundle whose source is later revoked
- bundle whose signing key hash no longer matches the approved source key
- source id that is missing from the current allowlist
- source id that appears more than once

Revocation evidence must include only:

- source id
- registry hash
- policy version
- revocation reason code
- evidence hash

## Signature Verification Sequence

The implementation batch must execute this sequence before any rule bundle can become registry-eligible:

1. Load source allowlist record.
2. Validate source with `SuricataRuleSourceRegistry.validate_source`.
3. Accept local fetch receipt metadata only.
4. Calculate local rule bundle hash without storing raw rule payload in audit evidence.
5. Build `SuricataRuleBundleMetadata`.
6. Verify metadata with `verify_suricata_rule_signature`.
7. Bind the signature evidence hash to the Suricata policy registry record.
8. Pass only hash/version/reason evidence to `RuntimeAggregator`.

If any step is missing, malformed, stale, mismatched, or revoked, the fetcher must return BLOCK.

## Source-To-Registry Binding

The future fetcher must produce a source-to-registry binding artifact containing:

- `approved_source_id`
- `source_registry_hash`
- `source_signature_evidence_hash`
- `rule_bundle_hash`
- `policy_id`
- `policy_version`
- `rule_count`
- `registry_evidence_hash`
- `binding_evidence_hash`

`SuricataPolicyRegistry` must reject registry records that cannot prove this binding.

`RuntimeAggregator` must continue to require:

- accepted Suricata EVE evidence
- approved Suricata threshold gate
- approved Suricata policy registry
- approved Suricata rule source signature

## Sensitive Data Redaction Model

Fetcher evidence must not persist:

- raw rule payload
- raw source URI
- credentials
- authorization headers
- cookies
- API keys
- tokens
- private hostnames
- internal repository paths
- customer identifiers
- connector response bodies

Allowed evidence:

- source id
- source URI hash
- public key hash
- bundle hash
- signature hash
- registry hash
- policy version
- timestamp hashes or normalized timestamps where not sensitive
- reason codes

## Fail-Closed States

The implementation batch should define these states:

- `SURICATA_RULE_FETCHER_NOT_IMPLEMENTED`
- `SURICATA_RULE_FETCH_SOURCE_UNKNOWN`
- `SURICATA_RULE_FETCH_SOURCE_REVOKED`
- `SURICATA_RULE_FETCH_SOURCE_STALE`
- `SURICATA_RULE_FETCH_SOURCE_POLICY_MISMATCH`
- `SURICATA_RULE_FETCH_SIGNATURE_MISSING`
- `SURICATA_RULE_FETCH_SIGNATURE_MISMATCH`
- `SURICATA_RULE_FETCH_KEY_MISMATCH`
- `SURICATA_RULE_FETCH_BUNDLE_HASH_MISSING`
- `SURICATA_RULE_FETCH_BUNDLE_HASH_MISMATCH`
- `SURICATA_RULE_FETCH_RAW_PAYLOAD_DETECTED`
- `SURICATA_RULE_FETCH_BINDING_MISSING`
- `SURICATA_RULE_FETCH_BINDING_MISMATCH`
- `SURICATA_RULE_FETCH_HUMAN_APPROVAL_MISSING`
- `SURICATA_RULE_FETCH_UNSAFE_METADATA`

Unknown state must be treated as blocked.

## Exact Files To Modify In Implementation Batch 007

Expected new files:

- `publication/suricata_rule_fetcher.py`
- `tests/test_suricata_rule_fetcher.py`
- `docs/publication/USBAY_SURICATA_007_RULE_SOURCE_FETCHER.md`

Expected updates:

- `publication/suricata_policy_registry.py`
- `publication/suricata_rule_signature.py`
- `publication/runtime_aggregator.py`
- `publication/__init__.py`
- `tests/test_suricata_policy_registry.py`
- `tests/test_suricata_rule_source_registry.py`

Files that must not be modified in batch 007:

- Gateway files
- Replit files
- Simulator files
- Game files
- connector/API endpoint files
- publication connector execution files

## Validation Plan

Required checks:

```bash
python3.11 -m py_compile publication/*.py tests/test_suricata*.py
pytest -q tests/test_suricata*.py
git diff --check
```

Required test coverage:

- approved source fetch metadata passes
- unknown source blocks
- revoked source blocks
- stale source blocks
- missing human approval blocks
- policy version mismatch blocks
- missing signature blocks
- signature mismatch blocks
- key hash mismatch blocks
- bundle hash mismatch blocks
- raw payload in evidence blocks
- source-to-registry binding missing blocks
- source-to-registry binding mismatch blocks
- deterministic fetch evidence hash
- deterministic binding hash
- runtime aggregator blocks missing fetcher evidence when live-rule-derived evidence is requested
- runtime aggregator allows only after source, signature, registry, gate, and EVE evidence all pass

## Rollback Plan

For this report-only batch:

```bash
rm -f docs/publication/USBAY_SURICATA_006_RULE_SOURCE_FETCHER_GAP_REPORT.md
```

For future batch 007 rollback, remove the fetcher-specific files and carefully revert any shared Suricata integration edits without removing SURICATA-001 through SURICATA-005 controls.

## Remaining Gaps

- No live fetcher exists.
- No source-to-registry binding runtime object exists.
- No fetch receipt model exists.
- No rule bundle hash calculation flow exists.
- No fetcher redaction test exists.
- No rollback path for fetched bundle replacement exists.
- No external trust anchor integration exists.

## Next Recommended Batch

`USBAY-SURICATA-007 — Governed Local Rule Source Fetcher`

Recommended scope:

- local-only fetch receipt model
- no network implementation by default
- deterministic bundle hash verification
- source-to-registry binding evidence
- fetcher redaction guard
- RuntimeAggregator binding for live-rule-derived evidence
- fail-closed tests for every missing, stale, revoked, unsigned, or mismatched fetcher artifact
