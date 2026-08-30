# USBAY-SURICATA-010 Live Fetcher Governance Plan

## PASS/FAIL

PASS.

## Purpose

USBAY-SURICATA-010 defines the governed live-network fetcher controls required before USBAY may fetch Suricata rule bundles from live sources. This is a plan only. It does not enable network fetching, connectors, endpoints, publication paths, or external signing authority integration.

## Existing Evidence Reviewed

- `USBAY-SURICATA-001`: local Suricata EVE evidence adapter with redaction and hash-only evidence.
- `USBAY-SURICATA-002`: severity threshold policy gate.
- `USBAY-SURICATA-003`: local Suricata policy registry.
- `USBAY-SURICATA-004`: live rule source gap report.
- `USBAY-SURICATA-005`: local rule-source registry and signature verification.
- `USBAY-SURICATA-006`: rule source fetcher gap report.
- `USBAY-SURICATA-007`: governed local rule source fetcher.
- `USBAY-SURICATA-008`: local/offline production trust-anchor store.
- `USBAY-SURICATA-009`: trust-anchor finalizer.

Current RuntimeAggregator Suricata gating requires:

1. Suricata EVE adapter PASS
2. threshold policy PASS
3. policy registry approval PASS
4. rule-source signature PASS
5. trust-anchor validation PASS
6. trust-anchor finalizer PASS
7. local rule-source fetcher PASS only when live-rule-source mode is explicitly enabled

## Required Live Fetcher Controls

### Approved Source Allowlist

Live fetch must only begin after source identity is present in the approved source allowlist. Required fields:

- `approved_source_id`
- `source_name`
- `source_uri_hash`
- `approved_public_key_hash`
- `approved_policy_version`
- `max_age_seconds`
- `revoked`
- `human_approval_id`
- `registry_hash`

Fail closed when source is unknown, duplicate, revoked, missing human approval, malformed, or policy-version mismatched.

### Source Signature Verification

Every fetched rule bundle must produce local metadata before policy registry use:

- `approved_source_id`
- `policy_version`
- `rule_bundle_hash`
- `signature_hash`
- `public_key_fingerprint_hash`
- `generated_at`
- `rule_count`

Unsigned bundles, signature mismatch, key mismatch, malformed metadata, and missing metadata must block.

### Trust-Anchor Binding

The signing key fingerprint must bind to the local/offline trust-anchor finalizer. Required evidence:

- `trust_anchor_id`
- `policy_version`
- `fingerprint_hash`
- `approval_hash`
- `trust_anchor_evidence_hash`
- `finalizer_decision`
- `finalizer_reason`

Fail closed when trust anchor is missing, revoked, malformed, missing human approval, fingerprint-mismatched, policy-mismatched, or finalizer-missing.

### Rule Bundle Hash

The live fetcher must hash the fetched bytes locally and store only:

- `rule_bundle_hash`
- `rule_bundle_size`
- `source_id`
- `policy_version`
- `signature_evidence_hash`
- `trust_anchor_finalizer_hash`

Raw rule payload must never appear in reports, logs, runtime aggregation evidence, or final reports.

### Fetch Receipt Hash

A future fetch receipt must be deterministic and hash-only:

- `fetch_receipt_id`
- `source_id`
- `source_uri_hash`
- `requested_at`
- `completed_at`
- `rule_bundle_hash`
- `signature_evidence_hash`
- `trust_anchor_finalizer_hash`
- `policy_version`
- `fetch_receipt_hash`

Fail closed when receipt is missing, malformed, stale, unordered, duplicated, or mismatched.

### Rollback / Replacement Receipt

Rule bundle replacement must create a separate rollback/replacement receipt:

- `previous_rule_bundle_hash`
- `replacement_rule_bundle_hash`
- `rollback_owner`
- `rollback_reason`
- `rollback_approved_by_human`
- `rollback_receipt_hash`
- `policy_version`

Fail closed when rollback evidence is missing, approval is absent, prior hash cannot be proven, or replacement hash cannot be bound to source/signature/trust-anchor evidence.

### Freshness Window

The live fetcher must enforce:

- source allowlist `max_age_seconds`
- bundle `generated_at`
- fetch receipt `completed_at`
- signature freshness
- trust-anchor policy version freshness

Fail closed on stale, future-dated, missing, or unparsable timestamps.

### Human Approval Metadata

Human approval remains mandatory and must be represented as hash-only metadata:

- `human_approval_id`
- `approval_hash`
- `approved_by_human`
- `policy_version`

Owner self-approval and missing human approval must block.

## Fail-Closed States

The implementation batch should define these reason codes:

- `SURICATA_LIVE_FETCH_DISABLED`
- `SURICATA_LIVE_FETCH_SOURCE_UNKNOWN`
- `SURICATA_LIVE_FETCH_SOURCE_REVOKED`
- `SURICATA_LIVE_FETCH_SOURCE_MALFORMED`
- `SURICATA_LIVE_FETCH_SIGNATURE_MISSING`
- `SURICATA_LIVE_FETCH_SIGNATURE_MISMATCH`
- `SURICATA_LIVE_FETCH_TRUST_ANCHOR_MISSING`
- `SURICATA_LIVE_FETCH_TRUST_ANCHOR_REVOKED`
- `SURICATA_LIVE_FETCH_TRUST_ANCHOR_FINALIZER_MISSING`
- `SURICATA_LIVE_FETCH_BUNDLE_HASH_MISSING`
- `SURICATA_LIVE_FETCH_BUNDLE_HASH_MISMATCH`
- `SURICATA_LIVE_FETCH_RECEIPT_MISSING`
- `SURICATA_LIVE_FETCH_RECEIPT_MALFORMED`
- `SURICATA_LIVE_FETCH_RECEIPT_STALE`
- `SURICATA_LIVE_FETCH_ROLLBACK_RECEIPT_MISSING`
- `SURICATA_LIVE_FETCH_HUMAN_APPROVAL_MISSING`
- `SURICATA_LIVE_FETCH_RAW_PAYLOAD_DETECTED`
- `SURICATA_LIVE_FETCH_POLICY_MISMATCH`

Unknown state must block.

## Safe Local Test Plan

Tests may be added only with local mocked fetch receipts. No network calls are permitted.

Required local test cases:

- mocked fetch receipt valid PASS
- malformed fetch receipt BLOCK
- stale fetch receipt BLOCK
- unsigned bundle BLOCK
- signature mismatch BLOCK
- trust-anchor finalizer missing BLOCK
- raw rule payload in report BLOCK
- rollback receipt missing BLOCK when replacing an existing bundle
- approved mocked bundle PASS

## Files For Future Implementation Batch

Expected new files:

- `publication/suricata_live_fetch_receipt.py`
- `tests/test_suricata_live_fetch_receipt.py`
- `docs/publication/USBAY_SURICATA_011_LIVE_FETCH_RECEIPT.md`

Expected updates:

- `publication/suricata_rule_source_fetcher.py`
- `publication/runtime_aggregator.py`
- `publication/__init__.py`
- `tests/test_suricata_rule_source_fetcher.py`
- `tests/test_suricata_trust_anchor_store.py`

Files that must not be modified:

- Gateway files
- Replit files
- Simulator files
- Game files
- connector/API endpoint files
- publication connector execution files

## Files Changed In This Batch

- `docs/publication/USBAY_SURICATA_010_LIVE_FETCHER_GOVERNANCE_PLAN.md`

## Tests Executed

- `python3.11 -m py_compile publication/*.py tests/test_suricata*.py` PASS
- `pytest -q tests/test_suricata*.py` PASS
- `git diff --check` PASS

## Remaining Gaps

- No live network fetcher enabled.
- No external signing authority.
- No production trust-anchor store. Current implementation is local/offline only; no external operational trust-anchor authority or backing store is enabled.
- No rollback/replacement runtime flow.
- No connector/API/publication path.

## Rollback Command

```bash
rm -f docs/publication/USBAY_SURICATA_010_LIVE_FETCHER_GOVERNANCE_PLAN.md
```
