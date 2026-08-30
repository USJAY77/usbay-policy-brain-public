# USBAY-SURICATA-011 Fetch Receipt Model

## PASS/FAIL

PASS.

## Files Changed

- `publication/suricata_fetch_receipt.py`
- `publication/runtime_aggregator.py`
- `publication/__init__.py`
- `tests/test_suricata_fetch_receipt.py`
- `tests/test_suricata_rule_source_fetcher.py`
- `docs/publication/USBAY_SURICATA_011_FETCH_RECEIPT_MODEL.md`

## Implementation Summary

USBAY-SURICATA-011 adds a governed local fetch receipt model. The receipt is metadata-only and hash-only. It does not fetch live network sources, call connectors, expose endpoints, publish artifacts, or include raw Suricata rule payloads.

The receipt includes:

- `source_id`
- `source_registry_hash`
- `rule_bundle_hash`
- `trust_anchor_hash`
- `fetched_at`
- `freshness_window_seconds`
- `human_approval_id`
- `fetch_receipt_hash`

Runtime aggregation requires an approved fetch receipt when `suricata_live_rule_source_enabled` is true.

## Fail-Closed Coverage

The validator blocks when:

- `source_id` is missing
- registry hash is missing or invalid
- rule bundle hash is missing or invalid
- trust anchor hash is missing or invalid
- `fetched_at` is stale, future-dated, missing, or malformed
- human approval is missing
- receipt is malformed
- `fetch_receipt_hash` is missing or mismatched

## Tests Run

- `python3.11 -m py_compile publication/*.py tests/test_suricata*.py` PASS
- `pytest -q tests/test_suricata*.py` PASS
- `git diff --check` PASS

## Remaining Gaps

- No live network fetcher.
- No external signing authority integration.
- No source rollback/replacement runtime flow.
- No connector/API/publication path enabled.

## Rollback Command

```bash
rm -f publication/suricata_fetch_receipt.py tests/test_suricata_fetch_receipt.py docs/publication/USBAY_SURICATA_011_FETCH_RECEIPT_MODEL.md
```

Then revert only the SURICATA-011 receipt parameter/export/test-helper edits in `publication/runtime_aggregator.py`, `publication/__init__.py`, and `tests/test_suricata_rule_source_fetcher.py`.
