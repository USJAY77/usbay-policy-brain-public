# USBAY-SURICATA-012 Fetch Receipt Finalizer

## PASS/FAIL

PASS.

## Files Changed

- `publication/suricata_fetch_receipt_finalizer.py`
- `publication/runtime_aggregator.py`
- `publication/__init__.py`
- `tests/test_suricata_fetch_receipt_finalizer.py`
- `tests/test_suricata_fetch_receipt.py`
- `tests/test_suricata_rule_source_fetcher.py`
- `docs/publication/USBAY_SURICATA_012_FETCH_RECEIPT_FINALIZER.md`

## Implementation Summary

USBAY-SURICATA-012 adds a final fail-closed Suricata live-mode proof that binds:

- approved rule-source registry evidence
- approved source signature evidence
- approved trust-anchor evidence
- approved trust-anchor finalizer evidence
- valid fetch receipt evidence
- approved local rule-source fetch evidence
- matching `rule_bundle_hash`
- matching source id
- matching policy version

RuntimeAggregator live-mode Suricata evidence now requires `final_suricata_fetch_hash` before allowing the Suricata chain to proceed.

## Evidence Propagation

Only hash-only evidence is propagated:

- `final_suricata_fetch_hash`
- `source_registry_hash`
- `signature_evidence_hash`
- `trust_anchor_hash`
- `fetch_receipt_hash`
- `local_fetch_hash`
- `policy_version`
- `decision`
- `reason`

Raw Suricata rules, raw EVE JSON, source URIs, IPs, domains, usernames, payloads, and user agents are not propagated.

## Tests Run

- `python3.11 -m py_compile publication/*.py tests/test_suricata*.py` PASS
- `pytest -q tests/test_suricata*.py` PASS, 108 passed
- `pytest -q tests/test_publication_*.py tests/test_suricata*.py` PASS, 307 passed
- `git diff --check` PASS

## Remaining Gaps

- No live network fetcher.
- No external signing authority integration.
- No source rollback/replacement runtime flow.
- No connector/API/publication path enabled.

## Rollback Command

```bash
rm -f publication/suricata_fetch_receipt_finalizer.py tests/test_suricata_fetch_receipt_finalizer.py docs/publication/USBAY_SURICATA_012_FETCH_RECEIPT_FINALIZER.md
```

Then revert only the SURICATA-012 finalizer parameter/export/test-helper edits in `publication/runtime_aggregator.py`, `publication/__init__.py`, `tests/test_suricata_fetch_receipt.py`, and `tests/test_suricata_rule_source_fetcher.py`.
