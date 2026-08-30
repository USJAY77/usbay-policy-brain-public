# USBAY-SURICATA-008 Production Trust Anchor Store

## PASS/FAIL

PASS.

## Files Changed

- `publication/suricata_trust_anchor_store.py`
- `publication/runtime_aggregator.py`
- `publication/__init__.py`
- `tests/test_suricata_trust_anchor_store.py`
- `tests/test_suricata_evidence_adapter.py`
- `tests/test_suricata_policy_gate.py`
- `tests/test_suricata_policy_registry.py`
- `tests/test_suricata_rule_source_registry.py`
- `tests/test_suricata_rule_source_fetcher.py`
- `docs/publication/USBAY_SURICATA_008_PRODUCTION_TRUST_ANCHOR_STORE.md`

## Implementation Summary

USBAY-SURICATA-008 adds a local/offline Suricata production trust-anchor store. The store validates approved signing-key fingerprints before Suricata rule-source evidence can participate in runtime aggregation.

The trust anchor record includes:

- `anchor_id`
- `issuer`
- `public_key_fingerprint`
- `status`
- `approved_by_human`
- `policy_version`
- `created_at`
- `evidence_hash`

The runtime aggregator now requires approved trust-anchor evidence whenever Suricata evidence is provided. Missing or rejected trust anchors fail closed with `NETWORK_IDS_EVIDENCE_INVALID`.

## Tests Executed

- `python3.11 -m py_compile publication/*.py tests/test_suricata*.py` PASS
- `pytest -q tests/test_suricata*.py` PASS, 83 passed
- `pytest -q tests/test_publication_*.py tests/test_suricata*.py` PASS, 282 passed
- `git diff --check` PASS

## Coverage Summary

Covered fail-closed cases:

- anchor missing
- anchor revoked
- missing human approval
- fingerprint mismatch
- policy version mismatch
- malformed anchor
- missing evidence hash
- runtime aggregator missing trust anchor
- runtime aggregator rejected trust anchor

Covered positive cases:

- valid anchor approval
- deterministic trust-anchor evidence hash
- runtime aggregator allows Suricata evidence only with trust-anchor evidence
- final report excludes public key material and raw rule payloads

## Remaining Gaps

- No live network fetcher.
- No external signing authority integration.
- No source rollback/replacement runtime flow.
- No connector/API/publication path enabled.

## Rollback Command

```bash
rm -f publication/suricata_trust_anchor_store.py tests/test_suricata_trust_anchor_store.py docs/publication/USBAY_SURICATA_008_PRODUCTION_TRUST_ANCHOR_STORE.md
```

Then revert only the SURICATA-008 trust-anchor parameter/export/test-helper edits in `publication/runtime_aggregator.py`, `publication/__init__.py`, and existing `tests/test_suricata*.py` files.
