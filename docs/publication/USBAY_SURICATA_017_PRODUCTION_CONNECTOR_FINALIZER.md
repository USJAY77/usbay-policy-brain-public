# USBAY-SURICATA-017 Production Connector Finalizer

## Status

Runtime/local implementation only. No live production endpoint is enabled by default.

## Controls Added

- Production Gateway endpoint configuration is explicit and disabled by default.
- Connector approval requires endpoint URL, policy version, evidence hash binding, HTTPS, allowlist membership, TLS verification, and certificate fingerprint validation.
- Persistent local nonce-store abstraction rejects replayed nonces and stale timestamps.
- Trust-provider configuration gate requires configured and human-approved CA/KMS/HSM metadata before a connector can approve.
- RuntimeAggregator blocks missing, rejected, or malformed connector evidence.

## Hash-Only Evidence

Final connector evidence exposes hashes, policy version, trust fingerprint hash, decision, reason, timestamp, nonce, and connector version. It does not expose raw Suricata EVE JSON, raw rules, source URLs, IP addresses, domains, payloads, usernames, user agents, certificates, private keys, or secrets.

## Fail-Closed Paths

- Missing endpoint: BLOCK
- Connector disabled: BLOCK
- Unapproved endpoint: BLOCK
- Missing trust provider: BLOCK
- Missing human trust-provider approval: BLOCK
- Replayed nonce: BLOCK
- Stale timestamp: BLOCK
- Malformed connector evidence: BLOCK

## Validation

Required commands:

```bash
python3.11 -m py_compile publication/*.py tests/test_suricata*.py
pytest -q tests/test_suricata*.py
pytest -q tests/test_publication_*.py tests/test_suricata*.py
git diff --check
```

## Remaining Gaps

- No production endpoint is configured.
- No real external network calls are made in tests.
- No live connector/API/publication path is enabled by default.
- CA/KMS/HSM trust-provider evidence is modeled locally and must be connected to production governance before live use.

## Rollback

```bash
git restore publication/suricata_publication_connector.py publication/runtime_aggregator.py publication/__init__.py tests/test_suricata_publication_connector.py tests/test_suricata_live_fetcher_gate.py tests/test_suricata_source_replacement_flow.py docs/publication/USBAY_SURICATA_017_PRODUCTION_CONNECTOR_FINALIZER.md
```
