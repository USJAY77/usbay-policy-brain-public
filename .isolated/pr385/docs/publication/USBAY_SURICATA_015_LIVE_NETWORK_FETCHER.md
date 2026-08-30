# USBAY-SURICATA-015 Live Network Fetcher

## Purpose

USBAY-SURICATA-015 adds the first governed production-capable live Suricata EVE JSON fetch layer. The implementation remains fail-closed and does not bypass Policy Brain governance. Tests use injected local transports; no validation run requires live network access.

## Trust Chain

Live Suricata evidence may proceed only when all required governance evidence is approved:

- approved source registry
- valid rule-source signature
- valid trust anchor
- approved external signing authority
- valid fetch receipt
- approved source replacement flow
- approved live-fetcher gate
- approved live network fetch result
- Suricata policy gate PASS

RuntimeAggregator blocks live mode when any required proof is missing, rejected, stale, malformed, mismatched, or policy-inconsistent.

## Certificate Validation

The live fetcher requires:

- HTTPS source URL
- `tls_required: true`
- `verify_certificate: true`
- certificate validity proof
- non-expired certificate
- non-self-signed certificate
- hostname match
- certificate fingerprint match against the approved trust anchor

Certificate failures produce fail-closed decisions and hash-only evidence.

## Allowlist

The fetcher accepts only source URLs that exactly match `suricata_live_fetch.allowlist`. HTTP endpoints, unknown HTTPS URLs, network-like bypasses, and disabled configurations block before transport execution can produce an allow decision.

## Failure Paths

The fetcher blocks on:

- live fetch disabled
- HTTP endpoint
- source not allowlisted
- invalid timeout, retry, or payload policy
- missing or invalid trust anchor
- missing or invalid fetch receipt
- missing or invalid replacement flow
- missing or invalid live-fetcher gate
- policy version mismatch
- timeout
- fetch failure
- non-200 status
- expired certificate
- self-signed certificate
- hostname mismatch
- certificate fingerprint mismatch
- empty or oversized payload
- malformed JSON
- unexpected schema
- failed Suricata redaction or parsing

## Audit Evidence

The fetcher emits deterministic hash-only evidence:

- evidence hash
- bundle hash derived from redacted EVE JSON
- timestamp
- policy version
- trust-anchor fingerprint hash
- fetch receipt id
- source URL hash
- decision
- reason

Runtime reports may expose only evidence hash, bundle hash, timestamp, policy version, trust fingerprint, decision, and reason.

## Privacy Model

Final reports must never expose:

- raw EVE JSON
- raw payloads
- IP addresses
- domains
- hostnames
- usernames
- user agents
- source URLs
- rule contents

Source URLs are represented only by deterministic hashes. EVE JSON is redacted before evidence hashing.

## Validation Commands

- `python3.11 -m py_compile publication/*.py tests/test_suricata*.py`
- `pytest -q tests/test_suricata*.py`
- `pytest -q tests/test_publication_*.py tests/test_suricata*.py`
- `git diff --check`

## Rollback Command

```bash
rm -f publication/suricata_live_network_fetcher.py tests/test_suricata_live_network_fetcher.py docs/publication/USBAY_SURICATA_015_LIVE_NETWORK_FETCHER.md
```

Then revert the SURICATA-015 RuntimeAggregator, report-field, export, and live-mode fixture changes.
