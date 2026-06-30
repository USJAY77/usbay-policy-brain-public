# USBAY-SURICATA-016 Publication Connector

## Purpose

USBAY-SURICATA-016 adds a fail-closed Suricata publication connector for publishing only approved, hash-only governance evidence to an approved USBAY Governance Gateway endpoint.

The connector is production-capable, but tests use injected local transports. No validation run performs real network calls, configures a production endpoint, or publishes live data.

## Trust Chain

RuntimeAggregator accepts live Suricata publication evidence only when all upstream controls are approved:

- Suricata evidence adapter
- policy threshold gate
- policy registry
- rule-source signature
- trust anchor
- external signing authority
- fetch receipt
- source replacement flow
- live fetcher gate
- live network fetch result
- publication connector

Missing or rejected connector evidence blocks live Suricata mode with `NETWORK_IDS_EVIDENCE_INVALID`.

## Connector Contract

The connector may publish only:

- evidence_hash
- policy_version
- trust_fingerprint
- decision
- reason
- timestamp
- nonce
- connector_version

No raw EVE JSON, raw payload, IP address, domain, hostname, username, user-agent, source URI, certificate body, public key material, or Suricata rule content may be included.

## Gateway Controls

The connector enforces:

- HTTPS-only endpoint
- approved endpoint allowlist
- certificate fingerprint presence
- trust fingerprint match
- policy-version binding
- evidence-hash verification
- nonce replay rejection
- timestamp freshness validation
- timeout bounds
- retry bounds
- response schema validation
- 5xx response blocking

## Failure Paths

The connector blocks on:

- HTTP endpoint
- unapproved endpoint
- missing certificate fingerprint
- certificate invalid, expired, self-signed, or hostname mismatch
- trust fingerprint mismatch
- policy mismatch
- evidence hash mismatch
- replayed nonce
- missing or stale timestamp
- timeout
- malformed response
- 5xx response
- missing live network fetch result
- rejected live network fetch result

## Audit Evidence

The connector emits deterministic hash-only evidence derived from:

- connector publication payload
- response acknowledgment hash
- policy version
- trust fingerprint
- nonce
- timestamp
- connector version

Runtime reports expose only the connector evidence hash and approved connector fields. Raw network, rule, certificate, or event data is not included.

## Privacy Model

The final report must not expose:

- raw EVE JSON
- IP addresses
- domains or hostnames
- payloads
- usernames
- user agents
- source URLs
- raw Suricata rules
- raw certificate bodies
- public key material

## Validation Commands

- `python3.11 -m py_compile publication/*.py tests/test_suricata*.py`
- `pytest -q tests/test_suricata*.py`
- `pytest -q tests/test_publication_*.py tests/test_suricata*.py`
- `git diff --check`

## Coverage Summary

Covered cases:

- approved connector publication
- HTTPS enforcement
- endpoint allowlist enforcement
- certificate fingerprint enforcement
- trust fingerprint mismatch
- policy mismatch
- evidence hash mismatch
- replayed nonce
- stale timestamp
- timeout
- malformed response
- 5xx response
- raw Suricata data leakage prevention
- RuntimeAggregator missing connector block
- RuntimeAggregator approved connector allow path
- final report hash-only connector fields

## Remaining Gaps

- No real production Gateway endpoint is configured.
- No persistent distributed nonce store is implemented.
- No live production certificate authority, KMS, or HSM integration is configured.

## Rollback Command

```bash
rm -f publication/suricata_publication_connector.py tests/test_suricata_publication_connector.py docs/publication/USBAY_SURICATA_016_PUBLICATION_CONNECTOR.md
```

Then revert the SURICATA-016 RuntimeAggregator, report-field, export, and live-mode fixture changes.
