# USBAY-SURICATA-014 Live Network Fetcher Gate

## Purpose

This batch adds a local, fail-closed governance gate for future live Suricata rule-source fetching. It does not perform network calls, connector calls, API calls, publication, or live rule fetching.

## Risk

Live Suricata rule fetching can import poisoned rules, bypass human trust approval, leak source metadata, or allow stale rule evidence to influence Policy Brain decisions. The gate requires complete governance evidence before any live-fetch-capable path may be considered approved.

## Mechanism

The live-fetcher gate requires:

- explicit live fetch enablement
- explicit policy flag approval
- human approval id
- approved source registry evidence
- approved trust-anchor proof
- approved trust-anchor finalizer proof
- approved fetch receipt evidence
- approved source replacement flow evidence
- deterministic gate evidence hash

RuntimeAggregator now requires an approved `SuricataLiveFetcherGateResult` whenever `suricata_live_rule_source_enabled` is true. Missing or rejected gate evidence blocks with `NETWORK_IDS_EVIDENCE_INVALID`.

## Fail-Closed Conditions

The gate blocks when:

- live fetch is disabled by default
- explicit policy flag is disabled
- human approval is missing
- source registry evidence is missing or rejected
- trust-anchor proof is missing or rejected
- fetch receipt is missing or rejected
- replacement flow is missing or rejected
- policy versions mismatch
- hash evidence is missing or malformed

## Runtime Evidence

RuntimeAggregator propagates only:

- suricata_live_fetcher_gate_hash
- suricata_live_fetcher_policy_version
- suricata_live_fetcher_decision
- suricata_live_fetcher_reason
- suricata_live_fetcher_timestamp

Final reports do not expose raw EVE JSON, raw rule payloads, source URI, IPs, domains, usernames, user agents, payload fields, public keys, or certificate bodies.

## Validation Commands

- `python3.11 -m py_compile publication/*.py tests/test_suricata*.py`
- `pytest -q tests/test_suricata*.py`
- `pytest -q tests/test_publication_*.py tests/test_suricata*.py`
- `git diff --check`

## Remaining Gaps

- No real live network fetcher is enabled.
- No connector/API/publication path is enabled.
- External signing authority and trust controls remain local/offline unless explicitly configured for a real CA/KMS/HSM provider.

## Rollback Command

```bash
rm -f publication/suricata_live_fetcher_gate.py tests/test_suricata_live_fetcher_gate.py docs/publication/USBAY_SURICATA_014_LIVE_NETWORK_FETCHER_GATE.md
```

Then revert the SURICATA live-fetcher gate imports, RuntimeAggregator parameters, report fields, and updated Suricata live-mode test fixtures.
