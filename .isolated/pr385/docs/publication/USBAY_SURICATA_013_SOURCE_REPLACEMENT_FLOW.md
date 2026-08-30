# USBAY-SURICATA-013 Source Replacement Flow

## Purpose

USBAY-SURICATA-013 adds a local, fail-closed source rollback and replacement proof for governed Suricata rule-source evidence. It does not fetch live rules, publish artifacts, call connectors, or expose raw Suricata rule payloads.

## Runtime Control

The replacement flow validates that a candidate rule source can replace the currently approved Suricata rule-source proof only when every upstream evidence object is approved and hash-bound:

- approved current fetch finalizer evidence
- approved candidate fetch receipt evidence
- approved candidate rule source registry evidence
- approved candidate signature evidence
- approved trust anchor evidence
- approved trust anchor finalizer evidence
- human approval id
- rollback plan id
- deterministic replacement flow hash

RuntimeAggregator accepts replacement evidence only when Suricata live-rule-source mode and replacement mode are explicitly enabled. When replacement mode is enabled, missing or rejected replacement evidence blocks readiness.

## Evidence Propagation

RuntimeAggregator propagates only hash-only replacement metadata:

- replacement_flow_hash
- replacement_rule_bundle_hash
- replacement_policy_version
- replacement_decision
- replacement_reason

The flow does not propagate raw rule contents, raw source URIs, raw EVE JSON, IP addresses, domains, usernames, payloads, or user-agent values.

## Fail-Closed Reasons

The replacement flow blocks on:

- current source proof missing or rejected
- candidate receipt missing or rejected
- candidate registry proof missing or rejected
- candidate signature proof missing or rejected
- trust anchor missing, revoked, malformed, or rejected
- trust anchor finalizer missing or rejected
- policy version mismatch
- rule bundle hash mismatch
- registry hash mismatch
- trust anchor hash mismatch
- source mismatch
- missing rollback plan id
- missing human approval id
- replacement without explicit replacement approval
- malformed hash evidence

## Audit Evidence

The replacement flow hash is deterministic and derived from:

- decision state
- source id
- candidate rule bundle hash
- previous rule bundle hash
- policy version
- rollback plan id
- human approval id
- current fetch finalizer hash
- candidate receipt hash
- candidate registry hash
- candidate signature hash
- trust anchor finalizer hash

## Validation Evidence

Required validation:

- `python3.11 -m py_compile publication/*.py tests/test_suricata*.py`
- `pytest -q tests/test_suricata*.py`
- `pytest -q tests/test_publication_*.py tests/test_suricata*.py`
- `git diff --check`

## Remaining Gaps

- No live network fetcher is enabled.
- No external signing authority integration is enabled.
- No connector, API endpoint, publication path, or automatic publication path is enabled.
