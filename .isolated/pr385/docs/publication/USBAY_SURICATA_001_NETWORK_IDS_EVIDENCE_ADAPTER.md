# USBAY-SURICATA-001 Network IDS Evidence Adapter

## Purpose

The Suricata Evidence Adapter is a local-only parser for caller-provided Suricata EVE JSON. It does not install Suricata, open sockets, call APIs, execute connectors, or publish artifacts.

The adapter converts network IDS alerts into hash-only governance evidence that can be consumed by the local publication Runtime Aggregator. If network threat severity exceeds the human-set policy threshold, the aggregator fails closed.

## Supported Input

- Single EVE JSON object
- List of EVE JSON objects
- JSON string containing an object or array

Supported alert fields include:

- `event_type`
- `alert.signature`
- `alert.category`
- `alert.severity`
- `src_ip`
- `dest_ip`
- `src_port`
- `dest_port`
- `proto`
- `timestamp`
- `flow_id`

Non-alert events are blocked when alert evidence is required.

## Severity Policy

Suricata commonly treats lower severity numbers as higher risk.

- `severity <= threshold`: block
- `severity > threshold`: allow

Example: threshold `2` blocks severity `1` and `2`, while severity `3+` is accepted.

Humans set the threshold. The adapter only evaluates the supplied threshold and evidence.

## Redaction Rules

The final evidence output must not include raw:

- source or destination IP addresses
- hostnames
- DNS names
- HTTP hostnames
- URLs
- payloads
- usernames
- user agents
- raw packet fields

Sensitive values are replaced with deterministic hash-only redaction markers. The Runtime Aggregator only propagates:

- `suricata_evidence_hash`
- `suricata_policy_version`
- `suricata_reason`

## Fail-Closed Cases

The adapter blocks when:

- JSON is malformed
- input is missing
- `event_type` is missing
- event is non-alert while alert evidence is required
- `alert.severity` is missing
- severity is not an integer
- threshold is missing
- schema is unsupported
- redaction fails

## Runtime Aggregator Binding

If Suricata evidence is provided, the Runtime Aggregator requires:

- `suricata_evidence.accepted == True`
- `suricata_evidence.blocked == False`

Blocked or invalid Suricata evidence produces `BLOCK_PUBLICATION` with network IDS block reason evidence. This local control does not enable publication, connector execution, network calls, or live IDS dependencies.

## Remaining Gaps

- No live Suricata integration.
- No external policy service.
- No connector or endpoint binding.
- Threshold governance remains a human policy responsibility.
