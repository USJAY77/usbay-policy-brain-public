# USBAY-SURICATA-002 Suricata Runtime Policy Threshold Gate

## Purpose

The Suricata Policy Threshold Gate is a local-only governance control that evaluates redacted Suricata evidence from USBAY-SURICATA-001 against a human-defined runtime policy threshold.

It does not call Suricata, open network connections, publish artifacts, execute connectors, or create HTTP/API paths.

## Policy Input

Required policy fields:

- `policy_version`
- `severity_threshold`
- `action_on_threshold_exceeded`

The only supported action is `BLOCK`.

## Decision Rule

SURICATA-002 uses policy-threshold semantics:

- `severity < severity_threshold`: approve
- `severity >= severity_threshold`: block

This gate treats threshold crossing as a policy breach and fails closed.

## Fail-Closed Conditions

The gate blocks when:

- policy config is missing
- policy version is missing
- threshold is missing
- threshold is non-numeric
- threshold is negative
- threshold exceeds the supported maximum severity
- action is not `BLOCK`
- Suricata evidence is missing
- Suricata severity is missing
- evidence hash is missing or malformed
- evidence hash does not match the redacted Suricata evidence
- Suricata evidence was not accepted by the upstream adapter

## Runtime Aggregator Binding

If Suricata evidence is provided, Runtime Aggregator requires a `SuricataPolicyGateResult`.

The aggregator blocks when:

- Suricata evidence exists but no policy gate exists
- the gate is not approved
- the upstream Suricata evidence is invalid

Allowed publication readiness can only proceed when Suricata evidence is accepted and the policy gate approves.

## Final Report Fields

Final reports may include only:

- `suricata_policy_version`
- `suricata_threshold`
- `suricata_decision`
- `suricata_evidence_hash`
- `suricata_reason`

Raw EVE JSON, IP addresses, domains, payloads, usernames, hostnames, URLs, and user-agent values are forbidden.

## Remaining Gaps

- No live Suricata daemon integration.
- No external threshold authority.
- No connector/API binding.
- Threshold ownership remains a human policy responsibility.
