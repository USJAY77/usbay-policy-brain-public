# USBAY-SURICATA-003 Suricata Policy Registry

## Purpose

The Suricata Policy Registry is a local-only governance authority for accepted Suricata rule sets. It verifies that network IDS policy evidence is versioned, approved, active, signed, and hash-bound before Policy Brain or Runtime Aggregator may consume Suricata network evidence.

This control does not install Suricata, call the network, expose endpoints, execute connectors, publish artifacts, or alter live runtime behavior.

## Registry Record

Each accepted rule set contains:

- `policy_id`
- `policy_version`
- `signature_hash`
- `evidence_hash`
- `rule_count`
- `created_at`
- `approved_by`
- `approval_timestamp`
- `active`
- `revoked`

## Cryptographic Evidence

The registry computes deterministic hashes for:

- the rule-set manifest
- the registry contents
- the registry validation result

Only hashes, versions, approval metadata, and reason codes are used by downstream publication/runtime decisions.

## Fail-Closed Validation

The registry rejects:

- duplicate policy versions
- invalid or mismatched hashes
- revoked policies
- inactive policies
- unsigned policies
- stale approval timestamps
- malformed records
- missing approval
- unknown policies

## Runtime Aggregator Binding

When Suricata evidence is present, Runtime Aggregator now requires:

- accepted Suricata evidence
- approved Suricata threshold gate
- approved Suricata policy registry result

If registry approval is missing or rejected, Suricata evidence cannot participate in execution or publication readiness decisions.

## Remaining Gaps

- No live Suricata rule source integration.
- No external signing authority integration.
- No connector/API binding.
- Human policy approval remains required outside this local validator.
