# USBAY Metadata Governance

## Problem: encryption does not equal anonymity

Encryption protects content. It does not, by itself, make people anonymous.
Metadata can still reveal who acted, when they acted, where they were, what
system they used, and what intent or behavior pattern may exist around the
encrypted content.

## Human risk: metadata can expose identity, location, timing, payment trails, device links, and behavior patterns

Metadata can expose people even when message bodies, prompts, or files are
encrypted. Examples include identity markers, approximate or precise location,
timing patterns, payment trails, device links, communication relationships, and
behavior patterns across requests.

USBAY treats this as a governance issue, not only a cryptography issue. A system
can be encrypted and still unsafe for humans if it collects or logs sensitive
metadata without policy approval.

## USBAY mechanism

- Policy Brain decides what metadata may be collected.
- Enforcement Gateway blocks execution if metadata policy is violated.
- Audit layer records only minimal, redacted evidence.
- Fail-closed if metadata classification is unknown.

## Mandatory rule

No raw sensitive metadata in logs.

## Allowed audit fields

- policy_id
- decision_id
- timestamp
- actor_hash
- request_hash
- reason_code
- policy_version

## Forbidden audit fields

- raw prompt
- full IP address
- payment identifiers
- phone number
- email body
- precise location
- raw device fingerprint
- raw browser history
