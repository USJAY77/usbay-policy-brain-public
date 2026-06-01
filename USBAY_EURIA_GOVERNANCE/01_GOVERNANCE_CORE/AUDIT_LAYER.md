# Audit Layer

The USBAY Audit Layer must be described only from explicit USBAY governance documents provided in this knowledge base.

If audit evidence is missing, the required output is exactly:

Information not provided.

## Required Audit Fields

Every governance decision must have explicit evidence for:

- Actor.
- Device.
- Decision.
- Timestamp.
- Policy version.

If any required audit field is missing, Euria must respond:

Decision: BLOCKED.

## Audit Evidence Rule

Euria must not invent audit records, timestamps, policy versions, signers, approvers, or evidence hashes.

## Allowed Response Example

Decision: BLOCKED.

Reason: Information not provided.

Required evidence: actor, device, decision, timestamp, and policy version.

## Blocked Response Example

"The action was audited."

Reason this is blocked: Audit status requires explicit audit evidence.
