# AWS Live Evidence Checklist

Purpose: track the real AWS S3 Object Lock evidence required for BLOCKER-003 evaluation.

Runtime impact: none.

Gateway impact: none.

Policy enforcement impact: none.

Provider credentials stored in repository: prohibited.

Provider verification claim: prohibited.

Immutable storage claim: prohibited.

Certification claim: prohibited.

Default decision: BLOCKED.

## Required Evidence

| Evidence Item | File | Current Status | Decision |
|---|---|---|---|
| Object Lock write receipt | `object_lock_write_receipt.json` | Information not provided. | BLOCKED |
| Retention configuration evidence | `retention_configuration_evidence.json` | Information not provided. | BLOCKED |
| Legal hold evidence | `legal_hold_evidence.json` | Information not provided. | BLOCKED |
| Export verification evidence | `export_verification_record.json` | Information not provided. | BLOCKED |
| Provider audit reference | `provider_audit_reference.md` | Information not provided. | BLOCKED |

## Fail-Closed Rule

If any evidence item is missing:

BLOCKER-003 = OPEN.

Decision: BLOCKED.

Only evidence may close BLOCKER-003.

## Forbidden Content

The evidence package must not contain:

- AWS access key ID.
- AWS secret access key.
- AWS session token.
- Provider credentials.
- Private keys.
- Raw governance payloads.
- Approval contents.
- Raw regulator exports.

If forbidden content is present:

Decision: BLOCKED.
