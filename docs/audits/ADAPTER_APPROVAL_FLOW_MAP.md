# PB-ADAPTER-008 - Adapter Approval Flow Map

Date: 2026-06-21

## Canonical Flow

```text
adapter.evaluate(request)
  -> validate_adapter_action_contract()
  -> capability declaration lookup
  -> action scope validation
  -> identity attestation validation
  -> provenance chain validation
  -> registration authority validation
  -> revocation authority validation
  -> approval authority validation
  -> canonical gate proof validation
  -> continue only when ACTIVE + APPROVED + NOT_REVOKED
```

## Approval State Map

| Approval state | Result |
| --- | --- |
| `PENDING` | Block |
| `APPROVED` | Continue validation |
| `REJECTED` | Block |
| `EXPIRED` | Block |
| `REVOKED` | Block |

## Registered Approved Adapters

| Adapter | Approval ID | State | Owner | Approved by | Reference |
| --- | --- | --- | --- | --- | --- |
| `browser` | `adapter-approval.browser.v1` | `APPROVED` | `execution.adapters.base` | `adapter-governance-board` | `usbay.adapter.browser.approval.v1` |
| `filesystem` | `adapter-approval.filesystem.v1` | `APPROVED` | `execution.adapters.base` | `adapter-governance-board` | `usbay.adapter.filesystem.approval.v1` |
| `github` | `adapter-approval.github.v1` | `APPROVED` | `execution.adapters.base` | `adapter-governance-board` | `usbay.adapter.github.approval.v1` |
| `shell` | `adapter-approval.shell.v1` | `APPROVED` | `execution.adapters.base` | `adapter-governance-board` | `usbay.adapter.shell.approval.v1` |

## Enforcement Statement

Adapter approval is mandatory and fail-closed. Missing, pending, rejected,
expired, revoked, or inconsistent approval evidence prevents adapter governance
evaluation, decision routing, and execution participation.
