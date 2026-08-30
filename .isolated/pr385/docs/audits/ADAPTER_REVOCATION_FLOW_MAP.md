# PB-ADAPTER-007 - Adapter Revocation Flow Map

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
  -> canonical gate proof validation
  -> fail closed on revoked or malformed revocation evidence
```

## Revocation States

| Revocation record | Result |
| --- | --- |
| `NOT_REVOKED`, `NONE`, `NONE` | Continue validation |
| Canonical revocation reason with actor and timestamp | Block |
| Missing revocation field | Block |
| Unknown revocation reason | Block |
| Owner mismatch | Block |
| Reference mismatch | Block |
| Malformed timestamp | Block |

## Registered Non-Revoked Adapters

| Adapter | Revocation ID | Reason | Owner | Reference |
| --- | --- | --- | --- | --- |
| `browser` | `adapter-revocation.browser.none.v1` | `NOT_REVOKED` | `execution.adapters.base` | `usbay.adapter.browser.revocation.none.v1` |
| `filesystem` | `adapter-revocation.filesystem.none.v1` | `NOT_REVOKED` | `execution.adapters.base` | `usbay.adapter.filesystem.revocation.none.v1` |
| `github` | `adapter-revocation.github.none.v1` | `NOT_REVOKED` | `execution.adapters.base` | `usbay.adapter.github.revocation.none.v1` |
| `shell` | `adapter-revocation.shell.none.v1` | `NOT_REVOKED` | `execution.adapters.base` | `usbay.adapter.shell.revocation.none.v1` |

## Enforcement Statement

Revocation validation is mandatory and fail-closed. A revoked, malformed, or
inconsistent revocation record prevents adapter governance evaluation,
capability validation, decision routing, and execution participation.
