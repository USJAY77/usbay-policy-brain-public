# PB-ADAPTER-006 - Adapter Registration State Map

Date: 2026-06-21

## Registration States

| State | Meaning | Adapter evaluation |
| --- | --- | --- |
| `REGISTERED` | Adapter record exists but is not approved or active | Block |
| `APPROVED` | Adapter is approved but not active | Block |
| `ACTIVE` | Adapter is registered, approved, and active | Allow contract validation to continue |
| `REVOKED` | Adapter registration has been revoked | Block |
| `SUSPENDED` | Adapter registration is temporarily suspended | Block |

## Canonical Authority

`usbay.execution.adapters.registration_authority`

## Registered Adapters

| Adapter | Registration ID | State | Owner | Reference |
| --- | --- | --- | --- | --- |
| `browser` | `adapter-registration.browser.v1` | `ACTIVE` | `execution.adapters.base` | `usbay.adapter.browser.registration.v1` |
| `filesystem` | `adapter-registration.filesystem.v1` | `ACTIVE` | `execution.adapters.base` | `usbay.adapter.filesystem.registration.v1` |
| `github` | `adapter-registration.github.v1` | `ACTIVE` | `execution.adapters.base` | `usbay.adapter.github.registration.v1` |
| `shell` | `adapter-registration.shell.v1` | `ACTIVE` | `execution.adapters.base` | `usbay.adapter.shell.registration.v1` |

## Transition Map

```text
REGISTERED -> APPROVED -> ACTIVE
ACTIVE -> SUSPENDED -> ACTIVE
ACTIVE -> REVOKED
SUSPENDED -> REVOKED
```

## Enforcement Statement

Adapter action contracts must present canonical registration evidence. Missing,
invalid, suspended, revoked, or inconsistent registration blocks adapter
evaluation before governance gate proof is accepted.
