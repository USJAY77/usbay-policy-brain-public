# PB-ADAPTER-005 - Adapter Provenance Map

Date: 2026-06-21

## Canonical Owner

`execution.adapters.base`

## Canonical Source

`usbay.execution.adapters.registry`

## Registered At

`2026-06-21T00:00:00Z`

## Provenance Records

| Adapter | Adapter ID | Owner | Source | Provenance attestation |
| --- | --- | --- | --- | --- |
| `browser` | `adapter.browser.v1` | `execution.adapters.base` | `usbay.execution.adapters.registry` | `usbay.adapter.browser.provenance.v1` |
| `filesystem` | `adapter.filesystem.v1` | `execution.adapters.base` | `usbay.execution.adapters.registry` | `usbay.adapter.filesystem.provenance.v1` |
| `github` | `adapter.github.v1` | `execution.adapters.base` | `usbay.execution.adapters.registry` | `usbay.adapter.github.provenance.v1` |
| `shell` | `adapter.shell.v1` | `execution.adapters.base` | `usbay.execution.adapters.registry` | `usbay.adapter.shell.provenance.v1` |

## Enforcement Statement

Every adapter action contract must include matching provenance ownership,
source, registration timestamp, provenance attestation reference, and
provenance chain hash. Missing or inconsistent provenance evidence blocks
adapter evaluation before any execution path can continue.
