# PB-ADAPTER-004 - Adapter Identity Attestation Audit

Date: 2026-06-21

## Scope

- `execution/adapters/base.py`
- `tests/test_execution_adapters.py`

## Identity Fields

Each adapter action contract must include adapter identity attestation fields:

- `adapter_id`
- `adapter_owner`
- `adapter_identity_hash`
- `attestation_reference`

The adapter identity hash is derived from:

- `adapter_name`
- `adapter_id`
- `adapter_owner`
- `attestation_reference`
- `governance_gate_reference`

This binds adapter identity to the canonical governance gate before adapter
evaluation can proceed.

## Canonical Identity Owner

`execution.adapters.base` is the canonical owner for adapter identity
declarations and validation. Adapter implementation modules remain providers
only and do not own identity attestation truth.

## Validation Path

```text
adapter.evaluate(request)
  -> validate_adapter_action_contract()
  -> adapter declaration lookup
  -> action scope validation
  -> adapter identity attestation validation
  -> canonical gate proof validation
  -> fail closed on any mismatch or missing field
```

Adapter execution remains disabled. PB-ADAPTER-004 strengthens pre-execution
identity validation so unidentified or impersonating adapters cannot enter
governed execution paths.

## Identity Declaration Inventory

| Adapter | Adapter ID | Adapter owner | Attestation reference |
| --- | --- | --- | --- |
| `browser` | `adapter.browser.v1` | `execution.adapters.base` | `usbay.adapter.browser.identity.v1` |
| `filesystem` | `adapter.filesystem.v1` | `execution.adapters.base` | `usbay.adapter.filesystem.identity.v1` |
| `github` | `adapter.github.v1` | `execution.adapters.base` | `usbay.adapter.github.identity.v1` |
| `shell` | `adapter.shell.v1` | `execution.adapters.base` | `usbay.adapter.shell.identity.v1` |

## Fail-Closed Reasons

| Condition | Reason code |
| --- | --- |
| Missing adapter ID | `ADAPTER_ID_MISSING` |
| Mismatched adapter ID | `ADAPTER_ID_MISMATCH` |
| Missing adapter owner | `ADAPTER_OWNER_MISSING` |
| Mismatched adapter owner | `ADAPTER_OWNER_MISMATCH` |
| Missing identity hash | `ADAPTER_IDENTITY_HASH_MISSING` |
| Mismatched identity hash | `ADAPTER_IDENTITY_HASH_MISMATCH` |
| Missing attestation reference | `ADAPTER_ATTESTATION_REFERENCE_MISSING` |
| Mismatched attestation reference | `ADAPTER_ATTESTATION_REFERENCE_MISMATCH` |

## Evidence Matrix

| Evidence | Coverage |
| --- | --- |
| `test_adapter_capability_map_has_single_canonical_owner` | identity fields published in the canonical map |
| `test_missing_adapter_identity_fields_fail_closed` | missing identity fields block |
| `test_mismatched_adapter_id_fails_closed` | adapter ID impersonation blocks |
| `test_mismatched_adapter_owner_fails_closed` | adapter owner drift blocks |
| `test_mismatched_adapter_identity_hash_fails_closed` | stale or forged identity hash blocks |
| `test_mismatched_attestation_reference_fails_closed` | attestation reference drift blocks |
| `test_adapter_evaluate_blocks_missing_identity_attestation` | adapter evaluation blocks missing attestation |
| `test_adapter_evaluate_blocks_mismatched_identity_attestation` | adapter evaluation blocks mismatched attestation |

## Remaining Gaps

No remaining PB-ADAPTER-004 gaps are identified in the scoped adapter identity
attestation layer. This audit does not introduce external trust calls,
deployment behavior, simulator changes, tenant changes, RFC3161 changes,
lineage changes, or inventory rewrites.

## Validation Commands

```text
python3.11 -m py_compile execution/adapters/base.py tests/test_execution_adapters.py
pytest -q tests/test_execution_adapters.py
pytest -q tests/test_gateway_app.py
git diff --check
git diff --cached --check
```
