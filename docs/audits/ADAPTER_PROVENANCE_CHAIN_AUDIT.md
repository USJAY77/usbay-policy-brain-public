# PB-ADAPTER-005 - Adapter Provenance Chain Audit

Date: 2026-06-21

## Scope

- `execution/adapters/base.py`
- `tests/test_execution_adapters.py`

## Canonical Provenance Model

Every adapter action contract must carry provenance evidence before adapter
evaluation can continue:

- `provenance_owner`
- `provenance_source`
- `provenance_registered_at`
- `provenance_attestation_reference`
- `provenance_chain_hash`

`execution.adapters.base` is the canonical provenance owner. Adapter provider
modules do not own provenance truth, registration truth, execution truth, or
audit truth.

## Chain Hash Inputs

The provenance chain hash is deterministic and local. It is derived from:

- `adapter_name`
- `adapter_id`
- `adapter_owner`
- `adapter_identity_hash`
- `provenance_owner`
- `provenance_source`
- `provenance_registered_at`
- `provenance_attestation_reference`
- `governance_gate_reference`

This binds provenance to adapter identity, ownership, attestation lineage, and
the canonical governance gate.

## Validation Path

```text
adapter.evaluate(request)
  -> validate_adapter_action_contract()
  -> capability declaration lookup
  -> action-scope validation
  -> identity attestation validation
  -> provenance chain validation
  -> canonical gate proof validation
  -> fail closed on missing or mismatched evidence
```

## Fail-Closed Reasons

| Condition | Reason code |
| --- | --- |
| Any provenance field missing | `ADAPTER_PROVENANCE_MISSING` |
| Provenance owner mismatch | `ADAPTER_PROVENANCE_OWNER_MISMATCH` |
| Provenance source mismatch | `ADAPTER_PROVENANCE_SOURCE_MISMATCH` |
| Provenance registration timestamp mismatch | `ADAPTER_PROVENANCE_REGISTRATION_MISMATCH` |
| Provenance attestation reference mismatch | `ADAPTER_PROVENANCE_ATTESTATION_MISMATCH` |
| Provenance chain hash mismatch | `ADAPTER_PROVENANCE_CHAIN_HASH_MISMATCH` |

## Evidence Matrix

| Evidence | Coverage |
| --- | --- |
| `test_adapter_capability_map_has_single_canonical_owner` | provenance fields exposed in canonical map |
| `test_missing_adapter_provenance_fails_closed` | missing provenance fields block |
| `test_mismatched_provenance_owner_fails_closed` | provenance owner drift blocks |
| `test_mismatched_provenance_source_fails_closed` | unregistered provenance source blocks |
| `test_mismatched_provenance_registration_fails_closed` | registration history drift blocks |
| `test_mismatched_provenance_attestation_fails_closed` | attestation lineage drift blocks |
| `test_mismatched_provenance_chain_hash_fails_closed` | stale or forged chain hash blocks |
| `test_adapter_evaluate_blocks_missing_provenance` | adapter evaluation blocks missing provenance |
| `test_adapter_evaluate_blocks_mismatched_provenance_chain_hash` | adapter evaluation blocks forged provenance |

## Remaining Gaps

No remaining PB-ADAPTER-005 gaps are identified in the scoped adapter
provenance chain. This capability does not add runtime behavior, simulator
behavior, travel/voucher behavior, tenant logic, RFC3161 logic, lineage
corruption work, or inventory rewrites.

## Validation Commands

```text
python3.11 -m py_compile execution/adapters/base.py tests/test_execution_adapters.py
pytest -q tests/test_execution_adapters.py
pytest -q tests/test_gateway_app.py
git diff --check
git diff --cached --check
```
