# PB-ADAPTER-006 - Adapter Registration Authority Audit

Date: 2026-06-21

## Scope

- `execution/adapters/base.py`
- `tests/test_execution_adapters.py`

## Canonical Registration Authority

`execution.adapters.base` is the canonical Adapter Registration Authority for
adapter registration declarations, registration state validation, registration
owner validation, and registration reference validation.

## Registration Model

Every adapter action contract must include:

- `registration_id`
- `registration_state`
- `registration_owner`
- `registration_reference`

The registration authority is `usbay.execution.adapters.registration_authority`.
Only `ACTIVE` registration is allowed for adapter evaluation. `REGISTERED` and
`APPROVED` are valid lifecycle states but are not executable states.

## Binding

Registration validation is bound to the existing governance layers:

- Capability layer: registration is declared on each adapter capability record.
- Identity layer: registration belongs to the declared adapter ID and owner.
- Provenance layer: registration is emitted from the same canonical source and
  registration timestamp used by the provenance chain.
- Gate layer: registration is validated before canonical gate proof is accepted.

## Fail-Closed Reasons

| Condition | Reason code |
| --- | --- |
| Missing registration evidence | `ADAPTER_REGISTRATION_MISSING` |
| Unknown registration state | `ADAPTER_REGISTRATION_STATE_INVALID` |
| Registered but not active | `ADAPTER_REGISTRATION_NOT_ACTIVE` |
| Approved but not active | `ADAPTER_REGISTRATION_NOT_ACTIVE` |
| Revoked registration | `ADAPTER_REGISTRATION_REVOKED` |
| Suspended registration | `ADAPTER_REGISTRATION_SUSPENDED` |
| Registration owner mismatch | `ADAPTER_REGISTRATION_OWNER_MISMATCH` |
| Registration reference mismatch | `ADAPTER_REGISTRATION_REFERENCE_MISMATCH` |

## Evidence Matrix

| Evidence | Coverage |
| --- | --- |
| `test_adapter_capability_map_has_single_canonical_owner` | registration fields published in canonical map |
| `test_missing_adapter_registration_fails_closed` | missing registration blocks |
| `test_invalid_adapter_registration_state_fails_closed` | invalid state blocks |
| `test_inactive_adapter_registration_states_fail_closed` | registered, approved, revoked, and suspended states block |
| `test_mismatched_registration_owner_fails_closed` | owner drift blocks |
| `test_mismatched_registration_reference_fails_closed` | reference drift blocks |
| `test_active_approved_adapter_registration_is_allowed` | active canonical registration validates |
| `test_adapter_evaluate_blocks_revoked_registration` | adapter evaluation blocks revoked registration |
| `test_adapter_evaluate_blocks_suspended_registration` | adapter evaluation blocks suspended registration |
| `test_adapter_evaluate_blocks_missing_registration` | adapter evaluation blocks missing registration |

## Remaining Gaps

No remaining PB-ADAPTER-006 gaps are identified in the scoped adapter
registration authority. This capability does not add runtime behavior,
simulator behavior, travel/voucher behavior, tenant logic, RFC3161 logic,
lineage changes, or inventory rewrites.

## Validation Commands

```text
python3.11 -m py_compile execution/adapters/base.py tests/test_execution_adapters.py
pytest -q tests/test_execution_adapters.py
pytest -q tests/test_gateway_app.py
git diff --check
git diff --cached --check
```
