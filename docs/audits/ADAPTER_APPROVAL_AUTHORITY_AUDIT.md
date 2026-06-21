# PB-ADAPTER-008 - Adapter Approval Authority Audit

Date: 2026-06-21

## Scope

- `execution/adapters/base.py`
- `tests/test_execution_adapters.py`

## Canonical Approval Authority

`execution.adapters.base` is the canonical Adapter Approval Authority for
approval declarations, approval state validation, approval owner validation, and
approval reference validation.

Authority identifier:

`usbay.execution.adapters.approval_authority`

## Approval Model

Every adapter action contract must include:

- `approval_id`
- `approval_state`
- `approval_owner`
- `approved_by`
- `approved_at`
- `approval_reference`

Only `APPROVED` approval state allows validation to continue. All other states
fail closed before canonical gate proof is accepted.

## Approval States

| State | Result |
| --- | --- |
| `PENDING` | Block |
| `APPROVED` | Continue validation |
| `REJECTED` | Block |
| `EXPIRED` | Block |
| `REVOKED` | Block |

## Binding

Approval validation is bound to the existing adapter governance layers:

- Identity layer: approval belongs to the declared adapter identity.
- Provenance layer: approval is emitted by the same canonical adapter record.
- Registration authority: approval can only continue when registration is
  `ACTIVE`.
- Revocation authority: approval can only continue when revocation state is
  `NOT_REVOKED`.

## Fail-Closed Reasons

| Condition | Reason code |
| --- | --- |
| Approval evidence missing | `ADAPTER_APPROVAL_MISSING` |
| Unknown approval state | `ADAPTER_APPROVAL_STATE_INVALID` |
| Approval pending | `ADAPTER_APPROVAL_PENDING` |
| Approval rejected | `ADAPTER_APPROVAL_REJECTED` |
| Approval expired | `ADAPTER_APPROVAL_EXPIRED` |
| Approval revoked | `ADAPTER_APPROVAL_REVOKED` |
| Approval owner mismatch | `ADAPTER_APPROVAL_OWNER_MISMATCH` |
| Approval reference mismatch | `ADAPTER_APPROVAL_REFERENCE_MISMATCH` |

## Evidence Matrix

| Evidence | Coverage |
| --- | --- |
| `test_adapter_capability_map_has_single_canonical_owner` | approval fields exposed in canonical map |
| `test_missing_adapter_approval_fails_closed` | missing approval blocks |
| `test_non_approved_adapter_approval_states_fail_closed` | pending, rejected, expired, and revoked approval block |
| `test_invalid_adapter_approval_state_fails_closed` | unknown approval state blocks |
| `test_mismatched_approval_owner_fails_closed` | approval owner drift blocks |
| `test_mismatched_approval_reference_fails_closed` | approval reference drift blocks |
| `test_approved_active_non_revoked_adapter_is_allowed` | active, approved, non-revoked adapter validates |
| `test_adapter_evaluate_blocks_pending_approval` | adapter evaluation blocks pending approval |
| `test_adapter_evaluate_blocks_missing_approval` | adapter evaluation blocks missing approval |

## Remaining Gaps

No remaining PB-ADAPTER-008 gaps are identified in the scoped adapter approval
authority. This capability does not add runtime behavior, simulator behavior,
travel/voucher behavior, tenant logic, RFC3161 logic, lineage changes, or
inventory rewrites.

## Validation Commands

```text
python3.11 -m py_compile execution/adapters/base.py tests/test_execution_adapters.py
pytest -q tests/test_execution_adapters.py
pytest -q tests/test_gateway_app.py
git diff --check
git diff --cached --check
```
