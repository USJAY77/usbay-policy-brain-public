# PB-ADAPTER-007 - Adapter Revocation Authority Audit

Date: 2026-06-21

## Scope

- `execution/adapters/base.py`
- `tests/test_execution_adapters.py`

## Canonical Revocation Authority

`execution.adapters.base` is the canonical Adapter Revocation Authority for
revocation record declarations, revocation state validation, revocation owner
validation, revocation reference validation, and revocation timestamp validation.

Authority identifier:

`usbay.execution.adapters.revocation_authority`

## Revocation Model

Every adapter action contract must include:

- `revocation_id`
- `revocation_reason`
- `revocation_owner`
- `revoked_by`
- `revoked_at`
- `revocation_reference`

The canonical non-revoked record uses:

- `revocation_reason`: `NOT_REVOKED`
- `revoked_by`: `NONE`
- `revoked_at`: `NONE`

Any other revocation reason, actor, or timestamp indicates revocation evidence
and fails closed.

## Binding

Revocation validation is bound to the existing governance layers:

- Registration authority: revoked adapters block even when registration evidence
  is otherwise present.
- Provenance chain: revocation belongs to the same canonical adapter record.
- Identity attestation: revocation is validated against the declared adapter ID
  and owner before gate proof validation.
- Capability layer: revocation is evaluated within each adapter capability
  declaration before adapter evaluation can continue.

## Revocation Reason Codes

| Reason | Meaning |
| --- | --- |
| `NOT_REVOKED` | Canonical non-revoked state |
| `SECURITY_COMPROMISE` | Adapter identity or behavior is compromised |
| `OWNER_REVOKED` | Adapter owner revoked authority |
| `POLICY_VIOLATION` | Adapter violated governance policy |
| `PROVENANCE_INVALID` | Adapter provenance is invalid |
| `REGISTRATION_REVOKED` | Adapter registration is revoked |

## Fail-Closed Reasons

| Condition | Reason code |
| --- | --- |
| Adapter has revocation evidence | `ADAPTER_REVOKED` |
| Revocation record incomplete | `ADAPTER_REVOCATION_MISSING` |
| Revocation reason is not canonical | `ADAPTER_REVOCATION_REASON_INVALID` |
| Revocation owner mismatch | `ADAPTER_REVOCATION_OWNER_MISMATCH` |
| Revocation reference mismatch | `ADAPTER_REVOCATION_REFERENCE_MISMATCH` |
| Revocation timestamp invalid | `ADAPTER_REVOCATION_TIMESTAMP_INVALID` |

## Evidence Matrix

| Evidence | Coverage |
| --- | --- |
| `test_adapter_capability_map_has_single_canonical_owner` | revocation fields exposed in canonical map |
| `test_missing_adapter_revocation_record_fails_closed` | incomplete revocation record blocks |
| `test_adapter_revoked_by_revocation_authority_fails_closed` | explicit revocation blocks |
| `test_invalid_revocation_reason_fails_closed` | non-canonical reason blocks |
| `test_mismatched_revocation_owner_fails_closed` | revocation owner drift blocks |
| `test_mismatched_revocation_reference_fails_closed` | revocation reference drift blocks |
| `test_invalid_revocation_timestamp_fails_closed` | malformed timestamp blocks |
| `test_adapter_evaluate_blocks_revocation_record` | adapter evaluation blocks revoked adapter |
| `test_adapter_evaluate_blocks_malformed_revocation_record` | adapter evaluation blocks malformed revocation |

## Remaining Gaps

No remaining PB-ADAPTER-007 gaps are identified in the scoped adapter
revocation authority. This capability does not add runtime behavior, simulator
behavior, travel/voucher behavior, tenant logic, RFC3161 logic, lineage changes,
or inventory rewrites.

## Validation Commands

```text
python3.11 -m py_compile execution/adapters/base.py tests/test_execution_adapters.py
pytest -q tests/test_execution_adapters.py
pytest -q tests/test_gateway_app.py
git diff --check
git diff --cached --check
```
