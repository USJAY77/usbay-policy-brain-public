# PB-ADAPTER-009 - Adapter Governance Consistency Audit

Date: 2026-06-21

## Scope

- `execution/adapters/base.py`
- `tests/test_execution_adapters.py`

## Canonical Consistency Authority

`execution.adapters.base` is the canonical Adapter Governance Consistency
Authority. It verifies that Contract, Capability, Action Scope, Identity,
Provenance, Registration, Approval, and Revocation evidence remain internally
consistent before adapter evaluation can continue.

Authority identifier:

`usbay.execution.adapters.governance_consistency_authority`

## Consistency Model

The consistency validator checks:

- all authority owners resolve to `execution.adapters.base`
- all authority references bind to the same adapter name
- capability and action scope match the declared action set
- identity hashes and provenance chain hashes match the canonical declaration
- registration and approval states are coherent
- approval and revocation evidence do not conflict
- authority identifiers are not duplicated inside a contract
- required authority linkage is present

The validator returns:

- `governance_consistency_status`
- `authority`
- `canonical_owner`
- `reason_codes`
- `fail_closed`

## Fail-Closed Reason Codes

| Condition | Reason code |
| --- | --- |
| Authority owner mismatch | `ADAPTER_CONSISTENCY_AUTHORITY_OWNER_MISMATCH` |
| Authority reference mismatch | `ADAPTER_CONSISTENCY_AUTHORITY_REFERENCE_MISMATCH` |
| Capability/action drift | `ADAPTER_CONSISTENCY_CAPABILITY_ACTION_DRIFT` |
| Identity/provenance drift | `ADAPTER_CONSISTENCY_IDENTITY_PROVENANCE_DRIFT` |
| Registration/approval drift | `ADAPTER_CONSISTENCY_REGISTRATION_APPROVAL_DRIFT` |
| Approval/revocation conflict | `ADAPTER_CONSISTENCY_APPROVAL_REVOCATION_CONFLICT` |
| Duplicate authority identifier | `ADAPTER_CONSISTENCY_DUPLICATE_AUTHORITY_IDENTIFIER` |
| Missing authority linkage | `ADAPTER_CONSISTENCY_LINKAGE_MISSING` |

## Evidence Matrix

| Evidence | Coverage |
| --- | --- |
| `test_governance_consistency_validation_success` | canonical success result |
| `test_consistency_authority_owner_mismatch_fails_closed` | owner mismatch blocks |
| `test_consistency_authority_reference_mismatch_fails_closed` | reference mismatch blocks |
| `test_consistency_capability_action_drift_fails_closed` | capability/action drift blocks |
| `test_consistency_identity_provenance_drift_fails_closed` | identity/provenance drift blocks |
| `test_consistency_registration_approval_drift_fails_closed` | registration/approval drift blocks |
| `test_consistency_approval_revocation_conflict_fails_closed` | approval/revocation conflict blocks |
| `test_consistency_duplicate_authority_identifier_fails_closed` | duplicate identifiers block |
| `test_consistency_missing_required_authority_linkage_fails_closed` | missing linkage blocks |

## Remaining Gaps

No remaining PB-ADAPTER-009 gaps are identified in the scoped adapter
governance consistency authority. This capability does not add runtime
behavior, simulator behavior, travel/voucher behavior, tenant logic, RFC3161
logic, lineage changes, or inventory rewrites.

## Validation Commands

```text
python3.11 -m py_compile execution/adapters/base.py tests/test_execution_adapters.py
pytest -q tests/test_execution_adapters.py
pytest -q tests/test_gateway_app.py
git diff --check
git diff --cached --check
```
