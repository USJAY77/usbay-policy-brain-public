# PB-ADAPTER-001 - Canonical Execution Adapter Contract Audit

Date: 2026-06-21

## Canonical Owner

`execution.adapters.base`

The base adapter module owns:

- adapter capability declarations
- adapter action contract construction
- adapter action contract validation
- canonical gate proof requirement
- disabled adapter fail-closed behavior

## Fail-Closed Validation

| Case | Expected Result | Reason Code |
| --- | --- | --- |
| Unknown adapter | `BLOCKED` | `UNKNOWN_ADAPTER` |
| Unknown capability | `BLOCKED` | `UNKNOWN_CAPABILITY` |
| Unknown action type | `BLOCKED` | `UNKNOWN_ACTION_TYPE` |
| Missing canonical gate proof | `BLOCKED` | `MISSING_CANONICAL_GATE_PROOF` |
| Invalid canonical gate proof | `BLOCKED` | `INVALID_CANONICAL_GATE_PROOF` |
| Malformed adapter contract | `BLOCKED` | `ADAPTER_CONTRACT_MALFORMED` |

## Governance Boundary

This change does not enable adapter execution, simulator work, travel/voucher behavior, tenant changes, RFC3161 changes, lineage changes, or inventory rewrites.

All concrete adapters continue to inherit disabled behavior and return `EXECUTION_BLOCKED` / `EXECUTION_DISABLED`.

## Evidence

- Capability map: `docs/audits/ADAPTER_CAPABILITY_MAP.md`
- Contract owner: `execution/adapters/base.py`
- Focused tests: `tests/test_execution_adapters.py`
