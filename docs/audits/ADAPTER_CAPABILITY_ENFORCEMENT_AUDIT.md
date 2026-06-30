# PB-ADAPTER-002 - Adapter Capability Enforcement Audit

Date: 2026-06-21

## Scope

- `execution/adapters/base.py`
- `execution/adapters/browser_adapter.py`
- `execution/adapters/filesystem_adapter.py`
- `execution/adapters/github_adapter.py`
- `execution/adapters/shell_adapter.py`
- `tests/test_execution_adapters.py`

## Canonical Contract Owner

`execution.adapters.base` is the canonical owner for adapter capability
declarations, adapter action contracts, adapter ownership validation, and
adapter governance gate reference validation.

## Canonical Adapter Capability Contract

Every adapter action contract must include:

- `schema`
- `contract_version`
- `adapter_name`
- `capability`
- `action_type`
- `owner`
- `governance_gate_reference`
- `request_id`

Every adapter action must also provide a valid canonical gate proof before the
adapter evaluates the request. The governance gate reference is fixed to
`gateway.app.canonical_execution_governance_gate`.

## Capability Declaration Inventory

| Adapter | Capability | Action types | Owner | Gate reference |
| --- | --- | --- | --- | --- |
| `browser` | `READ_ONLY_NAVIGATION` | `open_url_preview`, `read_page_metadata` | `execution.adapters.base` | `gateway.app.canonical_execution_governance_gate` |
| `filesystem` | `FILE_READ` | `preview_file`, `read_file_metadata` | `execution.adapters.base` | `gateway.app.canonical_execution_governance_gate` |
| `github` | `ISSUE_COMMENT_DRAFT` | `draft_issue_comment` | `execution.adapters.base` | `gateway.app.canonical_execution_governance_gate` |
| `github` | `PR_DESCRIPTION_DRAFT` | `draft_pr_description` | `execution.adapters.base` | `gateway.app.canonical_execution_governance_gate` |
| `shell` | `REPORT_GENERATION` | `generate_report` | `execution.adapters.base` | `gateway.app.canonical_execution_governance_gate` |
| `shell` | `GOVERNANCE_STATUS_READ` | `read_governance_status` | `execution.adapters.base` | `gateway.app.canonical_execution_governance_gate` |

## Fail-Closed Enforcement

| Condition | Result |
| --- | --- |
| Missing adapter action contract for an action-shaped request | `ADAPTER_ACTION_CONTRACT_MISSING` |
| Unknown adapter | `UNKNOWN_ADAPTER` |
| Missing capability | `ADAPTER_CONTRACT_CAPABILITY_MISSING` |
| Unknown capability | `UNKNOWN_CAPABILITY` |
| Unknown action type | `UNKNOWN_ACTION_TYPE` |
| Missing owner | `ADAPTER_OWNERSHIP_MISSING` |
| Owner mismatch | `ADAPTER_OWNERSHIP_MISMATCH` |
| Missing governance gate reference | `ADAPTER_GATE_REFERENCE_MISSING` |
| Gate reference mismatch | `ADAPTER_GATE_REFERENCE_MISMATCH` |
| Missing canonical gate proof | `MISSING_CANONICAL_GATE_PROOF` |
| Invalid canonical gate proof | `INVALID_CANONICAL_GATE_PROOF` |

## Runtime Boundary

Adapters remain disabled for direct execution. PB-ADAPTER-002 only strengthens
pre-execution governance validation so an adapter cannot evaluate an action-like
request without explicit capability, action type, ownership, governance gate
reference, and canonical gate proof.

## Exclusions

No simulator, travel/voucher, tenant, RFC3161, lineage, gateway, or runtime
rewrites are included in this audit scope.

## Evidence

Focused adapter tests validate:

- all declared adapters have one canonical owner and gate reference
- missing capability fails closed
- unknown action type fails closed
- missing ownership fails closed
- mismatched adapter ownership fails closed
- wrong governance gate reference fails closed
- action-shaped requests without adapter contracts fail closed

Validation commands:

```text
pytest -q tests/test_execution_adapters.py
pytest -q tests/test_gateway_app.py
git diff --check
git diff --cached --check
```
