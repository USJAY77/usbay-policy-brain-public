# PB-ADAPTER-003 - Adapter Action Scope Audit

Date: 2026-06-21

## Scope

- `execution/adapters/base.py`
- `tests/test_execution_adapters.py`

## Canonical Action-Scope Owner

`execution.adapters.base` is the canonical owner for adapter action-scope
declarations and validation. Adapter implementation modules are providers only;
they do not own action scope, action authorization, or execution truth.

## Action Scope Contract

Every adapter action contract must bind the request to:

- `adapter_name`
- `capability`
- `action_type`
- `action_scope_owner`
- `action_scope_id`
- `action_scope_hash`
- `governance_gate_reference`
- `canonical_gate_proof`

The `action_scope_hash` is computed from the declared adapter, capability,
ordered action set, action-scope owner, and governance gate reference. A request
with a stale, forged, or mismatched action-scope hash fails closed.

## Registered Action Inventory

| Adapter | Capability | Declared actions | Action-scope owner |
| --- | --- | --- | --- |
| `browser` | `READ_ONLY_NAVIGATION` | `open_url_preview`, `read_page_metadata` | `execution.adapters.base` |
| `filesystem` | `FILE_READ` | `preview_file`, `read_file_metadata` | `execution.adapters.base` |
| `github` | `ISSUE_COMMENT_DRAFT` | `draft_issue_comment` | `execution.adapters.base` |
| `github` | `PR_DESCRIPTION_DRAFT` | `draft_pr_description` | `execution.adapters.base` |
| `shell` | `REPORT_GENERATION` | `generate_report` | `execution.adapters.base` |
| `shell` | `GOVERNANCE_STATUS_READ` | `read_governance_status` | `execution.adapters.base` |

## Fail-Closed Boundaries

| Attempt | Result |
| --- | --- |
| Browser `submit_form` under `READ_ONLY_NAVIGATION` | `UNKNOWN_ACTION_TYPE` |
| Filesystem `delete_file` under `FILE_READ` | `UNKNOWN_ACTION_TYPE` |
| GitHub `publish_issue_comment` under `ISSUE_COMMENT_DRAFT` | `UNKNOWN_ACTION_TYPE` |
| GitHub `draft_issue_comment` under `PR_DESCRIPTION_DRAFT` | `UNKNOWN_ACTION_TYPE` |
| Shell `execute_command` under `REPORT_GENERATION` | `UNKNOWN_ACTION_TYPE` |
| Shell `mutate_governance_status` under `GOVERNANCE_STATUS_READ` | `UNKNOWN_ACTION_TYPE` |
| Mismatched action-scope owner | `ADAPTER_ACTION_SCOPE_OWNER_MISMATCH` |
| Mismatched action-scope id | `ADAPTER_ACTION_SCOPE_MISMATCH` |
| Mismatched action-scope hash | `ADAPTER_ACTION_SCOPE_HASH_MISMATCH` |

## Enforcement Evidence

Adapter evaluation calls `validate_adapter_action_contract()` before returning
any adapter response for action-shaped requests. If the action is not present in
the declared capability action set, if ownership drifts, or if the scope hash is
invalid, the adapter returns `EXECUTION_DISABLED` and `EXECUTION_BLOCKED`.

No simulator, travel/voucher, tenant, RFC3161, lineage, or inventory files were
changed for this capability.

## Validation Commands

```text
python3.11 -m py_compile execution/adapters/base.py tests/test_execution_adapters.py
pytest -q tests/test_execution_adapters.py
pytest -q tests/test_gateway_app.py
git diff --check
git diff --cached --check
```
