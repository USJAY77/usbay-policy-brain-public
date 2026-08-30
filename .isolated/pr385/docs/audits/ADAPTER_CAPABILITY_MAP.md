# PB-ADAPTER-001 - Adapter Capability Map

Date: 2026-06-21

Canonical adapter contract owner: `execution.adapters.base`

| Adapter | Capability | Action Types | Required Gate Proof |
| --- | --- | --- | --- |
| `browser` | `READ_ONLY_NAVIGATION` | `open_url_preview`, `read_page_metadata` | `canonical_gate_proof` |
| `filesystem` | `FILE_READ` | `preview_file`, `read_file_metadata` | `canonical_gate_proof` |
| `github` | `ISSUE_COMMENT_DRAFT` | `draft_issue_comment` | `canonical_gate_proof` |
| `github` | `PR_DESCRIPTION_DRAFT` | `draft_pr_description` | `canonical_gate_proof` |
| `shell` | `REPORT_GENERATION` | `generate_report` | `canonical_gate_proof` |
| `shell` | `GOVERNANCE_STATUS_READ` | `read_governance_status` | `canonical_gate_proof` |

All adapters remain disabled for direct execution. The contract map binds adapter requests to known capability/action declarations before any adapter can progress beyond fail-closed evaluation.
