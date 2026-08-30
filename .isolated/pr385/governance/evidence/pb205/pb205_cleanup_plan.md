# PB-205 Cleanup Plan

Decision: VERIFIED

Status: READY_FOR_REVIEW

Branch: governance/control-plane-ux-pb188-192

PR: #205

## Inspection

- git status --short: captured in pb205_scope_audit.json
- git diff --name-only origin/main...HEAD: captured in pb205_scope_audit.json
- gh pr view 205 --json title,mergeStateStatus,url: failed with environment network error and is recorded in pb205_scope_audit.json

## Keep Scope

Keep only PB-188 through PB-192 Control Plane UX view models, focused tests, evidence, and PB-205 remediation evidence.

Keep count: 52

## Remove Scope

Remove all files classified as REMOVE_OTHER_PROGRAM from this branch scope. This includes unrelated PB020, PB023-PB152, PB161-PB187, runtime, adapter, execution authority, template, script, and stale evidence files not directly needed by PB-188 through PB-192 UX.

Remove count: 425

## Unknown Scope

Unknown count: 0

Unknown files must not be removed automatically.

## Validation Required Before Push

- grep -n '<<<<<<<\|=======\|>>>>>>>' .gitignore
- git diff --check
- JSON validation for governance/evidence/pb205 and PB188-PB192 evidence
- pytest -q tests/test_human_review_ui.py tests/test_execution_queue_ui.py tests/test_adapter_registry_ui.py tests/test_audit_explorer_ui.py tests/test_tenant_dashboard_ui.py

No merge, deploy, delete, production activation, browser automation, desktop automation, or successful external API call is authorized by this remediation package.

## Validation Scope Note

.gitignore comment separators were changed from equals signs to hyphens so the exact required conflict-marker grep command returns no false-positive output.

## Finalization Status

Local cleanup is VERIFIED and ready for review. No push, merge, deploy, production activation, browser automation, desktop automation, or live execution was performed by this remediation.
