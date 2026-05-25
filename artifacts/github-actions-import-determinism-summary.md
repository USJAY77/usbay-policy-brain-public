# GitHub Actions Import Determinism Summary

Generated: 2026-05-25T15:29:18Z
Branch: `governance/github-actions-import-determinism`
Decision: `GITHUB_ACTIONS_IMPORT_DETERMINISM_STABLE`

## Failure

The failing workflow was `dependabot-governed-automerge`, job `governed-dependabot-automerge`.

The failing import was:

```python
from governance.canonical_governance_state import build_canonical_governance_state, sha256_text
```

The observed failure was `ModuleNotFoundError: No module named 'governance'`.

## Root Cause

The workflow invoked Python scripts directly from `scripts/`, while module discovery relied on implicit repository-root placement on `sys.path`. That made GitHub Actions behavior depend on ambient runner path state instead of an explicit workspace import root.

## Remediation

- Pinned `PYTHONPATH` to `${{ github.workspace }}` in:
  - `audit-artifact-guard`
  - `dependabot-governed-automerge`
  - `governance-check`
  - `policy-verification`
- Added deterministic repository-root bootstrap to `scripts/governed_dependabot_pr_automation.py`.
- Added focused tests that assert the governed action workflows pin `PYTHONPATH` to the workspace.

## Validation

- Workflow YAML parse: PASS
- Package `__init__.py` coverage: PASS
- Direct governed-dependabot script execution without `PYTHONPATH`: PASS
- Governance, verifier, RFC3161, dependency governance, and runtime policy imports: PASS
- Governed-dependabot focused tests: `48 passed`
- Policy/dependency/RFC3161/verifier focused tests: `41 passed`
- Offline verifier: `VERIFY_PASS` and `TIMESTAMP_VERIFY_PASS`

## Governance Impact

Governance integrity impact: false.

No RFC3161 logic, verifier semantics, replay semantics, governance evidence semantics, or runtime/UI behavior was modified.

## Fail-Closed Conclusion

No workflow execution path ambiguity remains for the named governance workflows. If ambiguity reappears, the required fail-closed mark is `GITHUB_ACTIONS_ENVIRONMENT_UNSTABLE`.
