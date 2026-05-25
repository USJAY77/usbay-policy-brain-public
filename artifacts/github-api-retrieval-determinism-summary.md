# GitHub API Retrieval Determinism Summary

Generated: 2026-05-25T16:19:57Z
Branch: `governance/github-api-retrieval-determinism`
Decision: `GITHUB_WORKFLOW_STATE_UNVERIFIABLE_HANDLED_FAIL_CLOSED`

## Failure Boundary

The failing workflow is `governed-branch-hygiene`.

The observed failure is workflow-run metadata retrieval:

```text
failed to get run -> HTTP 404 Not Found
```

The suspected endpoint class is:

```text
GET repos/{owner}/{repo}/actions/runs/{run_id}
```

## Classification

A missing, stale, deleted, expired, permission-hidden, pagination-missed, or event-filter-excluded workflow run is now classified as:

```text
GITHUB_WORKFLOW_STATE_UNVERIFIABLE
```

This is not treated as governance lineage corruption. It is treated as unavailable GitHub workflow metadata and fails closed.

## Retrieval Assumptions

- Workflow run metadata must be retrievable before it can be used as governance evidence.
- HTTP 404 is a terminal unavailable-state signal for that run id.
- Non-404 transient API failures may be retried by callers, but still fail closed if metadata remains unavailable.
- `exclude_pull_request` or event filtering must never create a silent pass.
- Missing Actions metadata permissions are indistinguishable from unavailable metadata for governance purposes.

## Validation

- Governed branch hygiene focused tests: `46 passed`
- Branch hygiene self-test: `BRANCH_HYGIENE_SELF_TEST=true`
- 404 classifier probe: `GITHUB_WORKFLOW_STATE_UNVERIFIABLE`
- Offline verifier: `VERIFY_PASS`
- Timestamp verifier: `TIMESTAMP_VERIFY_PASS`

## Governance Impact

Governance integrity impact: false.

No governance semantics, lineage semantics, replay semantics, RFC3161 logic, verifier logic, runtime behavior, or UI behavior was modified.

## Conclusion

The instability is isolated to GitHub API workflow-run metadata retrieval. If the run cannot be deterministically retrieved, branch hygiene must not infer success and must classify the state as `GITHUB_WORKFLOW_STATE_UNVERIFIABLE`.
