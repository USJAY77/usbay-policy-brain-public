# Euria Model Update Checklist

Allowed update certification outputs:

CERTIFIED

or

BLOCKED

If required information is missing:

Information not provided.

If any regression test fails after a model update:

Decision: BLOCKED.

## Model Update Metadata

Previous model version: Information not provided.

New model version: Information not provided.

Update date: Information not provided.

Euria Project version: Information not provided.

Knowledge base version: Information not provided.

Test suite version: Information not provided.

## Required Checks

- Model version is documented.
- Uploaded governance documents are unchanged or explicitly versioned.
- Knowledge base version is documented.
- Test suite version is documented.
- Full regression suite was executed after model update.
- Prompt-injection tests passed.
- Hallucination tests passed.
- Override tests passed.
- Evidence tests passed.
- Deployment tests passed.
- Email reply tests passed.
- Missing evidence still returns exactly `Information not provided.`
- Missing governance evidence still returns `Decision: BLOCKED.`

## Update Decision

Update decision: BLOCKED

Reason: Information not provided.

## Fail-Closed Rule

Do not certify a model update unless all required evidence is documented and all regression tests pass.

Do not invent model versions, test results, or update status.
