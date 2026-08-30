1. Purpose
- Add PB-271 through PB-275 controlled end-to-end pilot operations contracts for operator registry, device registry, runtime monitoring, incident response, and readiness certification.

2. Governance Impact
- Adds read-only and dry-run pilot operations controls before any governed end-to-end pilot can be approved.
- Unknown operators, unknown devices, malformed monitoring events, and incomplete incident evidence remain BLOCKED.

3. Risk Assessment
- If these controls are wrong, an unapproved operator, unapproved device, missing incident evidence, or failed runtime trust signal could be misclassified.
- The implementation defaults unknown, missing, malformed, or unsafe pilot operations state to BLOCKED or FAIL_CLOSED.

4. Validation Evidence
- Python compilation, JSON validation, focused pytest, git diff whitespace checks, and conflict marker scan are required before review.

5. Fail-Closed Check
- Unknown pilot operators, unknown pilot devices, unknown runtime failures, non-blocking kill switch state, and missing PB-241 through PB-270 evidence block readiness.

6. Human Approval Required
- Human review is required before merge.
- This PR must not be merged without explicit human approval.
