## PURPOSE
Ensure generated governance PR bodies replace the legacy GitHub PR template for PB governance pull requests.

## RISK
If PR creation falls back to the repository template, unresolved placeholders can enter review and create false audit completeness.

## POLICY LINK
AGENTS.md fail-closed branch governance, human oversight, branch protection, and audit-first engineering requirements.

## REQUIRED APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE CHECKS
- python3 -m py_compile scripts/governance_pr_body_integration.py
- pytest -q tests/test_pb026_pr_body_integration.py
- git diff --check
- conflict marker scan

## AUDIT
PB-026 generates an integration report proving the generated body is populated, placeholders are absent, and PR creation must supply the generated body.

## IMPACT
Governance PR creation fails closed when the generated body is missing, incomplete, or not supplied to the PR creation command.

## Decision
VERIFIED

## Status
READY FOR REVIEW
