## PURPOSE
Eliminate unresolved governance template placeholders from generated PB pull request bodies before PR creation.

## RISK
Unresolved template placeholders can create audit ambiguity, hide missing governance information, or allow incomplete release metadata into review.

## POLICY LINK
AGENTS.md branch governance, fail-closed validation, human oversight, and audit-first engineering requirements.

## REQUIRED APPROVALS
- USBAY-AUDIT
- USBAY-GLOBAL23

## GOVERNANCE CHECKS
- python3 -m py_compile scripts/governance_pr_template_validator.py
- pytest -q tests/test_pb025_pr_template_completion.py
- git diff --check
- conflict marker scan

## AUDIT
PB-025 generates a validation report and generated PR body proving all required sections are populated and all forbidden placeholders are absent.

## IMPACT
Generated PR bodies become deterministic, complete, and fail-closed when required governance fields are missing.

## Decision
VERIFIED

## Status
READY FOR REVIEW
