# PB-172 Governance Template Enforcement

Decision: VERIFIED
Status: READY_FOR_REVIEW

## Template Inventory
- `templates/generated_commit_title_template.txt`
- `templates/generated_pr_title_template.txt`
- `templates/generated_pr_body_template.md`
- `templates/generated_review_template.md`
- `templates/generated_evidence_template.md`

## Enforcement Design
`scripts/validate_governance_templates.py` is the canonical validator for governance titles, PR bodies, review templates, and evidence templates.

Fail-closed conditions:
- missing title
- invalid title format
- missing PB number
- missing required PR section
- missing audit section
- missing impact section
- missing template file

## Future PB Compliance Matrix
Every future PB must produce commit title, PR title, PR body, review artifact, and evidence package from the canonical templates and validate them before review.

## Validation
- Focused tests: PASS, 8 passed in 0.06s
- Validator CLI: PASS
- Compile: PASS
- Full pytest: PASS, 1781 passed in 5006.65s (1:23:26)

## Restrictions
No deployment, merge, delete, branch cleanup, runtime mutation, external API calls, or production activation was performed.
