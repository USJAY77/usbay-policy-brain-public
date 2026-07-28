# Pre-Commit Governance

USBAY uses repository-owned pre-commit configuration so local commit checks are portable and reviewable. The repository previously had a local generated hook installed, but no tracked `.pre-commit-config.yaml`; normal commits therefore failed before governance metadata could be committed.

## Installation

Install `pre-commit` in the developer environment, then run:

```bash
pre-commit install
```

The tracked configuration uses local dependency-free hooks. It does not install formatters, call network services, or rewrite files.

## Normal Use

Commits run the configured checks automatically:

- trailing whitespace and final newline validation
- JSON syntax validation
- Python syntax validation
- accidental secret marker detection

Expected failures are fail-closed and must be fixed before committing.

## Manual Execution

Run all local hooks with:

```bash
pre-commit run --all-files
```

Equivalent direct checks are:

```bash
python3 scripts/precommit_governance_checks.py whitespace $(git ls-files)
python3 scripts/precommit_governance_checks.py json $(git ls-files '*.json')
python3 scripts/precommit_governance_checks.py python $(git ls-files '*.py')
python3 scripts/precommit_governance_checks.py secrets $(git ls-files)
```

## CI Relationship

CI remains the merge authority. Local pre-commit checks catch deterministic syntax, whitespace, JSON, and accidental secret-marker issues before review. They do not replace production-readiness, policy verification, security, full pytest, or human review gates.

## No `--no-verify`

`--no-verify` is not the normal USBAY workflow. If a hook fails, the fix is to address the specific deterministic blocker or update this tracked governance configuration through review.
