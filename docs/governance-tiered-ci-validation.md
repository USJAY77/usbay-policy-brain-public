# USBAY Tiered CI Validation

## Purpose

USBAY CI is tiered to reduce pull-request latency without weakening fail-closed governance controls. Pull requests run the fast critical path. Full regression remains available through scheduled nightly execution and manual `workflow_dispatch`.

## Pull Request Critical Path

Every pull request must continue to run:

- policy validation workflows
- audit artifact guard
- production-readiness guardrails
- evidence manifest generation and verification
- signature and trust-policy verification
- critical/governance/dependency pytest markers
- CodeQL/security workflows

The PR test tier uses:

```text
pytest -q -m "critical or governance or dependency"
```

Production-readiness PR tests use:

```text
pytest -q -m "critical or dependency" tests/test_ci_tiered_validation.py tests/test_production_readiness.py
```

Both PR collection steps fail closed if no matching tests are collected.

## Dependency Remediation PRs

Dependabot and package remediation PRs run the dependency marker subset in addition to critical and governance tests. Dependency tests verify hashed CI requirements, governance-critical packages, evidence manifest signing dependencies, and canonical fingerprint behavior.

## Full Regression

The full regression workflow runs on a nightly schedule and through manual dispatch. It first verifies that regression or slow tests are collected, then runs:

```text
pytest -q
```

This preserves the full suite without putting the 900+ test path on every pull request.

## Release Requirement

Before release, operators must review the latest full-regression run and confirm:

- production-readiness passed
- full regression passed
- policy verification passed
- audit artifact guard passed
- evidence manifest and timestamp verification passed
- no required governance check was skipped

## Why Full Regression Is Not On Every PR

The full suite includes slow evidence-chain, trust-policy, timestamp, witness, tenant-package, and production-readiness tests. Running the entire suite on every PR creates long feedback loops and encourages unsafe bypass pressure. Tiered CI keeps mandatory fail-closed governance checks on every PR while reserving exhaustive regression for scheduled and release validation.

## Fail-Closed Behavior

Tiering is not a bypass:

- empty PR test collection fails
- empty regression collection fails
- production-readiness remains required
- evidence verification remains required
- no workflow may hide pytest failures with `|| true`
- no branch protection bypass is introduced

## Human Review

Human review remains required before merge. Tiered CI only changes which tests run automatically on the PR critical path; it does not authorize release or production deployment.
