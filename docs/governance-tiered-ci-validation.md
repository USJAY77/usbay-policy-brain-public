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

## Bounded Validation Watchdog

All validation lanes run through `scripts/run_bounded_validation.py` instead of unbounded shell execution.
The watchdog records hash-only evidence for each lane and fails closed on timeout.

Lane limits:

- `fast_pr`: 600 seconds, reason code `VALIDATION_TIMEOUT_FAST_PR`
- `dependency`: 600 seconds, reason code `VALIDATION_TIMEOUT_DEPENDENCY`
- `production_readiness`: 1200 seconds, reason code `VALIDATION_TIMEOUT_PRODUCTION_READINESS`
- `full_regression`: 7200 seconds, reason code `VALIDATION_TIMEOUT_FULL_REGRESSION`

Workflow scheduler bounds:

- Dependabot governed auto-merge job: 10 minutes
- PR critical governance job: 15 minutes
- production-readiness job: 30 minutes
- nightly/manual full regression job: 130 minutes

Timeout evidence includes the lane, status, reason code, command hash, duration, configured timeout, exit code, and `partial_audit_preserved=true`.
It does not include command output, secrets, raw payloads, private keys, approval contents, or tokens.
Timeouts are blocking governance failures, not soft warnings.

## Dependency Remediation PRs

Dependabot and package remediation PRs run the dependency marker subset in addition to critical and governance tests. Dependency tests verify hashed CI requirements, governance-critical packages, evidence manifest signing dependencies, and canonical fingerprint behavior.

## Full Regression

The full regression workflow runs on a nightly schedule and through manual dispatch. It first verifies that regression or slow tests are collected, then runs:

```text
pytest -q
```

This preserves the full suite without putting the 900+ test path on every pull request.
The full regression lane remains bounded by the watchdog and is not used as a PR auto-merge prerequisite.

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
- validation timeouts produce explicit `VALIDATION_TIMEOUT_*` reason codes and fail closed
- partial timeout audit evidence is preserved for operator review

## Human Review

Human review remains required before merge. Tiered CI only changes which tests run automatically on the PR critical path; it does not authorize release or production deployment.
