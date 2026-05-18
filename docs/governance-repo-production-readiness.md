# Governed Repo-to-Production Readiness Scanner

## Purpose

The repo-to-production readiness scanner evaluates whether local GitHub repository metadata is safe enough to move toward commercial or runtime use under USBAY governance.

It is defensive, local-only, and read-only. It does not clone unknown external repositories, execute repository code, call network services, or treat social/media claims as evidence.

## Trust Boundaries

```text
Local repo metadata
  |
  v
USBAY readiness scanner
  |
  +--> dependency lineage signal
  +--> workflow permission signal
  +--> secret exposure signal
  +--> audit evidence signal
  +--> runtime parity signal
  +--> branch protection signal
  |
  v
Hash-only audit report
  |
  v
Human governance review
```

## Verdict Model

- `REPO_PRODUCTION_READY`: all required local metadata signals are present and no unsafe signal is detected.
- `REPO_REVIEW_REQUIRED`: one or more critical signals are missing or unclear.
- `REPO_BLOCKED`: an unsafe signal is detected, such as `.env` presence, secret-like markers, permission widening, or unpinned actions.
- `REPO_UNKNOWN`: local source trust cannot be established.

The scanner never makes a final commercial-readiness claim without human review.

## Evidence Model

The audit report contains only hash-only or categorical evidence:

- repository path fingerprint
- scanned file category counts
- dependency manifest fingerprints
- workflow fingerprints
- reason codes
- final verdict
- policy version/hash
- timestamp
- audit hash

Raw secrets, private keys, approval contents, runtime artifacts, and raw payloads are never logged.

## Fail-Closed Behavior

Missing or ambiguous evidence produces `REPO_REVIEW_REQUIRED` or `REPO_BLOCKED`, never `REPO_PRODUCTION_READY`.

Critical unsafe conditions include:

- workflow permission widening
- unpinned GitHub Actions references
- `.env` files in the repository
- secret-like values in scannable metadata
- unclear dependency lineage
- missing audit or runtime parity evidence

## Human Review

Any commercial-readiness claim requires human review. The scanner provides deterministic evidence for that review; it does not approve, merge, deploy, or certify a repository.
