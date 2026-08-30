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
- broad `read-all` / `write-all` permissions
- implicit GitHub Actions permission defaults
- unjustified workflow write scopes
- GitHub Actions references not pinned to full commit SHA
- `.env` files in the repository
- secret-like values in scannable metadata
- unclear dependency lineage
- missing audit or runtime parity evidence
- npm lifecycle scripts in readiness/scanner jobs unless explicitly suppressed with `--ignore-scripts`
- pip installs without hash-verified lock evidence
- workflows that combine dependency installation, write permissions, and `pull_request` or `workflow_run` triggers
- uploaded artifacts without hash or attestation evidence

## Supply-Chain CI Token Hardening

The scanner treats CI token exposure as a governed supply-chain risk. It flags:

- `ACTION_NOT_SHA_PINNED` when any action reference is not a full commit SHA.
- `NPM_LIFECYCLE_SCRIPT_BLOCKED` when `npm install`, `npm i`, or `npm ci` may execute package lifecycle scripts.
- `PIP_HASH_LOCK_MISSING` when pip installs lack `--require-hashes`.
- `DEPENDENCY_INSTALL_UNTRUSTED` when dependency installation can execute untrusted package code.
- `CI_TOKEN_EXFILTRATION_RISK` when dependency installation runs in a workflow with write permissions on `pull_request` or `workflow_run`.
- `SECRET_EXPOSURE_RISK` when workflow metadata references token, secret, bearer, or `.env` material.
- `ARTIFACT_ATTESTATION_MISSING` when artifact upload lacks visible hash or attestation evidence.
- `READ_ALL_PERMISSION_BLOCKED` and `WRITE_ALL_PERMISSION_BLOCKED` when broad GitHub token permission shortcuts are used.
- `IMPLICIT_PERMISSION_WIDENING` when a workflow omits explicit permissions.
- `UNNECESSARY_WRITE_SCOPE` when a workflow declares a write scope without a governed workflow-specific justification.
- `LEAST_PRIVILEGE_ENFORCED` when explicit scoped permissions pass the least-privilege gate.
- `WORKFLOW_PERMISSION_SCOPE_APPROVED` when every declared workflow permission scope is known, explicit, and approved for the workflow context.

The report remains hash-only. It provides file fingerprints and reason codes, never token values, secret values, environment contents, package payloads, or raw workflow bodies.

## Structural Workflow Analysis

Workflow governance uses deterministic structural parsing for GitHub Actions metadata. Legacy text heuristics may still identify command-string risk, such as dependency installation or secret marker candidates, but heuristic output is not the authoritative source for permissions, workflow capability, or mutation intent.

The structural workflow manifest records:

- workflow fingerprint
- capability graph: `READ_ONLY`, `MUTATING`, `DEPLOYMENT`, `GOVERNANCE`, `ATTESTATION`, or `UNKNOWN`
- workflow-level and job-level permission graph
- mutation intent, including PR mutation, commit push, release creation, artifact upload, comments/issues, and branch/tag mutation
- action SHA-pinning status
- deterministic audit hash
- parser provenance: parser version, semantic schema version, parser mode, workflow manifest hash, and capability graph hash

Anchors, aliases, merge keys, malformed permission maps, multiline permission scalars, reusable workflows, and unclear workflow structures fail closed with `YAML_STRUCTURE_UNSAFE`, `WORKFLOW_STRUCTURE_UNKNOWN`, or `WORKFLOW_CAPABILITY_UNCLEAR`. The scanner does not execute workflows, expand remote reusable workflows, fetch external definitions, or log raw workflow payloads.

If the semantic parser cannot produce a trusted workflow object, readiness fails closed with `SEMANTIC_WORKFLOW_ANALYSIS_UNAVAILABLE`. No regex-only path is allowed to promote a workflow to trusted status.

## Human Review

Any commercial-readiness claim requires human review. The scanner provides deterministic evidence for that review; it does not approve, merge, deploy, or certify a repository.
