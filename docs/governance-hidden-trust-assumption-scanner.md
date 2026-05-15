# USBAY Hidden Trust Assumption Scanner

This capability is defensive, local-only, read-only, and governance-focused.
No exploit generation, attack automation, credential harvesting, or offensive execution is allowed.

## Purpose

The hidden trust assumption scanner is a defensive governance diagnostic that detects source and metadata patterns that can later become runtime governance defects. It is designed for pre-merge review and audit readiness, not runtime enforcement.

## Governance Scope

The scanner reports assumptions involving:

- implicit trust assumptions
- stale runtime authority reuse
- cached approvals without freshness proof
- fallback-to-allow paths
- replayable trust state
- mutable tracked registry usage
- subprocess trust leakage
- runtime policy bypass paths
- ambiguous or unsigned governance metadata
- missing human approval boundaries

## Safety Model

The scanner does not call network services, does not generate exploits, and does not execute scanned code. It reads local files, emits deterministic findings, and uses hash-only evidence identifiers. It never includes source snippets, raw payloads, secrets, private keys, approval contents, or runtime credentials in diagnostics.

## Fail-Closed Inputs

Scanner execution requires deterministic metadata with:

- scanner schema
- signed metadata flag
- SHA256 policy hash
- SHA256 signature hash
- UTC generation timestamp
- scan scope

Missing, malformed, stale, unsigned, ambiguous, or unsafe metadata fails closed. Findings set `merge_gate` to `BLOCK`.

## Output Fields

Each finding includes:

- `risk`
- `mechanism`
- `gap`
- `audit_evidence`
- `human_impact`
- `affected_files`
- `finding_severity`
- `merge_gate`

The `audit_evidence` field is a SHA256 identifier derived from the finding code, file path, and line number. It is intentionally not a source excerpt.

## Operator Flow

1. Generate or provide signed scanner metadata for the review scope.
2. Run the diagnostics CLI against selected files or a local tree.
3. Review findings with human governance reviewers.
4. Fix assumptions in an isolated branch and PR.
5. Re-run the scanner and production-readiness checks before merge.

## Boundaries

This module does not change runtime enforcement, approval validation, replay protection, provenance authority resolution, or registry state. It is a defensive pre-merge governance diagnostic layer only.
