# PB-156 Governed Vision Provider Abstraction Layer

## Purpose

PB-156 builds the provider-agnostic vision layer for USBAY Governed Computer-Use Runtime while preserving fail-closed governance, human approval boundaries, and audit-safe evidence.

## Implemented Scope

- Base provider contract with `provider_name`, `provider_version`, `health_check()`, and `analyze_screen(observation)`.
- Normalized provider response schema using `ALLOW`, `BLOCK`, and `FAIL_CLOSED`.
- Deterministic mock provider only.
- Fail-closed provider factory with default `mock` provider.
- Audit-safe metadata for every provider decision.
- No raw screenshot persistence by default.
- No credentials, live API calls, desktop mutation, browser mutation, deployment, or production activation.

## Deterministic Mock Scenarios

- `low_risk_read_screen` -> `ALLOW`
- `unknown_action` -> `BLOCK`
- `malformed_response` -> `FAIL_CLOSED`
- `provider_timeout` -> `FAIL_CLOSED`
- `provider_exception` -> `FAIL_CLOSED`
- `high_risk_click` -> `BLOCK` with human approval required
- `secret_like_text` -> `BLOCK`
- `missing_policy` -> `FAIL_CLOSED`

## Governance Decision

Decision: VERIFIED

Status: READY_FOR_REVIEW

Merge readiness: FAIL_CLOSED_NOT_MERGE_READY until full required test evidence is reviewed by humans and branch governance is completed.
