## PURPOSE

Build the provider-agnostic vision layer for USBAY Governed Computer-Use Runtime without enabling uncontrolled computer use.

## RISK

Uncontrolled screen-reading agents can follow prompt injection from the screen, click dangerous UI targets, leak sensitive screen data, execute without human approval, create unaudited decisions, silently depend on one external AI provider, or store raw screenshots in logs.

## POLICY LINK

- AGENTS.md fail-closed governance
- AGENTS.md human oversight
- AGENTS.md audit-first engineering
- docs/architecture/USBAY_GOVERNED_COMPUTER_USE_RUNTIME.md
- docs/architecture/USBAY_GOVERNED_VISION_PROVIDER_LAYER.md
- policy/computer_use_policy.json

## REQUIRED APPROVALS

- USBAY-AUDIT review required before merge.
- USBAY-GLOBAL23 review required before merge.
- No production activation is authorized by this PB.

## GOVERNANCE CHECKS

- Base provider contract defined.
- Deterministic mock provider implemented.
- Provider factory defaults to mock.
- Unknown provider fails closed.
- Provider exception fails closed.
- Provider timeout fails closed.
- Malformed response fails closed.
- High-risk action without approval marker fails closed.
- Secret-like typed text blocks.
- Missing policy fails closed.
- Provider output uses one normalized schema.
- Raw screenshots are not persisted.

## AUDIT

- Every provider decision records action ID, provider, decision, reason, timestamp, hash, and raw screenshot status.
- Raw screenshots, credentials, API keys, full screen text containing secrets, and unnecessary personal data are not written to audit logs.
- Screen text is represented only by hash when present in test observations.

## IMPACT

The runtime gains a governed screen-understanding boundary while remaining local-only, mock-only, and non-mutating. Live Gemini/OpenAI/Claude API adapters remain future work requiring separate governance review.

## Decision

VERIFIED

## Status

READY_FOR_REVIEW

## Merge Readiness

FAIL_CLOSED_NOT_MERGE_READY
