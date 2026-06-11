# USBAY Governed Vision Provider Layer

## Purpose

The governed vision provider layer gives USBAY a provider-agnostic way to interpret screen observations without becoming an uncontrolled computer-use agent. Providers may describe a screen and propose an action, but they cannot execute, approve, click, type, deploy, merge, delete, or bypass policy.

## Risk Model

Uncontrolled screen-reading agents can follow prompt-injected UI text, leak sensitive screen data, depend silently on one external model provider, and create unaudited decisions. USBAY treats provider output as untrusted until it is normalized, validated, policy checked, approval gated, and audited.

## Provider Boundary

The provider interface requires:

- `provider_name`
- `provider_version`
- `health_check()`
- `analyze_screen(observation)`

All provider responses use one normalized schema with:

- provider
- status: `ALLOW`, `BLOCK`, or `FAIL_CLOSED`
- screen summary
- proposed action type, target, and risk
- human approval requirement
- reason
- audit metadata

PB-156 implements only the deterministic mock provider. Gemini, OpenAI, and Claude live adapters are future boundaries and require a separate reviewed change before any live API call can exist.

## Fail-Closed Behavior

The provider layer returns `FAIL_CLOSED` when:

- provider is missing
- provider name is unknown
- provider raises an exception
- provider times out
- provider returns malformed output
- provider proposes a high-risk action without an approval marker
- observation is missing required fields

Provider output that proposes an unknown action returns `BLOCK`.

## No Raw Screenshot Logging

Raw screenshots are not persisted by default. Audit records include only provider name, decision, reason, action ID, timestamp, observation hash, audit hash, and `raw_screenshot_stored=false`.

## No Live Provider Calls Yet

PB-156 does not call Gemini, OpenAI, Claude, or any external provider. It does not read credentials, environment secrets, API keys, or network configuration.

## Human Approval Boundary

Provider analysis does not bypass the USBAY approval queue, approval token, approval expiration, deny path, replay protection, or runtime audit chain. High-risk proposed actions remain blocked or require human approval before any execution path can be considered.

## Audit Evidence

Every provider decision records audit-safe metadata through the computer-use audit recorder. Secret-like screen text is represented only by hashes and never written raw to logs.
