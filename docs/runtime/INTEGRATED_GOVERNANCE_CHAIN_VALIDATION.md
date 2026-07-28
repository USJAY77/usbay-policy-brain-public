# Integrated Governance Chain Validation

PB-1G validates the local execution-control chain across PB-1C, PB-1D, PB-1E, and PB-1F. The validator is metadata-only and never executes providers, commands, deployments, subprocesses, sockets, network calls, or production activation.

## Chain Order

1. Runtime dependency readiness gate.
2. Governed execution adapter contract.
3. Production readiness evidence export.
4. Precommit governance validator.
5. Integrated final decision.

## Decisions

- `READY`: every required governance stage passes.
- `READY_WITH_RESTRICTIONS`: every required governance stage passes and an upstream stage carries explicitly governed restrictions.
- `BLOCKED`: any stage is missing, malformed, stale, degraded, unknown, mismatched, or unsafe.

## Fail-Closed Boundary

The validator blocks on missing or denied policy, missing or expired approval, dependency failures, adapter-contract failures, evidence export failures, evidence-hash mismatches, precommit validation failures, unknown check states, replay/nonce/timestamp failures, direct execution-bypass attempts, sensitive input, and unexpected exceptions.

## Evidence

Evidence is deterministic, hash-only, and redacted. PB-1G records references to upstream decision hashes and package hashes. It does not store prompts, raw payloads, provider responses, credentials, tokens, personal data, or secret values.

## Execution Flags

All integrated outputs preserve:

- `execution_allowed=false`
- `provider_execution=false`
- `production_activation=false`
- `deployment_authorized=false`

The gateway remains authoritative for runtime enforcement. PB-1G validation is not execution authorization.
