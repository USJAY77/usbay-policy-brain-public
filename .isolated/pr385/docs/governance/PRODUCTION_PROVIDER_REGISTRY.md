# Production Provider Registry

## Purpose

The Phase D2 production provider registry is an offline control plane for future provider adapters. It stores provider metadata only and never connects to providers, starts runtime work, signs data, writes WORM objects, creates object locks, submits regulator exports, or activates production.

## Registry Architecture

Provider records contain:

- provider ID
- integration type
- adapter version
- contract version
- supported capabilities
- tenant scope
- policy version scope
- configuration hash
- enabled flag
- health state
- readiness state
- failure code

No raw configuration, credentials, secrets, private keys, certificate bodies, tokens, or approval contents are stored.

## Adapter Resolution

Adapter selection is deterministic and uses:

- integration type
- provider ID
- tenant
- policy version
- required capabilities
- contract version

Selection fails closed when no provider exists, multiple providers match ambiguously, the provider is disabled, capabilities mismatch, tenant or policy scope mismatches, health is unknown or degraded, or contract versions are incompatible.

## Configuration Boundary

Configuration validation checks provider identifier format, supported integration type, capability declarations, timeout metadata, retry policy metadata, tenant and policy isolation, receipt schema compatibility, contract compatibility, duplicate registration, and conflicting registration.

## Health Observation Boundary

Health is offline metadata only. Health observations must provide provider ID, integration type, observation time, expiry time, status, observation hash, source reference, tenant, and policy version. Expired, malformed, missing, mismatched, degraded, or conflicting observations block readiness.

## Human Activation Boundary

Controlled activation assessment requires provider registration, valid configuration, valid capabilities, valid scope, compatible contract version, valid health observation, compatible receipt schema, and a scoped human approval reference that has not expired.

Even when all checks pass, the result is only `READY_FOR_CONTROLLED_ACTIVATION`. The registry never returns `ACTIVE`, `EXECUTING`, or production authorization.

## Fail-Closed States

Supported states include `UNREGISTERED`, `REGISTERED`, `CONFIGURATION_INVALID`, `DISABLED`, `UNAVAILABLE`, `CAPABILITY_MISMATCH`, `TENANT_SCOPE_MISMATCH`, `POLICY_SCOPE_MISMATCH`, `HEALTH_UNKNOWN`, `HEALTHY`, `DEGRADED`, `BLOCKED`, and `READY_FOR_CONTROLLED_ACTIVATION`.

## Evidence Fields

Readiness evidence is hash-only and includes registry record hash, configuration hash, capability hash, health observation hash, approval reference hash, readiness report hash, correlation ID, tenant, policy version, provider ID, integration type, result, and failure code.

## Future Live-Provider Order

1. RFC3161 timestamp authority
2. External signing authority
3. WORM storage
4. Object-lock storage
5. Regulator submission transport

Each future adapter must remain one governed capability and must preserve the same fail-closed contracts before any provider connection is introduced.

## Rollback

Rollback removes this additive registry module, schema, tests, and documentation. Existing production integration contracts, matrix, validators, evidence contracts, approval behavior, and runtime decisions remain unchanged.
