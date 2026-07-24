# Provider Activation Workflow and Offline Controlled Receipts

## Purpose

The Provider Activation Workflow is the offline control layer between the provider registry and any future live provider implementation. It translates approved provider-registry readiness into deterministic activation metadata for human review only.

The workflow does not activate a provider, contact an external service, mutate the provider registry, or authorize production execution.

## Activation Workflow

The activation request binds:

- provider identity
- integration type
- tenant
- policy version
- provider registry record hash
- configuration hash
- capability hash
- health observation hash
- external approval reference hash
- request chronology
- correlation id
- requested-by reference
- reason code

Missing, malformed, expired, duplicate, conflicting, or scope-mismatched requests fail closed.

## Approval Binding

Human approval remains external. The workflow stores and validates only a hash/reference.

Approval binding verifies:

- approval exists
- approval has not expired
- approval scope matches tenant, policy version, provider, and integration type
- approval hash matches the activation request
- approval is not replayed
- approval is not already consumed
- approval version is compatible

Approval validation never activates a provider.

## Offline Simulation Boundary

The offline simulation consumes metadata and hashes only. It simulates validation of:

- activation request metadata
- approval binding
- provider selection
- configuration hash
- capability metadata
- health observation metadata
- receipt-schema compatibility
- timeout metadata
- retry policy metadata
- failure mapping
- rollback readiness

The simulation never performs network access, calls providers, opens sockets, starts subprocesses, starts threads, uses async execution, invokes Redis/Kafka, starts tmux, reads credentials, or mutates state.

## Simulated Receipt Envelope

The simulated receipt envelope is deterministic and hash-only. It contains:

- simulated receipt id
- simulation id
- activation request id
- provider id
- integration type
- tenant
- policy version
- contract version
- registry record hash
- readiness report hash
- approval reference hash
- simulated result
- failure code
- issued and expiry timestamps
- correlation id
- receipt hash
- previous receipt hash
- `simulation_only=true`

Raw payloads, secrets, credentials, private keys, certificate bodies, access tokens, prompts, approval contents, provider responses, and provider data are forbidden.

## Receipt-Chain Verification

Simulated receipts form an append-only hash chain using canonical JSON and `sha256:<64 hex>` references.

Verification fails closed on:

- duplicate receipts
- replayed activation requests
- deleted prefixes
- reordered links
- tampering
- tenant mismatch
- policy-version mismatch
- provider mismatch
- integration-type mismatch
- execution flags set to true
- raw-data markers

## Production-Decision Package

The final production-decision package is a human-review package only. It contains references to:

- activation request
- provider registry record
- readiness evidence
- health observation
- human approval
- simulated receipt
- simulated receipt chain
- rollback plan
- unresolved risk list

The only positive package result is `READY_FOR_HUMAN_PRODUCTION_DECISION`. This result is not authorization.

## Mandatory Execution Flags

Every workflow output preserves:

- `execution_allowed=false`
- `provider_execution=false`
- `production_activation=false`
- `runtime_execution=false`
- `deployment_execution=false`
- `policy_mutation=false`
- `network_access=false`
- `credentials_access=false`
- `live_provider_call=false`

## Future Live-Provider Sequence

Future live-provider activation must be implemented in a separate reviewed capability. It must require:

- provider-specific adapter review
- live receipt validation
- human production approval
- external timestamp/signing/WORM controls where applicable
- rollback evidence
- post-activation audit evidence

This offline workflow is not a substitute for those controls.

## Rollback Procedure

If the workflow output is incorrect, discard the generated activation request and simulated receipt references. Because the workflow is metadata-only and append-only, rollback is reference isolation rather than external state reversal. No provider state or registry state is mutated by this component.
