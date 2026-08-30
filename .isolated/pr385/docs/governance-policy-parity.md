# Governance Policy Parity

USBAY policy simulation is only rollout-safe when it can be proven to match the runtime enforcement outcome. The parity validator is a read-only control that compares the deterministic simulation result with runtime decision evidence. It never repairs policy packs, never changes enforcement behavior, and fails closed whenever parity cannot be proven.

## Parity Model

`governance.policy_parity` binds four inputs into the parity proof:

- canonical policy pack hash
- canonical request context hash, including tenant, environment, risk level, and human approval requirement
- simulated decision preview
- runtime decision evidence

The accepted decision states are `ALLOW`, `DENY`, `REQUIRE_HUMAN_REVIEW`, and `FAIL_CLOSED`. Any mismatch produces a machine-readable parity error and blocks rollout.

## Failure Codes

- `PARITY_DECISION_MISMATCH`: simulation and runtime produced different decisions.
- `PARITY_SCOPE_MISMATCH`: tenant or environment scope differs.
- `PARITY_POLICY_HASH_MISMATCH`: runtime evidence references a different policy pack.
- `PARITY_CONTEXT_DRIFT`: runtime evidence references a different request context.
- `PARITY_FAIL_CLOSED_REQUIRED`: simulation required fail-closed behavior but runtime did not fail closed.

## Operator Review Flow

Operators may use `scripts/governance_diagnostics.py verify-policy-parity` to verify a policy pack, request context, and runtime decision record before rollout. `show-parity-summary` emits a compact audit-safe summary, and `explain-parity-failure` maps a failure code to the fail-closed reason.

Diagnostics include only decisions, hashes, scope identifiers, and failure codes. Raw request payloads, approval contents, secrets, and private material are not printed.

## Rollout Safety

Parity validation sits before rollout approval. If policy hash continuity, context continuity, scope continuity, or decision equivalence cannot be proven, USBAY treats the preview as unverifiable and fails closed. Human review may authorize recovery work, but the validator does not auto-repair or downgrade the failure.
