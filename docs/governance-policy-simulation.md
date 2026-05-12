# USBAY Governance Policy Simulation

Policy simulation previews a governance decision before runtime enforcement. It
is read-only, deterministic, audit-safe, and fail closed on invalid or
ambiguous inputs.

## Simulation Lifecycle

1. Validate the policy pack.
2. Load a request context containing public request selectors such as `action`,
   `resource`, and optional `condition`.
3. Apply tenant and environment scope.
4. Match deny and allow rules.
5. Return one preview decision:
   - `ALLOW`
   - `DENY`
   - `REQUIRE_HUMAN_REVIEW`
   - `FAIL_CLOSED`

Simulation does not change runtime enforcement and never repairs policy packs.

## Operator Review Flow

Operators can run:

```text
python3 scripts/governance_diagnostics.py simulate-policy --policy-pack <pack.json> --request-context <request.json> --tenant-id t1 --environment test --risk-level low
```

For failed or human-review previews, use:

```text
python3 scripts/governance_diagnostics.py explain-policy-decision --simulation-error-code SIM_HUMAN_APPROVAL_REQUIRED
```

Diagnostics include only decision codes, matched policy IDs, scope labels, and
redacted error metadata. They must not include raw approval contents or secrets.

## Policy Rollout Safety

New policy packs should be simulated against representative request contexts
before rollout. A `FAIL_CLOSED` preview must be treated as a release blocker
until the underlying policy pack, scope, conflict, or human-review condition is
resolved through governed review.

