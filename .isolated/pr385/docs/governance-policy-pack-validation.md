# USBAY Governance Policy Pack Validation

Governance policy packs must be validated before runtime enforcement. Policy
validation is deterministic, read-only, audit-safe, and fail closed.

## Policy Lifecycle

1. Author a policy pack with schema `usbay.governance_policy_pack.v1`.
2. Include unique policy IDs, explicit scope, validity windows, fail-closed
   defaults, and human approval flags for high-risk policies.
3. Validate the pack with:
   `python3 scripts/governance_diagnostics.py validate-policy-pack --policy-pack <path>`
4. Promote only packs that return `valid=true`.

Invalid packs must not reach runtime enforcement.

## Policy Approval Flow

High-risk or critical policies require `requires_human_approval=true`. Missing
human approval is reported as `POLICY_MISSING_HUMAN_APPROVAL` and blocks the
policy pack.

Diagnostics never print raw approval contents. They report only policy IDs,
machine-readable error codes, and redacted failure details.

## Policy Rollback Guidance

Rollback to a previous policy pack is allowed only after validating the target
pack independently. Operators must verify:

- schema compatibility
- policy ID uniqueness
- no allow/deny conflicts
- non-expired validity windows
- explicit tenant/environment scope
- fail-closed defaults
- human approval on high-risk policy

Human approval is required for recovery from failed policy validation.

## Machine-Readable Errors

- `POLICY_SCHEMA_INVALID`
- `POLICY_DUPLICATE_ID`
- `POLICY_CONFLICTING_RULES`
- `POLICY_MISSING_HUMAN_APPROVAL`
- `POLICY_FAIL_CLOSED_MISSING`
- `POLICY_EXPIRED`
- `POLICY_SCOPE_INVALID`

