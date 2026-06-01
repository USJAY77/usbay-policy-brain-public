# Policy Brain

Source type: Notion architecture source requested.

Source status: Not available in the active repository/tool context.

Certification status: BLOCKED pending Notion export.

## Export Status

The Notion page `Policy Brain` could not be exported in this environment. No architecture detail from that Notion page is treated as verified.

## Repository Evidence

Verified repository evidence indicates:

- `runtime/policy_validator.py` validates policy JSON, SHA256 digest, signature, and public key artifacts.
- `docs/governance-policy-parity.md` states policy simulation is rollout-safe only when deterministic simulation matches runtime decision evidence.
- `governance/policy_registry.json`, `governance/policy_release_manifest.json`, and related policy files provide repository policy evidence surfaces.
- `gateway/app.py` validates policy registry startup and runtime policy state.

## Verified Facts

- Missing or invalid policy artifacts fail closed.
- Policy digest mismatch fails closed.
- Signature verification failure fails closed.
- Policy/runtime parity must be proven before rollout.
- Human review may authorize recovery work, but does not repair or downgrade validation failure.

## Assumptions

- The Notion Policy Brain page may define the conceptual policy model, but it is unavailable here.
- Repository policy validation and parity docs are the available implementation evidence.

## Traceability Gap

Decision: BLOCKED.

Reason: Notion source evidence unavailable.

