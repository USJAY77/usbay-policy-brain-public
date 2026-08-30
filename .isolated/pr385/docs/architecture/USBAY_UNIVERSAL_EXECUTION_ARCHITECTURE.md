# USBAY Universal Execution Architecture

Source type: Notion architecture source requested.

Source status: Not available in the active repository/tool context.

Certification status: BLOCKED pending Notion export.

## Export Status

The Notion page `USBAY Universal Execution Architecture` could not be exported in this environment. No architecture detail from that Notion page is treated as verified.

## Repository Evidence

Verified repository evidence indicates:

- `docs/runtime-deployment-governance.md` identifies `gateway.app:app` as the deployment entrypoint.
- `gateway/app.py` contains execution validation and `/execute` routing.
- `runtime/enforcement_gateway.py` documents fail-closed enforcement gateway guarantees.
- `runtime/policy_validator.py` validates policy integrity and fails closed on missing or invalid policy artifacts.
- `security/hydra_consensus.py` evaluates multi-node consensus before allow decisions.
- `audit/hash_chain.py` appends and verifies audit hash-chain events.

## Verified Facts

- Runtime deployment must use the platform-provided `PORT` and `gateway.app:app`.
- Missing, invalid, or unverifiable execution decision evidence blocks execution.
- Execution validation checks decision ID, signatures, actor binding, algorithm version, replay state, nonce binding, decision time, Hydra/policy verification, execution routing, and mark-used semantics before allowing execution.
- Human approval does not replace required runtime decision or audit evidence.

## Assumptions

- The Notion architecture page may define a broader universal execution model, but its content is unavailable.
- Repository execution architecture is assumed to map to `gateway/app.py`, `runtime/enforcement_gateway.py`, `runtime/policy_validator.py`, Hydra security modules, and audit modules.

## Traceability Gap

Decision: BLOCKED.

Reason: Notion source evidence unavailable.

