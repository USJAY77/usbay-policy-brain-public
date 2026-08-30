# Hydra Defense Stack

Source type: Notion architecture source requested.

Source status: Not available in the active repository/tool context.

Certification status: BLOCKED pending Notion export.

## Export Status

The Notion page `Hydra Defense Stack` could not be exported in this environment. No architecture detail from that Notion page is treated as verified.

## Repository Evidence

Verified repository evidence indicates:

- `security/hydra_consensus.py` defines three expected nodes and two required votes.
- `security/hydra_consensus.py` fails closed on missing provenance context, release-lineage mismatch, fewer than three decisions, invalid node decisions, request hash mismatch, policy version mismatch, unavailable quorum, stale node/attestation timestamps, missing state fields, policy hash mismatch, nonce/replay divergence, and node disagreement.
- `security/hydra_nodes.py` collects node decisions from in-process, subprocess, and remote node clients.
- `security/hydra_nodes.py` converts unavailable nodes, missing nodes, invalid signatures, and node failures into deny decisions.

## Verified Facts

- Hydra requires a quorum before allow consensus.
- Node decision signatures are verified.
- Missing or invalid node evidence fails closed.
- Replay and nonce divergence fail closed.
- Remote node behavior exists and requires production identity/transport governance before unrestricted deployment.

## Assumptions

- The Notion Hydra Defense Stack may define additional controls not visible in repository evidence.
- Repository Hydra code is treated as the verified implementation surface until Notion export is available.

## Traceability Gap

Decision: BLOCKED.

Reason: Notion source evidence unavailable.

