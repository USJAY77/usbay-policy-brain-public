# Hydra Governance Requirements

Purpose: define the evidence required to certify Hydra for unrestricted external deployment.

Source audit: `docs/audits/USBAY_ARCHITECTURE_AUDIT_002_CORE_ARCHITECTURE.md`

Certification status: BLOCKED until production Hydra governance evidence is complete.

## Verified Controls

Repository evidence verifies:

- `security/hydra_consensus.py` defines three expected nodes and two required votes.
- Consensus fails closed on missing provenance context, release-lineage mismatch, fewer than three decisions, invalid node decisions, request hash mismatch, policy version mismatch, unavailable quorum, stale node/attestation timestamps, missing state fields, policy hash mismatch, nonce/replay divergence, and node disagreement.
- `security/hydra_nodes.py` converts node failures, unavailable nodes, invalid signatures, and missing expected nodes into deny decisions.
- Consensus evidence includes node IDs, timestamps, policy hash, tenant evidence, node decision evidence, attestation evidence, evidence hash, and consensus signature.

## Required Controls

Hydra production certification requires evidence for:

- Node identity enrollment.
- Node role assignment.
- Node public identity.
- Node signing key custody.
- Node key rotation policy.
- Node revocation policy.
- Remote node endpoint identity.
- Remote transport security.
- Attestation freshness policy.
- Replay registry integrity.
- Nonce lifecycle.
- Policy hash binding.
- Tenant binding.
- Consensus evidence retention.
- Consensus evidence export verification.
- Failure-mode audit records.

## Evidence Requirements

| Requirement | Required Evidence | Closure Criteria |
|---|---|---|
| Node enrollment | Signed node enrollment record for each expected node. | All expected nodes have current enrollment evidence. |
| Node role governance | Written role mapping for primary, secondary, and offline backup nodes. | Role mapping matches repository expected roles and is versioned. |
| Key custody | Documented key custody and storage policy. | No default development secrets are accepted for production. |
| Key rotation | Rotation interval, owner, evidence record, and verification output. | Current rotation evidence exists for all active nodes. |
| Revocation | Revocation list or revocation policy with audit evidence. | Revoked nodes cannot contribute to quorum. |
| Remote endpoint identity | Endpoint identity, certificate or equivalent identity proof, and enrollment binding. | Remote node identity is verified before accepting decisions. |
| Transport security | Approved transport policy and validation evidence. | Remote Hydra traffic cannot be spoofed or downgraded. |
| Attestation freshness | Freshness threshold and validation output. | Stale attestation is denied and audited. |
| Replay protection | Nonce hash and replay registry hash evidence. | Reused nonce or divergent replay registry fails closed. |
| Consensus evidence | Consensus evidence hash and signature. | Evidence can be exported and independently verified. |

## Production Blockers

- Development/default Hydra secrets remain unacceptable for unrestricted deployment.
- Remote-node identity and transport governance are not certified by Audit #002.
- Hydra source claims from Notion are not exported or mapped.

## Certification Rule

Hydra may not be certified for unrestricted external deployment until every required control has written evidence, test evidence, and audit evidence.

If any Hydra governance evidence is missing:

Decision: BLOCKED.

