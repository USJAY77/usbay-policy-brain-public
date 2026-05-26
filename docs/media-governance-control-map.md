# USBAY Media Governance Control Map

This control map summarizes the non-production AI media governance demo layers. Each layer is evidence-based and fail-closed.

| Layer | Evidence | Control | Fail-Closed Trigger |
| --- | --- | --- | --- |
| Provenance | `artifacts/media-governance-demo-manifest.json` | Binds lifecycle to a provenance hash placeholder | Observed hash mismatch |
| Approval | `governance/approved_github_actions_policy.approvals.json` | Requires two-approval chain scaffolding | Missing or insufficient approval |
| Timestamp | `governance/rfc3161_timestamp_policy.json` | Requires timestamp policy reference | Missing timestamp evidence |
| Rights/Consent | `governance/media_rights_consent_policy.json` | Requires actor, voice, sample, dataset, royalty, and legal review evidence | Missing or expired consent |
| Release Token | `governance/media_release_token_policy.json` | Binds release token to media asset, approval, timestamp, provenance, and rights | Missing, expired, or mis-scoped token |
| Distribution | `governance/media_distribution_gateway_policy.json` | Requires platform authorization and signed placeholder request | Unknown platform, missing authority, scope mismatch |
| Revocation | `governance/media_revocation_policy.json` | Allows emergency freeze, revocation, dispute hold, and takedown blocking | Revoked token, frozen asset, dispute hold, takedown state |
| Jurisdiction | `artifacts/media-jurisdiction-export-manifest.json` | Applies regional scope, restrictions, and cross-region conflict controls | Unknown jurisdiction, conflict, region lock, revoked regional rights |
| Audit Export | `artifacts/media-audit-export-manifest.json` | Requires scoped reference-only export lineage | Missing scope, missing lineage, unsigned manifest, payload detection |
| Model Drift | `artifacts/media-drift-governance-manifest.json` | Detects model, policy, provenance, approval, export, distribution, and revocation drift | Drift finding or lineage gap |
| Watchtower | `artifacts/media-governance-watchtower-manifest.json` | Scores governance health and escalation state | Critical score, repeated drift, lineage instability |
| Human Escalation | `artifacts/media-human-escalation-manifest.json` | Requires explicit human crisis review scaffolding | Missing review, unresolved crisis, timeout |
| Recovery | `artifacts/media-recovery-governance-manifest.json` | Requires post-incident recovery and controlled reauthorization evidence | Missing review, stale recovery, unresolved incident |
| Red-Team | `artifacts/media-redteam-governance-manifest.json` | Simulates adversarial governance manipulation attempts | Forgery, replay, spoofing, bypass, tamper, attack state |
| Immutable Evidence | `artifacts/media-immutable-evidence-manifest.json` | Models signed, timestamp-bound, chain-hash evidence references | Missing signature reference, chain hash, timestamp, anchor, or lineage continuity |
| Orchestration | `artifacts/media-lifecycle-orchestration-manifest.json` | Models declarative stage order and transition allowlist | Unknown stage, stage order violation, missing gate, runtime override attempt |
| Dashboard/Export | `artifacts/media-dashboard-export-manifest.json` | Models scoped dashboard/export readiness references | Unscoped export, missing purpose, sensitive payload marker, missing export reference |
| Crypto Authority | `artifacts/media-crypto-authority-manifest.json` | Models signature authority references and scope binding | Missing signature reference, unknown authority, stale key reference, unbound scope |

## Operating Rule

Prior PASS states do not override later governance failures. Red-team, revocation, crisis, recovery, watchtower, jurisdiction, drift, immutable evidence, orchestration, dashboard/export, and cryptographic authority findings remain blocking until human-owned policy evidence clears them.
