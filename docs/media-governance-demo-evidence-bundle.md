# USBAY Media Governance Demo Evidence Bundle

This evidence bundle is a non-production, reference-only customer-demo scaffold. It collects pointers to the governance manifests and policies used by the AI media lifecycle demo.

## Contents

The bundle references these layers:

- Provenance
- Approval
- RFC3161-style timestamp policy
- Rights and consent
- Release token
- Distribution gateway
- Revocation and emergency freeze
- Jurisdiction governance
- Audit export
- Model drift
- Watchtower health scoring
- Human escalation
- Recovery and reauthorization
- Red-team governance override

## Reference-Only Boundary

The bundle does not include media payload bodies, person-identifying data, auth material, legal document bodies, platform bearer material, protected creative works, real platform integrations, real signing keys, or production authority.

## Validation Intent

The bundle exists to prove that each lifecycle layer has explicit evidence references and fail-closed behavior. A missing reference, malformed manifest, unsupported scope, attack state, revoked release, unresolved crisis, or red-team finding blocks the demo decision path.

## Command

Run the demo validation with:

```bash
python3 -m pytest -q tests/test_media_governance_lifecycle_e2e.py
```
