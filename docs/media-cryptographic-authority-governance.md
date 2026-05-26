# USBAY Media Cryptographic Authority Governance

This non-production scaffold makes cryptographic authority gaps explicit without adding real keys, HSM integration, private key storage, signing implementation, or production trust authority.

## Governed Gap

Production media governance needs signed references for approvals, escalation, recovery, and evidence manifests. This scaffold checks only placeholder references and scope binding.

## Fail-Closed Conditions

- Signature reference is missing
- Signing authority is unknown
- Key reference is stale
- Signature scope is unbound

## Demo Boundary

The manifest contains placeholder references only. Humans must define production signing authority, key custody, rotation, attestation, HSM use, and audit procedures before production use.
