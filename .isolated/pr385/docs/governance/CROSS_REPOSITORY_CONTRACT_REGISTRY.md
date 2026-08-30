# Cross-Repository Contract Registry

The Policy Brain repository publishes the canonical cross-repository registry
for Enforcement Gateway compatibility checks.

The registry is metadata-only. It does not authorize runtime execution, provider
execution, deployment, production activation, policy mutation, or public API
changes.

Canonical Policy Brain authority for this registry is
`github:USJAY77/usbay-policy-brain-public`, based on the active protected
governance PR chain and human approvals from `USBAY-AUDIT` and
`USBAY-GLOBAL23`.

`USBAY-GLOBAL/usbay-policy-brain` is treated as a legacy private candidate for
this batch because its main branch diverges before the current PB governance
chain. It must not be treated as an independent policy authority unless humans
approve a future authority transfer.

Hashing uses canonical JSON with sorted keys, compact separators, ASCII output,
UTF-8 bytes, SHA-256, lowercase hexadecimal, and `sha256:<hex>` references.
Unprefixed legacy hashes are not production-verified contract hashes.

Production readiness remains blocked unless an independent production
attestation validates repository identity, schema hashes, registry hash, source
commit, validator version, environment classification, and human approval
reference.
