# Governance Evidence Renewal Runtime

USBAY evidence renewal runtime readiness records are deterministic, local-only planning artifacts. They prove that future renewal execution is blocked behind already verified governance evidence instead of performing renewal work directly.

## Scope

The readiness stub verifies and binds:

- evidence record chain ID
- sealed audit archive root hash
- WORM immutable storage manifest hash
- TSA timestamp token hash
- regulator export profile hash
- policy decision metadata hash

The module produces hash-only records and a local-only URI. It does not write to external storage, call APIs, perform runtime renewal, export raw payloads, or handle private key material.

## Fail-Closed Model

Planning fails closed when any prerequisite evidence is missing or ambiguous:

- evidence record chain missing or mismatched
- sealed archive missing or root hash invalid
- WORM manifest missing or mismatched
- TSA metadata missing, stale, or malformed
- regulator export profile missing or mismatched
- stale policy decision metadata
- reordered renewal entries
- duplicate renewal runtime IDs
- mutable runtime output paths
- unsafe diagnostics or raw payload leakage

## Append-Only Runtime Ordering

Each renewal runtime entry carries:

- append-only position
- previous renewal runtime hash
- replay binding hash
- current renewal runtime hash

Verification recomputes every hash and rejects reordered or replayed entries. The current implementation is a readiness layer only; future runtime renewal engines must consume these records through explicit governance approval.

## Diagnostics

Diagnostics are redacted and hash-only. They must not include raw governance payloads, private keys, approval contents, OCSP/CRL bytes, secrets, runtime artifacts, or external service responses.

## Future Integration Path

Future work may attach real runtime renewal execution after:

- human-approved governance policy decisions
- immutable WORM export integration
- live TSA verification
- regulator export profiles
- runtime authorization gates

Until those controls exist, this module remains local-only and fail-closed.
