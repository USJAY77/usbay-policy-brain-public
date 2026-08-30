# Canonical Gateway Authorization Request Contract Publication (v1)

Canonical contract identifier:

`usbay.enforcement_gateway.authorization_request.v1`

This publication binds the exact contract merged in PR #316
(`governance/euria_gateway_authorization_request.py` and
`governance/evidence/euria_gateway_authorization_request_v1_schema.json`)
into the existing cross-repository contract registry
(`governance/contracts/cross_repository_contract_registry.json`) so an
independent Enforcement Gateway checkout can pin and verify:

- `contract_id`
- `version` (`v1`, immutable)
- canonical schema hash (`sha256:` reference over canonical JSON)

## Artifacts

- `governance/contracts/gateway_authorization_request_v1_publication.json` —
  the canonical publication (identifier, version, schema reference + hash,
  serialization/hashing rules, request-hash rule, producer authority,
  compatibility target, publication metadata, authority invariants).
- Registry pins under `canonical_schema_hashes`:
  `gateway_authorization_request_v1_publication` and
  `gateway_authorization_request_v1_schema`. The existing registry validator
  recomputes both hashes; a mutated artifact fails registry validation and
  cannot masquerade as canonical v1.
- `governance/gateway_authorization_contract_publication.py` — fail-closed
  validator and consumer-facing `resolve_canonical_contract()`.

## Hashing / serialization

Repository canonical hash contract: SHA-256 over
`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)` UTF-8
bytes, lowercase hex, `sha256:<hex>` references. The request hash is the
`sha256:` reference of the request object with the `request_hash` field
removed (reference implementation:
`governance.euria_gateway_authorization_request.compute_gateway_authorization_request_hash`).

## Immutability

Version `v1` is immutable. Any semantic change requires publishing a new
governed contract version; the registry hash pins make silent mutation of v1
fail closed.

## Consumer pinning

An independent Enforcement Gateway checkout must record the canonical
`contract_id`, `version`, and `canonical_schema_hash` (optionally the
publication hash) out-of-band, and resolve via
`resolve_canonical_contract(..., expected_schema_hash=...)`. Recomputed
checkout-local hashes detect unilateral drift only; the consumer's own pin is
what detects a coordinated artifact+registry mutation, and a mismatch fails
closed (`CONTRACT_PIN_MISMATCH`). A future governed version may additionally
anchor the registry with a detached signature (following the existing
`governance/policy_registry.sig` pattern); that requires governed key
material and is out of scope for this publication.

## Authority

The publication is metadata-only and grants no execution authority:

- `EURIA_EXECUTION_AUTHORITY=false`, `EURIA_POLICY_AUTHORITY=false`,
  `EURIA_APPROVAL_AUTHORITY=false`, `EURIA_DEPLOYMENT_AUTHORITY=false`
- `POLICY_BRAIN_EXECUTION_AUTHORITY=false`
- `PILOT_READY != EXECUTION_AUTHORIZED`
- `ACTIVATION_VALIDATED != EXECUTION_AUTHORIZED`
- `GATEWAY_REQUEST_CREATED != EXECUTION_AUTHORIZED`

Only the Enforcement Gateway may issue the final runtime ALLOW / BLOCK.
