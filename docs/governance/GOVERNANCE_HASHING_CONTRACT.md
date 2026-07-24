# Governance Hashing Contract

USBAY governance hashing uses deterministic JSON serialization and SHA-256
digests. The shared contract lives in `governance.hashing` and provides
immutable helpers for canonical JSON, hex digests, and `sha256:<hex>`
references.

## Canonical Serialization

- Sort keys deterministically.
- Use compact separators.
- Preserve ASCII-only output.
- Avoid raw payload logging.
- Use `default_to_str=True` only for legacy compatibility paths that already
  serialized non-JSON values with `default=str`.

## Hash References

- Hash-only evidence references use `sha256:<64 lowercase hex>`.
- Bare hex digests remain available for legacy contracts that already persisted
  unprefixed SHA-256 values.
- Invalid, malformed, uppercase, missing, prefixed incorrectly, or truncated
  hashes must fail closed.

## Migration Notes

Existing public wrappers such as `canonical_audit_json` and
`sha256_audit_hash` remain available for backward compatibility. New
governance code should import from `governance.hashing` directly unless it is
part of the audit evidence public API.
