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

Batch 2 migrated private Phase B/C runtime `_canonical_hash` wrappers whose
legacy behavior already matched `sha256_reference(..., default_to_str=True)`.
Those wrappers remain in place to preserve module-local compatibility while
removing duplicate canonical serialization logic.

Batch 3 migrated low-risk runtime and governance wrappers whose legacy behavior
already matched `canonical_json(..., default_to_str=True)`, `sha256_json(...,
default_to_str=True)`, or bare `sha256_text(...)`. Public wrapper names remain
available so existing evidence and import contracts continue to verify against
the same prefixed and unprefixed SHA-256 values.
