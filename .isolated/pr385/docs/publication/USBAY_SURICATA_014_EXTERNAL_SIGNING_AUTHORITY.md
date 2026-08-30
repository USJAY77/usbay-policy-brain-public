# USBAY-SURICATA-014 External Signing Authority Integration Gate

## Risk

Suricata rule evidence is unsafe if Policy Brain cannot prove which external signing authority governed the accepted rule-source signature. Missing, stale, revoked, malformed, or unapproved authority evidence could allow poisoned rule bundles, stale signing trust, or unverifiable network IDS evidence to influence publication or execution decisions.

## Mechanism

USBAY-SURICATA-014 adds a local, fail-closed external signing authority proof model. The model validates only redacted authority metadata:

- authority_id
- authority_fingerprint
- policy_version
- approved
- human_approved
- issued_at
- expires_at
- evidence_hash

The authority hash is deterministic and derived only from minimal redacted fields. The runtime does not store public key material, certificate bodies, raw Suricata rules, raw EVE JSON, IP addresses, domains, source URLs, payloads, usernames, or user-agent values.

RuntimeAggregator now requires approved signing authority proof whenever Suricata evidence participates in a decision. The proof must match the existing Suricata trust-anchor fingerprint and policy version. Missing or invalid proof blocks with `NETWORK_IDS_EVIDENCE_INVALID`.

## Fail-Closed Rules

The signing authority gate blocks when:

- authority proof is missing
- authority is revoked or not approved
- human approval is missing
- authority is expired or not yet valid
- fingerprint is malformed or mismatched
- policy version is mismatched
- authority evidence hash is missing or malformed
- authority evidence hash does not match deterministic redacted metadata

## Runtime Evidence

RuntimeAggregator propagates only:

- suricata_signing_authority_hash
- suricata_signing_authority_status
- suricata_reason

Final publication reports include the signing authority hash and status only. No public key material, raw certificate body, raw rule payload, source URL, or raw network event data is included.

## Validation Commands

- `python3.11 -m py_compile publication/*.py tests/test_suricata*.py`
- `pytest -q tests/test_suricata*.py`
- `pytest -q tests/test_publication_*.py tests/test_suricata*.py`
- `git diff --check`

## Remaining Gaps

- No live network fetcher enabled.
- No connector/API/publication path enabled.
- Production external signing authority is modeled but not connected to a real CA/KMS/HSM provider unless explicitly configured.

## Rollback Command

```bash
rm -f publication/suricata_external_signing_authority.py tests/test_suricata_external_signing_authority.py docs/publication/USBAY_SURICATA_014_EXTERNAL_SIGNING_AUTHORITY.md
```

Then revert the SURICATA-014 import, report-field, RuntimeAggregator, and Suricata test fixture changes.
